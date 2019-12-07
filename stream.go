package dmsg

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"io"
	"net"
	"time"

	"github.com/SkycoinProject/yamux"
	"github.com/sirupsen/logrus"

	"github.com/SkycoinProject/dmsg/noise"
)

func encodeGob(v interface{}) []byte {
	var b bytes.Buffer
	if err := gob.NewEncoder(&b).Encode(v); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// writeEncryptedGob encrypts with noise and prefixed with uint16 (2 additional bytes).
func writeEncryptedGob(w io.Writer, ns *noise.Noise, v interface{}) error {
	p := ns.EncryptUnsafe(encodeGob(v))
	p = append(make([]byte, 2), p...)
	binary.BigEndian.PutUint16(p, uint16(len(p)-2))
	_, err := w.Write(p)
	return err
}

func decodeGob(v interface{}, b []byte) error {
	return gob.NewDecoder(bytes.NewReader(b)).Decode(v)
}

func readEncryptedGob(r io.Reader, ns *noise.Noise, v interface{}) error {
	lb := make([]byte, 2)
	if _, err := io.ReadFull(r, lb); err != nil {
		return err
	}
	pb := make([]byte, binary.BigEndian.Uint16(lb))
	if _, err := io.ReadFull(r, pb); err != nil {
		return err
	}
	b, err := ns.DecryptUnsafe(pb)
	if err != nil {
		return err
	}
	return decodeGob(v, b)
}

type Stream2 struct {
	ses  *ClientSession // back reference
	yStr *yamux.Stream

	// The following fields are to be filled after handshake.
	lAddr  Addr
	rAddr  Addr
	ns     *noise.Noise
	nsConn *noise.ReadWriter
	close  func() // to be called when closing
	log    logrus.FieldLogger
}

func newInitiatingStream(cSes *ClientSession) (*Stream2, error) {
	yStr, err := cSes.ys.OpenStream()
	if err != nil {
		return nil, err
	}
	return &Stream2{ses: cSes, yStr: yStr}, nil
}

func newRespondingStream(cSes *ClientSession) (*Stream2, error) {
	yStr, err := cSes.ys.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &Stream2{ses: cSes, yStr: yStr}, nil
}

func (s *Stream2) Close() error {
	if s.close != nil {
		s.close()
	}
	return s.yStr.Close()
}

func (s *Stream2) writeRequest(rAddr Addr) (req StreamDialRequest, err error) {
	// Reserve stream in porter.
	var lPort uint16
	if lPort, s.close, err = s.ses.porter.ReserveEphemeral(context.Background(), s); err != nil {
		return
	}

	// Prepare fields.
	s.prepareFields(true, Addr{PK: s.ses.LocalPK(), Port: lPort}, rAddr)

	// Prepare request.
	var nsMsg []byte
	if nsMsg, err = s.ns.MakeHandshakeMessage(); err != nil {
		return
	}
	req = StreamDialRequest{
		Timestamp: time.Now().UnixNano(),
		SrcAddr:   s.lAddr,
		DstAddr:   s.rAddr,
		NoiseMsg:  nsMsg,
	}
	req.Sign(s.ses.localSK())

	// Write request.
	err = writeEncryptedGob(s.yStr, s.ses.ns, req)
	return
}

func (s *Stream2) readRequest() (req StreamDialRequest, err error) {
	if err = readEncryptedGob(s.yStr, s.ses.ns, &req); err != nil {
		return
	}
	if err = req.Verify(0); err != nil {
		err = ErrReqInvalidTimestamp
		return
	}
	if req.DstAddr.PK != s.ses.LocalPK() {
		err = ErrReqInvalidDstPK
		return
	}

	// Prepare fields.
	s.prepareFields(false, req.DstAddr, req.SrcAddr)

	if err = s.ns.ProcessHandshakeMessage(req.NoiseMsg); err != nil {
		return
	}
	return
}

func (s *Stream2) writeResponse(req StreamDialRequest) error {

	// Obtain associated local listener.
	pVal, ok := s.ses.porter.PortValue(s.lAddr.Port)
	if !ok {
		return ErrReqNoListener
	}
	lis, ok := pVal.(*Listener)
	if !ok {
		return ErrReqNoListener
	}

	// Prepare and write response.
	nsMsg, err := s.ns.MakeHandshakeMessage()
	if err != nil {
		return err
	}
	resp := DialResponse{
		ReqHash:  req.Hash(),
		Accepted: true,
		NoiseMsg: nsMsg,
	}
	resp.Sign(s.ses.localSK())
	if err := writeEncryptedGob(s.yStr, s.ses.ns, resp); err != nil {
		return err
	}

	// Push stream to listener.
	return lis.introduceStream(s)
}

func (s *Stream2) readResponse(req StreamDialRequest) (err error) {
	// Read and process response.
	var resp DialResponse
	if err = readEncryptedGob(s.yStr, s.ses.ns, &resp); err != nil {
		return
	}
	if err = resp.Verify(req.DstAddr.PK, req.Hash()); err != nil {
		return
	}
	if err = s.ns.ProcessHandshakeMessage(resp.NoiseMsg); err != nil {
		return
	}

	// Finalize noise read writer.
	s.nsConn = noise.NewReadWriter(s.yStr, s.ns)
	return
}

func (s *Stream2) prepareFields(init bool, lAddr, rAddr Addr) {
	ns, err := noise.New(noise.HandshakeKK, noise.Config{
		LocalPK:   s.ses.LocalPK(),
		LocalSK:   s.ses.localSK(),
		RemotePK:  rAddr.PK,
		Initiator: init,
	})
	if err != nil {
		s.log.WithError(err).Panic("Failed to prepare stream noise object.")
	}

	s.lAddr = lAddr
	s.rAddr = rAddr
	s.ns = ns
	s.log = s.ses.log.WithField("stream", s.lAddr.ShortString()+"->"+s.rAddr.ShortString())
}

func (s *Stream2) LocalAddr() net.Addr {
	return s.lAddr
}

func (s *Stream2) RemoteAddr() net.Addr {
	return s.rAddr
}

func (s *Stream2) StreamID() uint32 {
	return s.yStr.StreamID()
}

func (s *Stream2) Read(b []byte) (int, error) {
	return s.yStr.Read(b)
}

func (s *Stream2) Write(b []byte) (int, error) {
	return s.yStr.Write(b)
}

func (s *Stream2) SetDeadline(t time.Time) error {
	return s.yStr.SetDeadline(t)
}

func (s *Stream2) SetReadDeadline(t time.Time) error {
	return s.yStr.SetReadDeadline(t)
}

func (s *Stream2) SetWriteDeadline(t time.Time) error {
	return s.yStr.SetWriteDeadline(t)
}