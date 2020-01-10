package noise

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/SkycoinProject/dmsg/cipher"
)

// MaxWriteSize is the largest amount for a single write.
const MaxWriteSize = maxPayloadSize

// Frame format: [ len (2 bytes) | auth & nonce (24 bytes) | payload (<= maxPayloadSize bytes) ]
const (
	maxFrameSize   = 4096                                 // maximum frame size (4096)
	maxPayloadSize = maxFrameSize - hdrSize - authSize // maximum payload size
	maxPrefixValue = maxFrameSize - hdrSize            // maximum value contained in the 'len' prefix

	hdrSize  = 3 // Header size: 1 byte (typ), 2 bytes (pay len)
	authSize = 24 // noise auth data size
)

// Frame types.
const (
	TypHandshake = byte(0)
	TypClose     = byte(1)
	TypData      = byte(2)
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type netError struct{ Err error }

func (e *netError) Error() string { return e.Err.Error() }
func (netError) Timeout() bool    { return false }
func (netError) Temporary() bool  { return true }

// ReadWriter implements noise encrypted read writer.
type ReadWriter struct {
	origin io.ReadWriter
	ns     *Noise

	hs     bytes.Buffer
	hsStat uint32
	hsErr  error
	hsMx   sync.Mutex

	rawIn bytes.Buffer // raw input, starting with a frame header
	in    bytes.Reader // application data waiting to be read, from rawIn.Next
	inErr error
	rawInputOld *bufio.Reader
	inMx        sync.Mutex

	outBuf []byte
	outErr error
	outMx sync.Mutex
}

// NewReadWriter constructs a new ReadWriter.
func NewReadWriter(rw io.ReadWriter, ns *Noise) *ReadWriter {
	return &ReadWriter{
		origin:      rw,
		ns:          ns,
		rawInputOld: bufio.NewReaderSize(rw, maxFrameSize*2), // can fit 2 frames.
	}
}

func (rw *ReadWriter) Read(p []byte) (int, error) {
	if err := rw.Handshake(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		// Put this after Handshake, in case people were calling
		// Read(nil) for the side effect of the Handshake.
		return 0, nil
	}

	rw.inMx.Lock()
	defer rw.inMx.Unlock()

	if rw.in.Len() == 0 {
		if err := rw.readFrame(); err != nil {
			fmt.Println("Read:", 0, err)
			return 0, err
		}
	}

	n, _ := rw.in.Read(p)
	fmt.Println("Read:", n, nil)
	return n, nil
}

func (rw *ReadWriter) Write(p []byte) (int, error) {

	// TODO(evanlinjin): Interlock with Close.

	if err := rw.Handshake(); err != nil {
		return 0, err
	}

	rw.outMx.Lock()
	defer rw.outMx.Unlock()

	if err := rw.outErr; err != nil {
		return 0, err
	}

	n, err := rw.writeFrame(TypData, p)
	fmt.Println("Write:", n, err)
	return n, err
}


// LocalStatic returns the local static public key.
func (rw *ReadWriter) LocalStatic() cipher.PubKey {
	return rw.ns.LocalStatic()
}

// RemoteStatic returns the remote static public key.
func (rw *ReadWriter) RemoteStatic() cipher.PubKey {
	return rw.ns.RemoteStatic()
}

func (rw *ReadWriter) writeFrame(typ byte, data []byte) (int, error) {
	var n int
	for len(data) > 0 {
		m := len(data)
		if m > maxPayloadSize {
			m = maxPayloadSize
		}

		var payload []byte
		if rw.ns.HandshakeFinished() && typ != TypHandshake {
			payload = rw.ns.EncryptUnsafe(data[:m])
		} else {
			payload = data
		}

		frame := make([]byte, hdrSize+len(payload))
		frame[0] = typ
		binary.BigEndian.PutUint16(frame[1:], uint16(len(payload)))
		copy(frame[hdrSize:], payload)

		//rw.outBuf = append(rw.outBuf, frame...)

		if _, err := rw.origin.Write(frame); err != nil {
			return n, err
		}

		n += m
		data = data[m:]
	}
	return n, nil
}

func (rw *ReadWriter) readFrame() error {
	if rw.inErr != nil {
		return rw.inErr
	}

	// This function modifies c.rawIn, which owns the c.in memory.
	if rw.in.Len() != 0 {
		rw.inErr = errors.New("dmsg.Noise: internal error: attempted to read frame with pending application data")
	}
	rw.in.Reset(nil)

	// Read header.
	if err := rw.readFromUntil(rw.origin, hdrSize); err != nil {
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			rw.inErr = err
		}
		fmt.Println("Failed to read header!", err)
		return err
	}
	hdr := rw.rawIn.Bytes()[:hdrSize] //int(binary.BigEndian.Uint16(rw.rawIn.Bytes()[:hdrSize]))
	typ := hdr[0]
	if typ != TypData {
		// TODO
	}

	n := int(binary.BigEndian.Uint16(hdr[1:]))

	// Read payload.
	if err := rw.readFromUntil(rw.origin, hdrSize+n); err != nil {
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			rw.inErr = err
		}
		return err
	}
	frame := rw.rawIn.Next(hdrSize + n)

	// Decrypt.
	var data []byte
	if rw.ns.HandshakeFinished() {
		var err error
		if data, err = rw.ns.DecryptUnsafe(frame[hdrSize:]); err != nil {
			rw.inErr = err
			return err
		}
	} else {
		data = frame[hdrSize:]
	}

	switch typ {
	case TypData:
		// Note that data is owned by rw.rawIn, following the Next call above,
		// to avoid copying the plaintext. This is safe because rw.rawIn is
		// not read from or written to until rw.in is drained.
		rw.in.Reset(data)

	case TypHandshake:
		if len(data) == 0 {
			// TODO(evanlinjin): error.
		}
		rw.hs.Write(data)
	}

	return nil
}

// readFromUntil reads from r into c.rawIn until c.rawIn contains
// at least n bytes or else returns an error.
func (rw *ReadWriter) readFromUntil(r io.Reader, n int) error {
	if rw.rawIn.Len() >= n {
		return nil
	}
	needs := n - rw.rawIn.Len()
	// There might be extra input waiting on the wire. Make a best effort
	// attempt to fetch it so that it can be used in (*Conn).Read to
	// "predict" closeNotify alerts.
	rw.rawIn.Grow(needs + bytes.MinRead)
	_, err := rw.rawIn.ReadFrom(&atLeastReader{R: r, N: int64(needs)})
	return err
}

// atLeastReader reads from R, stopping with EOF once at least N bytes have been
// read. It is different from an io.LimitedReader in that it doesn't cut short
// the last Read call, and in that it considers an early EOF an error.
type atLeastReader struct {
	R io.Reader
	N int64
}

func (r *atLeastReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	n, err := r.R.Read(p)
	r.N -= int64(n) // won't underflow unless len(p) >= n > 9223372036854775809
	if r.N > 0 && err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	if r.N <= 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

/* HANDSHAKE STUFF */

func (rw *ReadWriter) Handshake() error {
	rw.hsMx.Lock()
	defer rw.hsMx.Unlock()

	if err := rw.hsErr; err != nil {
		return err
	}
	if rw.handshakeComplete() {
		return nil
	}

	var hsActions [2]func() error
	if init := rw.ns.init; init {
		hsActions[0] = rw.writeHandshakeFrame
		hsActions[1] = rw.readHandshakeFrame
	} else {
		hsActions[0] = rw.readHandshakeFrame
		hsActions[1] = rw.writeHandshakeFrame
	}

	for {
		for _, action := range hsActions {
			if err := action(); err != nil {
				rw.hsErr = err
				goto hsDone
			}
			if rw.ns.HandshakeFinished() {
				atomic.StoreUint32(&rw.hsStat, 1)
				goto hsDone
			}
		}
	}

hsDone:
	if rw.hsErr == nil && !rw.ns.HandshakeFinished() {
		rw.hsErr = errors.New("noise: internal error: handshake should have had a result")
	}
	return rw.hsErr
}

func (rw *ReadWriter) writeHandshakeFrame() error {
	msg, err := rw.ns.MakeHandshakeMessage()
	if err != nil {
		fmt.Printf("[%s:writeHandshakeFrame] %d, %v\n", rw.ns.LocalStatic(), len(msg), err)
		return err
	}
	if _, err := rw.writeFrame(TypHandshake, msg); err != nil {
		fmt.Printf("[%s:writeHandshakeFrame] %d, %v\n", rw.ns.LocalStatic(), len(msg), err)
		return err
	}
	fmt.Printf("[%s:writeHandshakeFrame] %d, %v (%v)\n", rw.ns.LocalStatic(), len(msg), err, msg)
	return nil
}

func (rw *ReadWriter) readHandshakeFrame() error {
	if err := rw.readFrame(); err != nil {
		fmt.Printf("[%s:readHandshakeFrame] %d, %v\n", rw.ns.LocalStatic(), -1, nil)
		return err
	}

	msg := rw.hs.Next(rw.hs.Len())
	if err := rw.ns.ProcessHandshakeMessage(msg); err != nil {
		fmt.Printf("[%s:readHandshakeFrame] %d, %v (%v)\n", rw.ns.LocalStatic(), len(msg), err, msg)
		return err
	}
	fmt.Printf("[%s:readHandshakeFrame] %d, %v (%v)\n", rw.ns.LocalStatic(), len(msg), nil, msg)
	return nil
}

func (rw *ReadWriter) handshakeComplete() bool {
	return atomic.LoadUint32(&rw.hsStat) == 1
}
