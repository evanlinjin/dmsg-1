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
	"time"

	"github.com/SkycoinProject/dmsg/cipher"
	"github.com/SkycoinProject/dmsg/ioutil"
)

// MaxWriteSize is the largest amount for a single write.
const MaxWriteSize = maxPayloadSize

// Frame format: [ len (2 bytes) | auth & nonce (24 bytes) | payload (<= maxPayloadSize bytes) ]
const (
	maxFrameSize   = 4096                                 // maximum frame size (4096)
	maxPayloadSize = maxFrameSize - prefixSize - authSize // maximum payload size
	maxPrefixValue = maxFrameSize - prefixSize            // maximum value contained in the 'len' prefix

	prefixSize = 2  // len prefix size
	authSize   = 24 // noise auth data size
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

	rawIn bytes.Buffer // raw input, starting with a record header
	in    bytes.Reader // application data waiting to be read, from rawIn.Next
	inErr error

	rawInputOld *bufio.Reader
	inputOld    bytes.Buffer
	rMx         sync.Mutex

	wPad bytes.Reader
	wMx  sync.Mutex
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
	rw.rMx.Lock()
	defer rw.rMx.Unlock()

	if rw.inputOld.Len() > 0 {
		return rw.inputOld.Read(p)
	}

	ciphertext, err := ReadRawFrame(rw.rawInputOld)
	if err != nil {
		return 0, err
	}
	plaintext, err := rw.ns.DecryptUnsafe(ciphertext)
	if err != nil {
		// TODO(evanlinjin): log error here.
		return 0, nil
	}
	if len(plaintext) == 0 {
		return 0, nil
	}
	return ioutil.BufRead(&rw.inputOld, plaintext, p)
}

func (rw *ReadWriter) Write(p []byte) (n int, err error) {
	rw.wMx.Lock()
	defer rw.wMx.Unlock()

	if _, err = rw.origin.Write(nil); err != nil {
		return 0, err
	}

	for rw.wPad.Len() > 0 {
		if _, err = rw.wPad.WriteTo(rw.origin); err != nil {
			return 0, err
		}
	}

	// Enforce max frame size.
	if len(p) > maxPayloadSize {
		p, err = p[:maxPayloadSize], io.ErrShortWrite
	}

	writtenB, wErr := WriteRawFrame(rw.origin, rw.ns.EncryptUnsafe(p))

	if !IsCompleteFrame(writtenB) {
		rw.wPad.Reset(FillIncompleteFrame(writtenB))
	}

	if wErr != nil {
		return 0, wErr
	}

	return len(p), err
}

// Handshake performs a Noise handshake using the provided io.ReadWriter.
func (rw *ReadWriter) Handshake(hsTimeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		if rw.ns.init {
			errCh <- InitiatorHandshake(rw.ns, rw.rawInputOld, rw.origin)
		} else {
			errCh <- ResponderHandshake(rw.ns, rw.rawInputOld, rw.origin)
		}
		close(errCh)
	}()
	select {
	case err := <-errCh:
		return err
	case <-time.After(hsTimeout):
		return timeoutError{}
	}
}

// LocalStatic returns the local static public key.
func (rw *ReadWriter) LocalStatic() cipher.PubKey {
	return rw.ns.LocalStatic()
}

// RemoteStatic returns the remote static public key.
func (rw *ReadWriter) RemoteStatic() cipher.PubKey {
	return rw.ns.RemoteStatic()
}

// InitiatorHandshake performs a noise handshake as an initiator.
func InitiatorHandshake(ns *Noise, r *bufio.Reader, w io.Writer) error {
	for {
		msg, err := ns.MakeHandshakeMessage()
		if err != nil {
			return err
		}
		if _, err := WriteRawFrame(w, msg); err != nil {
			return err
		}
		if ns.HandshakeFinished() {
			break
		}
		res, err := ReadRawFrame(r)
		if err != nil {
			return err
		}
		if err = ns.ProcessHandshakeMessage(res); err != nil {
			return err
		}
		if ns.HandshakeFinished() {
			break
		}
	}
	return nil
}

// ResponderHandshake performs a noise handshake as a responder.
func ResponderHandshake(ns *Noise, r *bufio.Reader, w io.Writer) error {
	for {
		msg, err := ReadRawFrame(r)
		if err != nil {
			return err
		}
		if err := ns.ProcessHandshakeMessage(msg); err != nil {
			return err
		}
		if ns.HandshakeFinished() {
			break
		}
		res, err := ns.MakeHandshakeMessage()
		if err != nil {
			return err
		}
		if _, err := WriteRawFrame(w, res); err != nil {
			return err
		}
		if ns.HandshakeFinished() {
			break
		}
	}
	return nil
}

// WriteRawFrame writes a raw frame (data prefixed with a uint16 len).
// It returns the bytes written.
func WriteRawFrame(w io.Writer, p []byte) ([]byte, error) {
	buf := make([]byte, prefixSize+len(p))
	binary.BigEndian.PutUint16(buf, uint16(len(p)))
	copy(buf[prefixSize:], p)

	n, err := w.Write(buf)
	return buf[:n], err
}

// ReadRawFrame attempts to read a raw frame from a buffered reader.
func ReadRawFrame(r *bufio.Reader) (p []byte, err error) {
	prefixB, err := r.Peek(prefixSize)
	if err != nil {
		return nil, err
	}

	// obtain payload size
	prefix := int(binary.BigEndian.Uint16(prefixB))
	if prefix > maxPrefixValue {
		return nil, &netError{
			Err: fmt.Errorf("noise prefix value %dB exceeds maximum %dB", prefix, maxPrefixValue),
		}
	}

	// obtain payload
	b, err := r.Peek(prefixSize + prefix)
	if err != nil {
		return nil, err
	}
	if _, err := r.Discard(prefixSize + prefix); err != nil {
		panic(fmt.Errorf("unexpected error when discarding %d bytes: %v", prefixSize+prefix, err))
	}
	return b[prefixSize:], nil
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

	// Read header, payload.
	if err := rw.readFromUntil(rw.origin, prefixSize); err != nil {
		if e, ok := err.(net.Error); !ok || !e.Temporary() {
			rw.inErr = err
		}
		return err
	}
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
	_, err := rw.rawIn.ReadFrom(&atLeastReader{r, int64(needs)})
	return err
}

// IsCompleteFrame determines if a frame is fully formed.
func IsCompleteFrame(b []byte) bool {
	if len(b) < prefixSize || len(b[prefixSize:]) != int(binary.BigEndian.Uint16(b)) {
		return false
	}
	return true
}

// FillIncompleteFrame takes in an incomplete frame, and returns empty bytes to fill the incomplete frame.
func FillIncompleteFrame(b []byte) []byte {
	originalLen := len(b)

	for len(b) < prefixSize {
		b = append(b, byte(0))
	}
	b = append(b, make([]byte, binary.BigEndian.Uint16(b))...)
	return b[originalLen:]
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