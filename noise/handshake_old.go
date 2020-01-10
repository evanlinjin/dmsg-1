package noise

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

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
	buf := make([]byte, hdrSize+len(p))
	buf[0] = TypHandshake
	binary.BigEndian.PutUint16(buf[1:], uint16(len(p)))
	copy(buf[hdrSize:], p)

	n, err := w.Write(buf)
	return buf[:n], err
}

// ReadRawFrame attempts to read a raw frame from a buffered reader.
func ReadRawFrame(r *bufio.Reader) (p []byte, err error) {
	prefixB, err := r.Peek(hdrSize)
	if err != nil {
		return nil, err
	}
	if prefixB[0] != TypHandshake {
		err = errors.New("TODO: Not handshake frame")
		return
	}

	// obtain payload size
	prefix := int(binary.BigEndian.Uint16(prefixB[1:]))
	if prefix > maxPrefixValue {
		return nil, &netError{
			Err: fmt.Errorf("noise prefix value %dB exceeds maximum %dB", prefix, maxPrefixValue),
		}
	}

	// obtain payload
	b, err := r.Peek(hdrSize + prefix)
	if err != nil {
		return nil, err
	}
	if _, err := r.Discard(hdrSize + prefix); err != nil {
		panic(fmt.Errorf("unexpected error when discarding %d bytes: %v", hdrSize+prefix, err))
	}
	return b[hdrSize:], nil
}

// Handshake performs a Noise handshake using the provided io.ReadWriter.
func (rw *ReadWriter) HandshakeOld(hsTimeout time.Duration) error {
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