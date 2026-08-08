package turnrelay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	frameLenPrefix = 4
	maxFrameSize   = 64 * 1024
)

var (
	errFrameTooLarge = errors.New("turnrelay: frame too large")
	errShortFrame    = errors.New("turnrelay: short frame")
)

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("%w: %d", errFrameTooLarge, len(payload))
	}
	var hdr [frameLenPrefix]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if len(payload) == 0 {
		return nil
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write frame body: %w", err)
	}
	return nil
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [frameLenPrefix]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameSize {
		return nil, fmt.Errorf("%w: %d", errFrameTooLarge, n)
	}
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errShortFrame
		}
		return nil, fmt.Errorf("read frame body: %w", err)
	}
	return buf, nil
}
