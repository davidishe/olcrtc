package turnrelay

import (
	"bytes"
	"testing"
)

func TestWriteReadFrameRoundTrip(t *testing.T) {
	payloads := [][]byte{
		{},
		{0x01},
		bytes.Repeat([]byte("x"), 1024),
	}
	var buf bytes.Buffer
	for _, p := range payloads {
		if err := writeFrame(&buf, p); err != nil {
			t.Fatalf("writeFrame: %v", err)
		}
	}
	for i, want := range payloads {
		got, err := readFrame(&buf)
		if err != nil {
			t.Fatalf("readFrame[%d]: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("readFrame[%d] = %q, want %q", i, got, want)
		}
	}
}
