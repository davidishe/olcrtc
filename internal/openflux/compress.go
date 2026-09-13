// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: OpenFlux payload framing (marker byte + optional lz4 frame).

import (
	"bytes"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"
)

// Wire compatibility with upstream OpenFlux: 0x00 prefix means raw bytes,
// 0x1F prefix means an lz4 frame. Payloads up to minCompress stay raw.
const (
	markerRaw   = 0x00
	markerLZ4   = 0x1F
	minCompress = 200
)

func compress(data []byte) []byte {
	if len(data) > minCompress {
		var buf bytes.Buffer
		buf.WriteByte(markerLZ4)
		w := lz4.NewWriter(&buf)
		_, werr := w.Write(data)
		cerr := w.Close()
		if werr == nil && cerr == nil && buf.Len() < len(data)+1 {
			return buf.Bytes()
		}
	}
	out := make([]byte, 0, len(data)+1)
	out = append(out, markerRaw)
	return append(out, data...)
}

func decompress(data []byte) ([]byte, error) {
	if len(data) == 0 || data[0] == markerRaw {
		if len(data) == 0 {
			return data, nil
		}
		return data[1:], nil
	}
	out, err := io.ReadAll(lz4.NewReader(bytes.NewReader(data[1:])))
	if err != nil {
		return nil, fmt.Errorf("lz4: %w", err)
	}
	return out, nil
}
