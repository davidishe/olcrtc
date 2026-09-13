// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: OpenFlux payload framing (marker byte + optional lz4 frame).

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"
)

// Wire compatibility with upstream OpenFlux: 0x00 prefix means raw bytes,
// 0x1F prefix means an lz4 frame. Payloads up to minCompress stay raw.
//
// 0x42 is a Cockney extension: one message carrying several units, each a
// length-prefixed 0x00/0x1F payload. The document relays roughly 300 messages
// per second regardless of their size, so one packet per message capped the
// tunnel at about 1 Mbit/s. Upstream OpenFlux cannot read a batch; the exit
// node must run the Cockney patch.
const (
	markerRaw   = 0x00
	markerLZ4   = 0x1F
	markerBatch = 0x42
	minCompress = 200

	maxBatchUnits = 32
	maxBatchBytes = 24000 // base64 inflates this to ~32 KB per message
)

var errBatchTruncated = errors.New("batch unit truncated")

// encodeBatch packs several compressed units into one payload.
func encodeBatch(units [][]byte) []byte {
	total := 1
	for _, u := range units {
		total += 2 + len(u)
	}
	out := make([]byte, 0, total)
	out = append(out, markerBatch)
	for _, u := range units {
		out = append(out, byte(len(u)>>8), byte(len(u)))
		out = append(out, u...)
	}
	return out
}

// decodeUnits returns every packet carried by one payload, batched or not.
func decodeUnits(payload []byte) ([][]byte, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	if payload[0] != markerBatch {
		pkt, err := decompress(payload)
		if err != nil {
			return nil, err
		}
		return [][]byte{pkt}, nil
	}
	var out [][]byte
	rest := payload[1:]
	for len(rest) > 0 {
		if len(rest) < 2 {
			return out, errBatchTruncated
		}
		n := int(rest[0])<<8 | int(rest[1])
		rest = rest[2:]
		if n > len(rest) {
			return out, errBatchTruncated
		}
		pkt, err := decompress(rest[:n])
		if err != nil {
			return out, err
		}
		out = append(out, pkt)
		rest = rest[n:]
	}
	return out, nil
}

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
