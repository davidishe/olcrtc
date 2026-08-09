package socks5udp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		host string
		port int
		data string
	}{
		{name: "ipv4", host: "1.1.1.1", port: 53, data: "query"},
		{name: "ipv6", host: "2606:4700:4700::1111", port: 443, data: "quic"},
		{name: "domain", host: "example.com", port: 443, data: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := EncodeAddr(tc.host, tc.port)
			if err != nil {
				t.Fatalf("EncodeAddr() error = %v", err)
			}

			var buf bytes.Buffer
			if err := WriteFrame(&buf, addr, []byte(tc.data)); err != nil {
				t.Fatalf("WriteFrame() error = %v", err)
			}

			gotAddr, payload, err := ReadFrame(&buf, make([]byte, MaxPayload))
			if err != nil {
				t.Fatalf("ReadFrame() error = %v", err)
			}
			if !bytes.Equal(gotAddr.Bytes(), addr.Bytes()) {
				t.Fatalf("address = %v, want %v", gotAddr.Bytes(), addr.Bytes())
			}
			if string(payload) != tc.data {
				t.Fatalf("payload = %q, want %q", payload, tc.data)
			}
			if buf.Len() != 0 {
				t.Fatalf("%d bytes left unread", buf.Len())
			}
		})
	}
}

// The header layout is dictated by hev-socks5, so pin the exact bytes rather
// than only checking that we can read back what we wrote.
func TestWriteFrameWireLayout(t *testing.T) {
	addr, err := EncodeAddr("1.1.1.1", 53)
	if err != nil {
		t.Fatalf("EncodeAddr() error = %v", err)
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, addr, []byte{0xaa, 0xbb}); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}

	want := []byte{
		0x00, 0x02, // DATLEN: payload only
		0x0a,                    // HDRLEN: 3 prefix + 7 address
		0x01, 1, 1, 1, 1, 0, 53, // ATYP, DST.ADDR, DST.PORT
		0xaa, 0xbb,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("frame = % x, want % x", buf.Bytes(), want)
	}
}

func TestReadFrameSequential(t *testing.T) {
	first, _ := EncodeAddr("1.1.1.1", 53)
	second, _ := EncodeAddr("example.com", 443)

	var buf bytes.Buffer
	if err := WriteFrame(&buf, first, []byte("one")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if err := WriteFrame(&buf, second, []byte("two")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}

	scratch := make([]byte, MaxPayload)
	for _, want := range []string{"one", "two"} {
		_, payload, err := ReadFrame(&buf, scratch)
		if err != nil {
			t.Fatalf("ReadFrame() error = %v", err)
		}
		if string(payload) != want {
			t.Fatalf("payload = %q, want %q", payload, want)
		}
	}
	if _, _, err := ReadFrame(&buf, scratch); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadFrame() error = %v, want EOF", err)
	}
}

func TestReadFrameRejectsMalformed(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
		want  error
	}{
		{
			name:  "header too short for any address",
			frame: []byte{0x00, 0x00, 0x04, 0x01},
			want:  ErrMalformedFrame,
		},
		{
			name:  "unknown address type",
			frame: []byte{0x00, 0x00, 0x0a, 0x09, 1, 1, 1, 1, 0, 53},
			want:  ErrUnsupportedAddressType,
		},
		{
			// HDRLEN claims an IPv6 address while ATYP says IPv4.
			name:  "header length disagrees with address type",
			frame: append([]byte{0x00, 0x00, 0x16, 0x01}, make([]byte, 18)...),
			want:  ErrMalformedFrame,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ReadFrame(bytes.NewReader(tc.frame), make([]byte, MaxPayload))
			if !errors.Is(err, tc.want) {
				t.Fatalf("ReadFrame() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReadFrameRejectsOversizedPayload(t *testing.T) {
	frame := []byte{0xff, 0xff, 0x0a, 0x01, 1, 1, 1, 1, 0, 53}
	_, _, err := ReadFrame(bytes.NewReader(frame), make([]byte, 16))
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("ReadFrame() error = %v, want %v", err, ErrPayloadTooLarge)
	}
}

func TestAddrString(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{host: "1.1.1.1", port: 53, want: "1.1.1.1:53"},
		{host: "2606:4700:4700::1111", port: 443, want: "[2606:4700:4700::1111]:443"},
		{host: "example.com", port: 443, want: "example.com:443"},
	}

	for _, tc := range cases {
		addr, err := EncodeAddr(tc.host, tc.port)
		if err != nil {
			t.Fatalf("EncodeAddr(%q) error = %v", tc.host, err)
		}
		if got := addr.String(); got != tc.want {
			t.Fatalf("String() = %q, want %q", got, tc.want)
		}
	}
}

// HDRLEN is a single byte, so long names cannot be represented at all and must
// be refused rather than silently truncated into a corrupt frame.
func TestEncodeAddrRejectsOverlongDomain(t *testing.T) {
	_, err := EncodeAddr(strings.Repeat("a", maxDomainLen+1), 443)
	if !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("EncodeAddr() error = %v, want %v", err, ErrMalformedFrame)
	}
}
