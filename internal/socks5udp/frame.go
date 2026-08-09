// Package socks5udp implements the UDP-in-TCP relay framing of hev-socks5, a
// proprietary extension to RFC 1928 that carries datagrams inside the SOCKS5
// TCP stream instead of a side channel. Clients ask for it with command 0x05.
//
// A relay message looks like this:
//
//	+--------+--------+------+----------+----------+----------+
//	| DATLEN | HDRLEN | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+--------+--------+------+----------+----------+----------+
//	|   2    |   1    |  1   | Variable |    2     | Variable |
//
// DATLEN (big endian) counts DATA alone. HDRLEN counts everything preceding
// DATA, so the address occupies HDRLEN-3 bytes. Both directions use the same
// layout: outbound the address is the destination, inbound it is the source.
package socks5udp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// CmdUDPInTCP is the SOCKS5 command byte requesting a UDP-in-TCP relay.
const CmdUDPInTCP = 0x05

// MaxPayload is the largest datagram the framing can express.
const MaxPayload = 65535

const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	headerPrefix = 3
	portLen      = 2

	// maxHeaderLen is what the single HDRLEN byte can express.
	maxHeaderLen = 255
	// maxDomainLen keeps ATYP, the length byte, the name and the port within it.
	maxDomainLen = maxHeaderLen - headerPrefix - 1 - 1 - portLen
)

var (
	// ErrMalformedFrame is returned when a relay message violates the framing.
	ErrMalformedFrame = errors.New("malformed udp relay frame")
	// ErrUnsupportedAddressType is returned for address types outside RFC 1928.
	ErrUnsupportedAddressType = errors.New("unsupported address type")
	// ErrPayloadTooLarge is returned when a datagram exceeds MaxPayload.
	ErrPayloadTooLarge = errors.New("udp payload too large")
)

// Addr is a relay address kept in its encoded form. Replies must echo back
// exactly the bytes the peer sent: a client using mapped DNS matches datagrams
// against the literal address it asked for, so substituting the resolved one
// would make it discard every answer.
type Addr struct {
	encoded []byte
}

// ParseAddr validates an encoded address (ATYP through DST.PORT).
func ParseAddr(encoded []byte) (Addr, error) {
	if len(encoded) < 1 {
		return Addr{}, fmt.Errorf("%w: empty address", ErrMalformedFrame)
	}
	want, err := encodedAddrLen(encoded)
	if err != nil {
		return Addr{}, err
	}
	if len(encoded) != want {
		return Addr{}, fmt.Errorf("%w: address is %d bytes, want %d",
			ErrMalformedFrame, len(encoded), want)
	}
	out := make([]byte, len(encoded))
	copy(out, encoded)
	return Addr{encoded: out}, nil
}

// EncodeAddr builds an address from a host (IP or domain) and port.
func EncodeAddr(host string, port int) (Addr, error) {
	if port < 0 || port > 65535 {
		return Addr{}, fmt.Errorf("%w: port %d out of range", ErrMalformedFrame, port)
	}
	var encoded []byte
	switch ip := net.ParseIP(host); {
	case ip == nil:
		// HDRLEN is a single byte covering the 3-byte prefix and the whole
		// address, which caps the domain well below the 255 the length byte
		// would otherwise allow.
		if len(host) == 0 || len(host) > maxDomainLen {
			return Addr{}, fmt.Errorf("%w: domain of %d bytes", ErrMalformedFrame, len(host))
		}
		encoded = append([]byte{atypDomain, byte(len(host))}, host...)
	case ip.To4() != nil:
		encoded = append([]byte{atypIPv4}, ip.To4()...)
	default:
		encoded = append([]byte{atypIPv6}, ip.To16()...)
	}
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(port)) //nolint:gosec // range checked above
	return Addr{encoded: encoded}, nil
}

// Bytes returns the encoded address.
func (a Addr) Bytes() []byte { return a.encoded }

// IsZero reports whether the address was never populated.
func (a Addr) IsZero() bool { return len(a.encoded) == 0 }

// String renders the address as host:port, ready for dialing.
func (a Addr) String() string {
	if len(a.encoded) == 0 {
		return ""
	}
	body := a.encoded[1 : len(a.encoded)-portLen]
	port := binary.BigEndian.Uint16(a.encoded[len(a.encoded)-portLen:])

	var host string
	switch a.encoded[0] {
	case atypIPv4, atypIPv6:
		host = net.IP(body).String()
	case atypDomain:
		host = string(body[1:])
	default:
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// encodedAddrLen reports how many bytes the address occupies, based on ATYP.
func encodedAddrLen(encoded []byte) (int, error) {
	switch encoded[0] {
	case atypIPv4:
		return 1 + net.IPv4len + portLen, nil
	case atypIPv6:
		return 1 + net.IPv6len + portLen, nil
	case atypDomain:
		if len(encoded) < 2 {
			return 0, fmt.Errorf("%w: domain length byte missing", ErrMalformedFrame)
		}
		return 1 + 1 + int(encoded[1]) + portLen, nil
	default:
		return 0, fmt.Errorf("%w: %d", ErrUnsupportedAddressType, encoded[0])
	}
}

// ReadFrame reads one relay message. The returned payload aliases scratch, so
// callers must consume it before the next read.
func ReadFrame(r io.Reader, scratch []byte) (Addr, []byte, error) {
	var head [headerPrefix]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Addr{}, nil, err
	}
	payloadLen := int(binary.BigEndian.Uint16(head[:2]))
	addrLen := int(head[2]) - headerPrefix
	// The shortest legal address is an IPv4 one; anything smaller cannot hold
	// ATYP and a port, and would desynchronize the stream.
	if addrLen < 1+net.IPv4len+portLen {
		return Addr{}, nil, fmt.Errorf("%w: header length %d", ErrMalformedFrame, head[2])
	}
	if payloadLen > len(scratch) {
		return Addr{}, nil, fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, payloadLen, len(scratch))
	}

	encoded := make([]byte, addrLen)
	if _, err := io.ReadFull(r, encoded); err != nil {
		return Addr{}, nil, err
	}
	addr, err := ParseAddr(encoded)
	if err != nil {
		return Addr{}, nil, err
	}

	payload := scratch[:payloadLen]
	if _, err := io.ReadFull(r, payload); err != nil {
		return Addr{}, nil, err
	}
	return addr, payload, nil
}

// WriteFrame writes one relay message as a single Write so that concurrent
// writers cannot interleave a header with somebody else's payload.
func WriteFrame(w io.Writer, addr Addr, payload []byte) error {
	if addr.IsZero() {
		return fmt.Errorf("%w: empty address", ErrMalformedFrame)
	}
	if len(payload) > MaxPayload {
		return fmt.Errorf("%w: %d", ErrPayloadTooLarge, len(payload))
	}

	encoded := addr.Bytes()
	if headerPrefix+len(encoded) > maxHeaderLen {
		return fmt.Errorf("%w: header of %d bytes", ErrMalformedFrame, headerPrefix+len(encoded))
	}

	frame := make([]byte, 0, headerPrefix+len(encoded)+len(payload))
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload))) //nolint:gosec // range checked above
	frame = append(frame, byte(headerPrefix+len(encoded)))
	frame = append(frame, encoded...)
	frame = append(frame, payload...)

	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("write udp frame: %w", err)
	}
	return nil
}
