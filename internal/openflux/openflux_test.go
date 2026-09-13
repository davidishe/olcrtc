// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: unit tests for wire compatibility and diagnostics.

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestCompressRoundTrip(t *testing.T) {
	small := []byte("hello")
	if got := compress(small); got[0] != markerRaw || !bytes.Equal(got[1:], small) {
		t.Fatalf("small payload must stay raw, got %x", got)
	}
	big := bytes.Repeat([]byte("abcdefgh"), 100)
	c := compress(big)
	if c[0] != markerLZ4 {
		t.Fatalf("compressible payload must use lz4 marker, got %x", c[0])
	}
	out, err := decompress(c)
	if err != nil || !bytes.Equal(out, big) {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestExtractCursors(t *testing.T) {
	frame := `42["message",{"type":"cursor","messages":[{"cursor":"18;AAA","user":"u1"},{"cursor":"18;BBB","user":"u2"}]}]`
	got := extractCursors(frame)
	if strings.Join(got, ",") != "AAA,BBB" {
		t.Fatalf("got %v", got)
	}
	if len(extractCursors(`42["message",{"type":"connectState"}]`)) != 0 {
		t.Fatal("non cursor frame must yield nothing")
	}
}

func TestParseClientConfig(t *testing.T) {
	raw := `{"officeActionData":{"balancer_url":"https://b.example","editor_config":{"token":"tok",` +
		`"document":{"key":"k1","fileType":"docx","permissions":{"edit":true}}}}}`
	info, err := parseClientConfig([]byte(raw), "42")
	if err != nil {
		t.Fatal(err)
	}
	if info.wsURL != "wss://b.example/"+wsVersionPath+"/doc/k1/c/?EIO=4&transport=websocket" || info.token != "tok" {
		t.Fatalf("bad info %+v", info)
	}
	if _, err := parseClientConfig([]byte(`{"officeActionData":{}}`), "1"); err == nil {
		t.Fatal("missing fields must fail")
	}
}

func TestParseProbe(t *testing.T) {
	kind, side, r, ok := parseProbe("---KA---R1:s:7:1000:50:40")
	if !ok || kind != "R1" || side != "s" || r.seq != 7 || r.sent != 50 || r.recv != 40 {
		t.Fatalf("got %v %v %+v %v", kind, side, r, ok)
	}
	if _, _, _, ok := parseProbe("---KA---"); ok {
		t.Fatal("plain keepalive is not a probe")
	}
}

func tcpPacket(src, dst [4]byte, sport, dport uint16, seq uint32, flags byte, payload int) []byte {
	p := make([]byte, 40+payload)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[9] = protoTCP
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	binary.BigEndian.PutUint32(p[24:28], seq)
	p[32] = 5 << 4
	p[33] = flags
	binary.BigEndian.PutUint16(p[34:36], 1000)
	return p
}

func TestFlowRetransmissions(t *testing.T) {
	st := newStats()
	f := newFlowTable()
	dev := [4]byte{10, 10, 10, 2}
	srv := [4]byte{1, 1, 1, 1}

	f.observeUp(tcpPacket(dev, srv, 5000, 443, 100, tcpSYN, 0), st)
	f.observeUp(tcpPacket(dev, srv, 5000, 443, 100, tcpSYN, 0), st)
	f.observeUp(tcpPacket(dev, srv, 5000, 443, 101, tcpACK, 10), st)
	f.observeUp(tcpPacket(dev, srv, 5000, 443, 111, tcpACK, 10), st)
	f.observeUp(tcpPacket(dev, srv, 5000, 443, 101, tcpACK, 10), st)
	if st.retransUp.Load() != 2 || st.dataUp.Load() != 3 {
		t.Fatalf("up retr=%d data=%d", st.retransUp.Load(), st.dataUp.Load())
	}

	f.observeDown(tcpPacket(srv, dev, 443, 5000, 900, tcpACK, 20), st)
	f.observeDown(tcpPacket(srv, dev, 443, 5000, 900, tcpACK, 20), st)
	f.observeDown(tcpPacket(srv, dev, 443, 5000, 920, tcpACK|tcpRST, 0), st)
	if st.retransDn.Load() != 1 || st.rstDn.Load() != 1 {
		t.Fatalf("dn retr=%d rst=%d", st.retransDn.Load(), st.rstDn.Load())
	}
}

func TestEchoDetection(t *testing.T) {
	c := newDocConn("https://example", newStats(), func([]byte) {})
	c.echo.add(hash64("QUJD"))
	if !c.echo.has(hash64("QUJD")) || c.echo.has(hash64("REVG")) {
		t.Fatal("echo detection broken")
	}
}

func TestIncomingDedup(t *testing.T) {
	r := newHashRing(8)
	h := hash64("payload")
	if !r.addIfNew(h) {
		t.Fatal("first occurrence must be new")
	}
	if r.addIfNew(h) {
		t.Fatal("second occurrence must be a duplicate")
	}
}

func TestICMPChecksum(t *testing.T) {
	udp := make([]byte, 28)
	udp[0] = 0x45
	udp[9] = protoUDP
	icmp := icmpPortUnreachable(udp)
	if ipChecksum(icmp[:20]) != 0 || ipChecksum(icmp[20:]) != 0 {
		t.Fatal("checksums must verify to zero")
	}
}
