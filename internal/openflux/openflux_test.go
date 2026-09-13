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

// dnsQuery builds a minimal A query for name with the given transaction id.
func dnsQuery(name string, id uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(msg[4:6], 1)      // one question
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = append(msg, 0, 1, 0, 1) // A, IN
	return msg
}

func TestDNSCacheKeyIgnoresTransactionID(t *testing.T) {
	a, ok := cacheKey(dnsQuery("example.com", 1))
	if !ok {
		t.Fatal("question must parse")
	}
	b, _ := cacheKey(dnsQuery("example.com", 2))
	if a != b {
		t.Fatal("same question with a different id must share the cache key")
	}
	c, _ := cacheKey(dnsQuery("other.com", 1))
	if a == c {
		t.Fatal("different names must not share a key")
	}
}

func TestDNSCacheRestoresTransactionID(t *testing.T) {
	r := newDNSResolver(newStats())
	query := dnsQuery("example.com", 0x1234)
	answer := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(answer[6:8], 1) // pretend one answer record
	r.store(query, answer)

	again := dnsQuery("example.com", 0xbeef)
	got, ok := r.fromCache(again)
	if !ok {
		t.Fatal("second query must hit the cache")
	}
	if binary.BigEndian.Uint16(got[0:2]) != 0xbeef {
		t.Fatalf("cached answer must carry the asking id, got %x", got[0:2])
	}
}

func TestBatchRoundTrip(t *testing.T) {
	one := compress([]byte("first packet"))
	two := compress(bytes.Repeat([]byte("second packet "), 40))
	three := compress([]byte("third"))

	single, err := decodeUnits(one)
	if err != nil || len(single) != 1 || string(single[0]) != "first packet" {
		t.Fatalf("single unit must still decode: %v %q", err, single)
	}

	batch := encodeBatch([][]byte{one, two, three})
	if batch[0] != markerBatch {
		t.Fatalf("batch marker missing: %x", batch[0])
	}
	pkts, err := decodeUnits(batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 3 || string(pkts[0]) != "first packet" || string(pkts[2]) != "third" {
		t.Fatalf("bad batch contents: %d units", len(pkts))
	}
	if !bytes.Equal(pkts[1], bytes.Repeat([]byte("second packet "), 40)) {
		t.Fatal("compressed unit inside a batch must survive")
	}

	if _, err := decodeUnits([]byte{markerBatch, 0x00}); err == nil {
		t.Fatal("truncated batch must fail")
	}
}

func TestDrainQueueRespectsLimits(t *testing.T) {
	c := newDocConn("https://example", newStats(), func([]byte) {})
	for i := 0; i < maxBatchUnits+10; i++ {
		c.sendQ <- []byte("unit")
	}
	units := c.drainQueue([]byte("first"))
	if len(units) != maxBatchUnits {
		t.Fatalf("expected %d units, got %d", maxBatchUnits, len(units))
	}
	// A quiet queue must not wait for more.
	drained := c.drainQueue([]byte("solo"))
	if len(drained) == 0 {
		t.Fatal("drain must always return the first unit")
	}
}
