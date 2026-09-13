// SPDX-License-Identifier: WTFPL

//go:build openflux_live

package openflux

// ai-generated: live check against a real exit node.
// Run: OPENFLUX_DOC_URL=... go test -tags openflux_live -run TestLive -v ./internal/openflux

import (
	"encoding/binary"
	"math/rand/v2"
	"os"
	"testing"
	"time"
)

func TestLiveSynAck(t *testing.T) {
	docURL := os.Getenv("OPENFLUX_DOC_URL")
	if docURL == "" {
		t.Skip("OPENFLUX_DOC_URL not set")
	}
	tun, err := Start(docURL)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Stop()

	deadline := time.Now().Add(30 * time.Second)
	for !tun.Connected() && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if !tun.Connected() {
		t.Fatal("websocket did not connect")
	}

	dev := [4]byte{10, 10, 10, 2}
	dst := [4]byte{1, 1, 1, 1}
	syn := tcpPacket(dev, dst, uint16(20000+rand.IntN(40000)), 80, rand.Uint32(), tcpSYN, 0)
	binary.BigEndian.PutUint16(syn[34:36], 65535)
	binary.BigEndian.PutUint16(syn[10:12], ipChecksum(syn[:20]))
	binary.BigEndian.PutUint16(syn[36:38], tcpChecksum(syn))

	for attempt := 0; attempt < 5; attempt++ {
		tun.WritePacket(syn)
		until := time.Now().Add(3 * time.Second)
		for time.Now().Before(until) {
			p := tun.ReadPacket(500 * time.Millisecond)
			if len(p) >= 40 && p[9] == protoTCP && p[33]&(tcpSYN|tcpACK) == tcpSYN|tcpACK {
				t.Logf("syn-ack from %d.%d.%d.%d after attempt %d; %s", p[12], p[13], p[14], p[15], attempt+1,
					tun.st.totals())
				return
			}
		}
	}
	t.Fatalf("no syn-ack; %s", tun.st.totals())
}

func TestLiveProbe(t *testing.T) {
	docURL := os.Getenv("OPENFLUX_DOC_URL")
	if docURL == "" {
		t.Skip("OPENFLUX_DOC_URL not set")
	}
	tun, err := Start(docURL)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Stop()
	time.Sleep(12 * time.Second)
	if line, _ := tun.st.snapshot(tun.conn, 0, 0); line != "" {
		t.Log(line)
	}
	if tun.st.probeRecv.Load() == 0 {
		t.Fatalf("no probe replies; exit node lacks diagnostics? %s", tun.st.totals())
	}
}

func tcpChecksum(p []byte) uint16 {
	seg := p[20:]
	pseudo := make([]byte, 12+len(seg))
	copy(pseudo[0:4], p[12:16])
	copy(pseudo[4:8], p[16:20])
	pseudo[9] = protoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(seg)))
	copy(pseudo[12:], seg)
	return ipChecksum(pseudo)
}
