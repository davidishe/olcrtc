// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: device packet dispatch, TCP flow accounting, ICMP replies.

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10

	flowIdle     = 2 * time.Minute
	flowTableCap = 8192
)

func (t *Tunnel) handleDevicePacket(pkt []byte) {
	st := t.st
	st.devInPkts.Add(1)
	st.devInBytes.Add(int64(len(pkt)))
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		st.nonIPv4.Add(1)
		return
	}
	switch pkt[9] {
	case protoTCP:
		st.tcpUp.Add(1)
		t.flows.observeUp(pkt, st)
		t.conn.send(compress(pkt))
	case protoUDP:
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < ihl+8 {
			return
		}
		if binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]) == 53 {
			st.udpDNS.Add(1)
			t.dns.handle(pkt, t.enqueueDevice)
			return
		}
		// The exit node is TCP only; a port-unreachable makes QUIC fall back fast.
		st.udpOther.Add(1)
		if icmp := icmpPortUnreachable(pkt); icmp != nil {
			t.enqueueDevice(icmp)
		}
	}
}

type tcpInfo struct {
	devPort, remotePort uint16
	remote              [4]byte
	seq                 uint32
	flags               byte
	window              uint16
	payload             int
}

func parseTCP(pkt []byte, fromDevice bool) (tcpInfo, bool) {
	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl+20 {
		return tcpInfo{}, false
	}
	tcp := pkt[ihl:]
	total := min(int(binary.BigEndian.Uint16(pkt[2:4])), len(pkt))
	off := int(tcp[12]>>4) * 4
	info := tcpInfo{
		seq:     binary.BigEndian.Uint32(tcp[4:8]),
		flags:   tcp[13],
		window:  binary.BigEndian.Uint16(tcp[14:16]),
		payload: max(total-ihl-off, 0),
	}
	src := binary.BigEndian.Uint16(tcp[0:2])
	dst := binary.BigEndian.Uint16(tcp[2:4])
	if fromDevice {
		info.devPort, info.remotePort = src, dst
		copy(info.remote[:], pkt[16:20])
	} else {
		info.devPort, info.remotePort = dst, src
		copy(info.remote[:], pkt[12:16])
	}
	return info, true
}

type flowKey struct {
	devPort, remotePort uint16
	remote              [4]byte
}

type flowState struct {
	upEnd, dnEnd uint32
	upSet, dnSet bool
	synSeq       uint32
	synSeen      bool
	last         time.Time
}

type flowTable struct {
	mu    sync.Mutex
	flows map[flowKey]*flowState
}

func newFlowTable() *flowTable {
	return &flowTable{flows: make(map[flowKey]*flowState, 256)}
}

func (f *flowTable) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.flows)
}

func (f *flowTable) get(k flowKey, create bool) *flowState {
	fs := f.flows[k]
	if fs == nil && create && len(f.flows) < flowTableCap {
		fs = &flowState{}
		f.flows[k] = fs
	}
	return fs
}

// before reports a <= b in 32-bit sequence space.
func before(a, b uint32) bool { return b-a < 1<<31 }

func (f *flowTable) observeUp(pkt []byte, st *stats) {
	info, ok := parseTCP(pkt, true)
	if !ok {
		return
	}
	if info.flags&tcpRST != 0 {
		st.rstUp.Add(1)
	}
	if info.flags&tcpFIN != 0 {
		st.finUp.Add(1)
	}
	if info.window == 0 && info.flags&tcpRST == 0 {
		st.zeroWinUp.Add(1)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	fs := f.get(flowKey{info.devPort, info.remotePort, info.remote}, info.flags&tcpSYN != 0 || info.payload > 0)
	if fs == nil {
		return
	}
	fs.last = time.Now()
	if info.flags&tcpSYN != 0 {
		st.synUp.Add(1)
		if fs.synSeen && fs.synSeq == info.seq {
			st.retransUp.Add(1)
		}
		fs.synSeq, fs.synSeen = info.seq, true
		return
	}
	if info.payload == 0 {
		return
	}
	st.dataUp.Add(1)
	end := info.seq + uint32(info.payload) //nolint:gosec // payload < 65536
	if fs.upSet && before(end, fs.upEnd) {
		st.retransUp.Add(1)
		return
	}
	fs.upEnd, fs.upSet = end, true
}

func (f *flowTable) observeDown(pkt []byte, st *stats) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != protoTCP {
		return
	}
	info, ok := parseTCP(pkt, false)
	if !ok {
		return
	}
	switch {
	case info.flags&tcpRST != 0:
		st.rstDn.Add(1)
		st.noteRST(fmt.Sprintf("%d.%d.%d.%d:%d", info.remote[0], info.remote[1], info.remote[2],
			info.remote[3], info.remotePort))
	case info.flags&(tcpSYN|tcpACK) == tcpSYN|tcpACK:
		st.synAckDn.Add(1)
	}
	if info.flags&tcpFIN != 0 {
		st.finDn.Add(1)
	}
	if info.window == 0 && info.flags&tcpRST == 0 {
		st.zeroWinDn.Add(1)
	}
	if info.payload == 0 {
		return
	}
	st.dataDn.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	fs := f.get(flowKey{info.devPort, info.remotePort, info.remote}, true)
	if fs == nil {
		return
	}
	fs.last = time.Now()
	end := info.seq + uint32(info.payload) //nolint:gosec // payload < 65536
	if fs.dnSet && before(end, fs.dnEnd) {
		st.retransDn.Add(1)
		return
	}
	fs.dnEnd, fs.dnSet = end, true
}

func (f *flowTable) expire(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, fs := range f.flows {
		if now.Sub(fs.last) > flowIdle {
			delete(f.flows, k)
		}
	}
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum) //nolint:gosec // folded to 16 bits above
}

func icmpPortUnreachable(orig []byte) []byte {
	ihl := int(orig[0]&0x0f) * 4
	if len(orig) < ihl+8 {
		return nil
	}
	quote := orig[:ihl+8]
	pkt := make([]byte, 20+8+len(quote))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt))) //nolint:gosec // bounded by MTU
	pkt[8] = 64
	pkt[9] = protoICMP
	copy(pkt[12:16], orig[16:20])
	copy(pkt[16:20], orig[12:16])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	icmp := pkt[20:]
	icmp[0], icmp[1] = 3, 3
	copy(icmp[8:], quote)
	binary.BigEndian.PutUint16(icmp[2:4], ipChecksum(icmp))
	return pkt
}
