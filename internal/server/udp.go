package server

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/socks5udp"
	"github.com/xtaci/smux"
)

const (
	// udpFlowIdle is how long a destination may go without traffic before its
	// socket is reclaimed. Datagram protocols have no teardown, so this is the
	// only thing keeping the table bounded on a long-lived stream.
	udpFlowIdle = 60 * time.Second
	// udpMaxFlows caps the sockets one stream can hold open. A client bursting
	// QUIC at hundreds of hosts must not exhaust the agent's descriptors.
	udpMaxFlows = 256
	// udpDialTimeout bounds name resolution; the connect itself is local.
	udpDialTimeout = 5 * time.Second
)

// errTooManyFlows is returned when a stream is already at udpMaxFlows.
var errTooManyFlows = errors.New("udp flow limit reached")

// udpRelay carries datagrams for one client stream. The client multiplexes
// every destination onto that single stream, so the relay keeps a socket per
// destination and fans replies back under the address the client used.
type udpRelay struct {
	stream   io.ReadWriter
	streamID uint32
	dialer   *net.Dialer

	mu    sync.Mutex
	flows map[string]*udpFlow
	// closed stops late flow goroutines from resurrecting entries once the
	// stream is gone.
	closed bool

	writeMu sync.Mutex

	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64

	wg sync.WaitGroup
}

type udpFlow struct {
	conn net.Conn
	addr socks5udp.Addr
}

// relayUDP serves a client stream that asked for the UDP-in-TCP extension.
func (s *Server) relayUDP(stream *smux.Stream, sessionID string) {
	logger.Infof("sid=%d udp relay open", stream.ID())

	relay := &udpRelay{
		stream:   stream,
		streamID: stream.ID(),
		dialer: &net.Dialer{
			Timeout:  udpDialTimeout,
			Resolver: s.resolver,
		},
		flows: make(map[string]*udpFlow),
	}

	if _, err := stream.Write([]byte{0x00}); err != nil {
		return
	}

	err := relay.run()
	in, out := relay.shutdown()

	logger.Infof("sid=%d udp relay closed in=%d out=%d (%v)", stream.ID(), in, out, err)
	if s.onTraffic != nil && (in > 0 || out > 0) {
		s.onTraffic(sessionID, "udp", in, out)
	}
}

// run pumps client datagrams outbound until the stream ends.
func (r *udpRelay) run() error {
	scratch := make([]byte, socks5udp.MaxPayload)
	for {
		addr, payload, err := socks5udp.ReadFrame(r.stream, scratch)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}

		flow, err := r.flowFor(addr)
		if err != nil {
			// One unreachable destination must not tear down the other flows
			// on this stream, so the datagram is dropped as a network would.
			logger.Infof("sid=%d udp dial %s failed: %v", r.streamID, addr.String(), err)
			continue
		}

		if _, err := flow.conn.Write(payload); err != nil {
			logger.Infof("sid=%d udp send %s failed: %v", r.streamID, addr.String(), err)
			r.removeFlow(flow)
			continue
		}
		// Sending counts as activity, otherwise a one-way stream of datagrams
		// would have its socket reclaimed out from under it.
		_ = flow.conn.SetReadDeadline(time.Now().Add(udpFlowIdle))
		r.bytesOut.Add(uint64(len(payload)))
	}
}

// flowFor returns the socket for addr, opening one on first use.
func (r *udpRelay) flowFor(addr socks5udp.Addr) (*udpFlow, error) {
	key := string(addr.Bytes())

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, net.ErrClosed
	}
	if flow, ok := r.flows[key]; ok {
		r.mu.Unlock()
		return flow, nil
	}
	if len(r.flows) >= udpMaxFlows {
		r.mu.Unlock()
		return nil, errTooManyFlows
	}
	r.mu.Unlock()

	// Dialing outside the lock keeps a slow resolver from stalling every other
	// destination on the stream.
	conn, err := r.dialer.Dial("udp4", addr.String())
	if err != nil {
		return nil, err
	}
	flow := &udpFlow{conn: conn, addr: addr}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	if existing, ok := r.flows[key]; ok {
		// A concurrent datagram for the same destination won the race.
		r.mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	r.flows[key] = flow
	r.mu.Unlock()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.pumpInbound(flow)
	}()
	return flow, nil
}

// pumpInbound forwards replies from one destination back to the client.
func (r *udpRelay) pumpInbound(flow *udpFlow) {
	defer r.removeFlow(flow)

	buf := make([]byte, socks5udp.MaxPayload)
	for {
		_ = flow.conn.SetReadDeadline(time.Now().Add(udpFlowIdle))
		n, err := flow.conn.Read(buf)
		if n > 0 {
			r.bytesIn.Add(uint64(n))
			if writeErr := r.writeFrame(flow.addr, buf[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// writeFrame serializes replies so concurrent flows cannot interleave.
func (r *udpRelay) writeFrame(addr socks5udp.Addr, payload []byte) error {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	return socks5udp.WriteFrame(r.stream, addr, payload)
}

func (r *udpRelay) removeFlow(flow *udpFlow) {
	key := string(flow.addr.Bytes())

	r.mu.Lock()
	if current, ok := r.flows[key]; ok && current == flow {
		delete(r.flows, key)
	}
	r.mu.Unlock()

	_ = flow.conn.Close()
}

// shutdown closes every socket and waits for the inbound pumps to finish.
func (r *udpRelay) shutdown() (uint64, uint64) {
	r.mu.Lock()
	r.closed = true
	flows := make([]*udpFlow, 0, len(r.flows))
	for key, flow := range r.flows {
		flows = append(flows, flow)
		delete(r.flows, key)
	}
	r.mu.Unlock()

	for _, flow := range flows {
		_ = flow.conn.Close()
	}
	r.wg.Wait()

	return r.bytesIn.Load(), r.bytesOut.Load()
}
