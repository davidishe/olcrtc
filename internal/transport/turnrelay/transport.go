package turnrelay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/protect"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/pion/turn/v5"
	"github.com/xtaci/kcp-go/v5"
)

const (
	defaultMaxPayload   = 32 * 1024
	kcpDataShard        = 10
	kcpParityShard      = 3
	acceptBackoff       = 200 * time.Millisecond
	defaultListenAddr   = "0.0.0.0:56000"
	turnAllocateTimeout = 30 * time.Second
)

var (
	errEndpointRequired  = errors.New("turnrelay: endpoint required (agent host:port)")
	errAlreadyConnected  = errors.New("turnrelay: already connected")
	errNotConnected      = errors.New("turnrelay: not connected")
	errClosed            = errors.New("turnrelay: closed")
	errNoPeer            = errors.New("turnrelay: peer not found")
	errServerNeedsListen = errors.New("turnrelay: listen addr required for server role")
)

// New creates a turnrelay transport. Role is inferred from options:
// ListenAddr set (or OnPeerData provided without Endpoint) → server;
// Endpoint set → client.
func New(ctx context.Context, cfg transport.Config) (transport.Transport, error) {
	opts, err := parseOptions(cfg)
	if err != nil {
		return nil, err
	}
	t := &Transport{
		cfg:        cfg,
		opts:       opts,
		onData:     cfg.OnData,
		onPeerData: cfg.OnPeerData,
		peers:      make(map[string]*peerConn),
		closed:     make(chan struct{}),
	}
	return t, nil
}

func parseOptions(cfg transport.Config) (Options, error) {
	opts := Options{}
	if cfg.Options != nil {
		o, ok := cfg.Options.(Options)
		if !ok {
			return Options{}, fmt.Errorf("%w: got %T", transport.ErrOptionsTypeMismatch, cfg.Options)
		}
		opts = o
	}
	if opts.Endpoint == "" {
		opts.Endpoint = strings.TrimSpace(cfg.Endpoint)
	}
	if opts.ListenAddr == "" {
		opts.ListenAddr = strings.TrimSpace(cfg.ListenAddr)
	}
	// Allow Endpoint via ProxyAddr:ProxyPort as a fallback seam for older
	// embedders that only set those fields.
	if opts.Endpoint == "" && cfg.ProxyAddr != "" && cfg.ProxyPort > 0 {
		opts.Endpoint = net.JoinHostPort(cfg.ProxyAddr, fmt.Sprintf("%d", cfg.ProxyPort))
	}
	return opts, nil
}

// Transport is a KCP-over-TURN (client) or KCP-UDP (server) byte pipe.
type Transport struct {
	cfg        transport.Config
	opts       Options
	onData     func([]byte)
	onPeerData func(peerID string, data []byte)

	mu       sync.RWMutex
	client   *kcp.UDPSession
	turnCli  *turn.Client
	udpConn  net.PacketConn
	relay    net.PacketConn
	listener *kcp.Listener
	peers    map[string]*peerConn
	peerSeq  atomic.Uint64

	onReconnect     func()
	shouldReconnect func() bool
	onEnded         func(string)

	connected atomic.Bool
	closeOnce sync.Once
	closed    chan struct{}
	wg        sync.WaitGroup
}

type peerConn struct {
	id   string
	sess *kcp.UDPSession
}

// Connect establishes the client TURN+KCP path or starts the server listener.
func (t *Transport) Connect(ctx context.Context) error {
	if t.connected.Load() {
		return errAlreadyConnected
	}
	if t.isServer() {
		if err := t.connectServer(ctx); err != nil {
			return err
		}
	} else {
		if err := t.connectClient(ctx); err != nil {
			return err
		}
	}
	t.connected.Store(true)
	return nil
}

func (t *Transport) isServer() bool {
	if strings.TrimSpace(t.opts.ListenAddr) != "" {
		return true
	}
	// Server role when peer-data callback is wired and no client endpoint.
	return t.onPeerData != nil && strings.TrimSpace(t.opts.Endpoint) == ""
}

func (t *Transport) connectClient(ctx context.Context) error {
	endpoint := strings.TrimSpace(t.opts.Endpoint)
	if endpoint == "" {
		return errEndpointRequired
	}

	var packetConn net.PacketConn
	var turnCli *turn.Client
	var relay net.PacketConn

	if t.opts.Direct {
		pc, err := listenProtectedUDP()
		if err != nil {
			return err
		}
		packetConn = pc
		logger.Infof("turnrelay: client DIRECT udp → %s", endpoint)
	} else {
		creds, err := issueTurnCredentials(ctx, t.cfg.Carrier, t.cfg.RoomURL, t.cfg.AuthToken)
		if err != nil {
			return err
		}
		pc, err := listenProtectedUDP()
		if err != nil {
			return err
		}
		packetConn = pc

		turnAddr := net.JoinHostPort(creds.Host, creds.Port)
		allocCtx, cancel := context.WithTimeout(ctx, turnAllocateTimeout)
		defer cancel()

		cli, rel, err := allocateTURN(allocCtx, pc, turnAddr, creds.Username, creds.Password)
		if err != nil {
			_ = pc.Close()
			return err
		}
		turnCli = cli
		relay = rel
		packetConn = rel
		logger.Infof("turnrelay: client TURN allocated via %s → peer %s", turnAddr, endpoint)
	}

	sess, err := kcp.NewConn(endpoint, nil, kcpDataShard, kcpParityShard, packetConn)
	if err != nil {
		_ = packetConn.Close()
		if turnCli != nil {
			turnCli.Close()
		}
		return fmt.Errorf("kcp dial %s: %w", endpoint, err)
	}
	tuneKCP(sess)

	t.mu.Lock()
	t.client = sess
	t.turnCli = turnCli
	t.udpConn = packetConn
	t.relay = relay
	t.mu.Unlock()

	t.wg.Add(1)
	go t.readClientLoop(sess)
	return nil
}

func (t *Transport) connectServer(_ context.Context) error {
	addr := strings.TrimSpace(t.opts.ListenAddr)
	if addr == "" {
		addr = defaultListenAddr
	}
	ln, err := kcp.ListenWithOptions(addr, nil, kcpDataShard, kcpParityShard)
	if err != nil {
		return fmt.Errorf("%w: listen %s: %v", errServerNeedsListen, addr, err)
	}
	t.mu.Lock()
	t.listener = ln
	t.mu.Unlock()
	logger.Infof("turnrelay: server listening on %s", addr)

	t.wg.Add(1)
	go t.acceptLoop(ln)
	return nil
}

func allocateTURN(
	ctx context.Context,
	pc net.PacketConn,
	turnAddr, username, password string,
) (*turn.Client, net.PacketConn, error) {
	cli, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: turnAddr,
		TURNServerAddr: turnAddr,
		Conn:           pc,
		Username:       username,
		Password:       password,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("turn.NewClient: %w", err)
	}
	if err := cli.Listen(); err != nil {
		cli.Close()
		return nil, nil, fmt.Errorf("turn.Listen: %w", err)
	}

	type result struct {
		relay net.PacketConn
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		relay, err := cli.Allocate()
		ch <- result{relay: relay, err: err}
	}()
	select {
	case <-ctx.Done():
		cli.Close()
		return nil, nil, fmt.Errorf("turn allocate: %w", ctx.Err())
	case res := <-ch:
		if res.err != nil {
			cli.Close()
			return nil, nil, fmt.Errorf("turn allocate: %w", res.err)
		}
		return cli, res.relay, nil
	}
}

func listenProtectedUDP() (net.PacketConn, error) {
	// Prefer ProtectedNet so iOS Protector (IP_BOUND_IF) / Android VpnService.protect
	// run on the fd before TURN Allocate.
	if pnet, err := protect.NewProtectedNet(); err == nil {
		pc, err := pnet.ListenPacket("udp4", ":0")
		if err == nil {
			return pc, nil
		}
		logger.Warnf("turnrelay: ProtectedNet.ListenPacket failed: %v; falling back", err)
	}
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	return pc, nil
}

func tuneKCP(sess *kcp.UDPSession) {
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(1024, 1024)
	sess.SetStreamMode(true)
	_ = sess.SetDSCP(0)
	_ = sess.SetReadBuffer(4 * 1024 * 1024)
	_ = sess.SetWriteBuffer(4 * 1024 * 1024)
}

func (t *Transport) readClientLoop(sess *kcp.UDPSession) {
	defer t.wg.Done()
	for {
		frame, err := readFrame(sess)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, errClosed) {
				logger.Warnf("turnrelay: client read: %v", err)
			}
			t.handleDisconnect("client-read-end")
			return
		}
		if cb := t.onData; cb != nil {
			cb(frame)
		}
	}
}

func (t *Transport) acceptLoop(ln *kcp.Listener) {
	defer t.wg.Done()
	for {
		sess, err := ln.AcceptKCP()
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
			}
			logger.Warnf("turnrelay: accept: %v", err)
			time.Sleep(acceptBackoff)
			continue
		}
		tuneKCP(sess)
		peerID := t.registerPeer(sess)
		logger.Infof("turnrelay: accepted peer=%s remote=%s", peerID, sess.RemoteAddr())
		t.wg.Add(1)
		go t.readPeerLoop(peerID, sess)
	}
}

func (t *Transport) registerPeer(sess *kcp.UDPSession) string {
	id := fmt.Sprintf("p%d", t.peerSeq.Add(1))
	t.mu.Lock()
	t.peers[id] = &peerConn{id: id, sess: sess}
	t.mu.Unlock()
	return id
}

func (t *Transport) readPeerLoop(peerID string, sess *kcp.UDPSession) {
	defer t.wg.Done()
	defer t.dropPeer(peerID)
	for {
		frame, err := readFrame(sess)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				logger.Warnf("turnrelay: peer %s read: %v", peerID, err)
			}
			return
		}
		if cb := t.onPeerData; cb != nil {
			cb(peerID, frame)
		} else if cb := t.onData; cb != nil {
			cb(frame)
		}
	}
}

func (t *Transport) dropPeer(peerID string) {
	t.mu.Lock()
	p, ok := t.peers[peerID]
	if ok {
		delete(t.peers, peerID)
	}
	t.mu.Unlock()
	if ok && p.sess != nil {
		_ = p.sess.Close()
	}
}

func (t *Transport) handleDisconnect(reason string) {
	if !t.connected.Swap(false) {
		return
	}
	logger.Warnf("turnrelay: disconnect reason=%s", reason)
	if t.shouldReconnect != nil && t.shouldReconnect() && t.onReconnect != nil {
		t.onReconnect()
		return
	}
	if t.onEnded != nil {
		t.onEnded(reason)
	}
}

// Send transmits a frame to the single client peer (client role) or the
// first server peer when only one is connected.
func (t *Transport) Send(data []byte) error {
	t.mu.RLock()
	client := t.client
	t.mu.RUnlock()
	if client != nil {
		return writeFrame(client, data)
	}
	t.mu.RLock()
	var first *peerConn
	for _, p := range t.peers {
		first = p
		break
	}
	t.mu.RUnlock()
	if first == nil || first.sess == nil {
		return errNotConnected
	}
	return writeFrame(first.sess, data)
}

// SendTo transmits a frame to a specific accepted peer (server role).
func (t *Transport) SendTo(peerID string, data []byte) error {
	t.mu.RLock()
	p := t.peers[peerID]
	t.mu.RUnlock()
	if p == nil || p.sess == nil {
		return fmt.Errorf("%w: %s", errNoPeer, peerID)
	}
	return writeFrame(p.sess, data)
}

// SupportsPeerRouting reports true for the server accept path.
func (t *Transport) SupportsPeerRouting() bool {
	return t.isServer()
}

// Close tears down TURN/KCP resources.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		t.connected.Store(false)
		t.mu.Lock()
		if t.client != nil {
			_ = t.client.Close()
			t.client = nil
		}
		if t.listener != nil {
			_ = t.listener.Close()
			t.listener = nil
		}
		for id, p := range t.peers {
			if p.sess != nil {
				_ = p.sess.Close()
			}
			delete(t.peers, id)
		}
		if t.relay != nil {
			_ = t.relay.Close()
			t.relay = nil
		}
		if t.turnCli != nil {
			t.turnCli.Close()
			t.turnCli = nil
		}
		if t.udpConn != nil {
			_ = t.udpConn.Close()
			t.udpConn = nil
		}
		t.mu.Unlock()
	})
	t.wg.Wait()
	return nil
}

// Reconnect rebuilds the client path; server stays listening.
func (t *Transport) Reconnect(reason string) {
	logger.Infof("turnrelay: reconnect requested reason=%s", reason)
	if t.isServer() {
		return
	}
	t.mu.Lock()
	if t.client != nil {
		_ = t.client.Close()
		t.client = nil
	}
	if t.relay != nil {
		_ = t.relay.Close()
		t.relay = nil
	}
	if t.turnCli != nil {
		t.turnCli.Close()
		t.turnCli = nil
	}
	if t.udpConn != nil {
		_ = t.udpConn.Close()
		t.udpConn = nil
	}
	t.mu.Unlock()
	t.connected.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), turnAllocateTimeout)
	defer cancel()
	if err := t.connectClient(ctx); err != nil {
		logger.Warnf("turnrelay: reconnect failed: %v", err)
		if t.onEnded != nil {
			t.onEnded("reconnect-failed")
		}
		return
	}
	t.connected.Store(true)
	if t.onReconnect != nil {
		t.onReconnect()
	}
}

// SetReconnectCallback registers a reconnect handler.
func (t *Transport) SetReconnectCallback(cb func()) { t.onReconnect = cb }

// SetShouldReconnect configures reconnect policy.
func (t *Transport) SetShouldReconnect(fn func() bool) { t.shouldReconnect = fn }

// SetEndedCallback registers end-of-session handling.
func (t *Transport) SetEndedCallback(cb func(string)) { t.onEnded = cb }

// WatchConnection blocks until the transport is closed.
func (t *Transport) WatchConnection(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-t.closed:
	}
}

// CanSend reports whether a write path is available.
func (t *Transport) CanSend() bool {
	if !t.connected.Load() {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.client != nil {
		return true
	}
	return len(t.peers) > 0
}

// Features describes turnrelay delivery semantics.
func (t *Transport) Features() transport.Features {
	return transport.Features{
		Reliable:        true,
		Ordered:         true,
		MessageOriented: true,
		MaxPayloadSize:  defaultMaxPayload,
	}
}

var (
	_ transport.Transport     = (*Transport)(nil)
	_ transport.PeerTransport = (*Transport)(nil)
)
