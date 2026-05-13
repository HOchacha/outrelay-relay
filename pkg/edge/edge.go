// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package edge implements the relay's data-plane front: it accepts
// QUIC connections from agents, dispatches ORP control frames, and
// pairs streams across two agents in splice mode. It is the
// integration surface where registry resolution, policy evaluation,
// the stream-resume matcher (for reconnects), the candidate forwarder
// (for P2P promotion), and the inter-relay forwarder come together.
package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	pbcontrol "github.com/boanlab/OutRelay/lib/control/v1"
	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/observe"
	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/resume"
	"github.com/boanlab/OutRelay/lib/transport"

	"github.com/boanlab/outrelay-relay/pkg/audit"
	"github.com/boanlab/outrelay-relay/pkg/forward"
	"github.com/boanlab/outrelay-relay/pkg/intra"
	"github.com/boanlab/outrelay-relay/pkg/policy"
	"github.com/boanlab/outrelay-relay/pkg/registry"
	"github.com/boanlab/outrelay-relay/pkg/splice"
)

// Server runs the relay accept loop.
type Server struct {
	listenAddr string
	tlsConf    *tls.Config
	reg        *registry.Registry
	policy     *policy.Engine
	cache      *policy.Cache
	audit      *audit.Emitter
	pool       *intra.Pool
	forward    *forward.Plane // nil disables relay_mode=FORWARD
	metrics    *relayMetrics
	resumer    *resumeMatcher
	logger     *slog.Logger

	// pairsMu protects pairs. pairs[stream_id] is the (consumer URI,
	// provider URI) tuple recorded at handleConsumerStream entry so
	// CANDIDATE_OFFER / CANDIDATE_ANSWER frames can be routed back to
	// the right peer on its control stream.
	pairsMu sync.Mutex
	pairs   map[uint64]streamPair

	// migrated tracks streams that have left the splice via
	// MIGRATE_TO_P2P, kept around for MigrationTTL so a fast
	// MIGRATE_TO_RELAY demotion can pick up the same metadata.
	migrated *migratedLRU
}

type streamPair struct {
	consumerURI string
	providerURI string
}

// relayMetrics holds the named instances we touch on the hot path.
// Pulled into a struct so each lookup happens once at construction.
type relayMetrics struct {
	streamOpenDuration *observe.Histogram
	streamActive       *observe.Gauge
	policyEvalDuration *observe.Histogram
	policyCacheHits    *observe.Counter
	policyCacheMisses  *observe.Counter
	bytesForwarded     *observe.Counter
	intraRelayHops     *observe.Counter
	streamRejects      *observe.Counter
}

func newRelayMetrics(reg *observe.Registry) *relayMetrics {
	if reg == nil {
		return nil
	}
	return &relayMetrics{
		streamOpenDuration: reg.Histogram("stream_open_duration"),
		streamActive:       reg.Gauge("stream_active"),
		policyEvalDuration: reg.Histogram("policy_eval_duration"),
		policyCacheHits:    reg.Counter("policy_cache_hits"),
		policyCacheMisses:  reg.Counter("policy_cache_misses"),
		bytesForwarded:     reg.Counter("bytes_forwarded"),
		intraRelayHops:     reg.Counter("intra_relay_hops"),
		streamRejects:      reg.Counter("stream_rejects"),
	}
}

// New configures (but does not start) a relay server. policyEngine,
// cache, audit, pool, and obsReg may be nil for tests / single-relay
// setups.
func New(listenAddr string, tlsConf *tls.Config, reg *registry.Registry, policyEngine *policy.Engine, cache *policy.Cache, auditEm *audit.Emitter, pool *intra.Pool, fwd *forward.Plane, obsReg *observe.Registry, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		listenAddr: listenAddr,
		tlsConf:    tlsConf,
		reg:        reg,
		policy:     policyEngine,
		cache:      cache,
		audit:      auditEm,
		pool:       pool,
		forward:    fwd,
		metrics:    newRelayMetrics(obsReg),
		resumer:    newResumeMatcher(),
		pairs:      map[uint64]streamPair{},
		migrated:   newMigratedLRU(),
		logger:     logger,
	}
}

// recordPair / forgetPair maintain stream_id -> (consumer, provider)
// for candidate routing. recordPair returns false if streamID is
// already mapped to a DIFFERENT pair — that is a stream-id collision
// and the caller must reject the stream rather than silently take
// over the existing splice.
func (s *Server) recordPair(streamID uint64, p streamPair) bool {
	if streamID == 0 {
		return true
	}
	s.pairsMu.Lock()
	defer s.pairsMu.Unlock()
	if existing, ok := s.pairs[streamID]; ok && existing != p {
		return false
	}
	s.pairs[streamID] = p
	return true
}

func (s *Server) forgetPair(streamID uint64) {
	if streamID == 0 {
		return
	}
	s.pairsMu.Lock()
	delete(s.pairs, streamID)
	s.pairsMu.Unlock()
}

// peerOf returns the peer URI for stream_id (the agent on the other
// end), looking up the recorded pair against caller (the requester).
// Returns "" if the stream is unknown or caller is neither side.
func (s *Server) peerOf(streamID uint64, callerURI string) string {
	s.pairsMu.Lock()
	defer s.pairsMu.Unlock()
	p, ok := s.pairs[streamID]
	if !ok {
		known := make([]uint64, 0, len(s.pairs))
		for k := range s.pairs {
			known = append(known, k)
		}
		s.logger.Warn("edge: peerOf miss",
			"stream_id", streamID, "caller", callerURI,
			"known_streams", known, "known_count", len(known))
		return ""
	}
	switch callerURI {
	case p.consumerURI:
		return p.providerURI
	case p.providerURI:
		return p.consumerURI
	}
	return ""
}

// Registry exposes the in-memory service registry (tests use this).
func (s *Server) Registry() *registry.Registry { return s.reg }

// Run blocks until ctx is canceled or Accept errors. Returns nil on
// clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	ln, err := transport.ListenQUIC(s.listenAddr, s.tlsConf, nil)
	if err != nil {
		return fmt.Errorf("edge: listen: %w", err)
	}
	defer func() { _ = ln.Close() }()
	s.logger.Info("relay listening", "addr", ln.Addr())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return fmt.Errorf("edge: accept: %w", err)
		}
		go s.serveConn(ctx, conn)
	}
}

// RunListener uses an already-bound listener (for tests that want a
// random ephemeral port and need to know the address before Run).
func (s *Server) RunListener(ctx context.Context, ln transport.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return fmt.Errorf("edge: accept: %w", err)
		}
		go s.serveConn(ctx, conn)
	}
}

// serveConn handles a single accepted connection. The peer cert URI's
// Role decides whether it's an agent (the splice path) or a peer
// relay (the inter-relay forwarding path).
func (s *Server) serveConn(ctx context.Context, conn transport.Conn) {
	defer func() { _ = conn.Close() }()

	uri, err := uriFromConn(conn)
	if err != nil {
		s.logger.Warn("reject conn: missing identity", "err", err)
		return
	}
	name, err := identity.Parse(uri)
	if err != nil {
		s.logger.Warn("reject conn: bad identity URI", "uri", uri, "err", err)
		return
	}

	if name.Role == identity.RoleRelay {
		s.servePeerRelay(ctx, conn, uri)
		return
	}

	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		s.logger.Warn("accept control stream", "uri", uri, "err", err)
		return
	}

	hello := &orpv1.Hello{}
	f, err := orp.ParseFrame(ctrl)
	if err != nil {
		s.logger.Warn("read HELLO", "uri", uri, "err", err)
		return
	}
	if err := orp.UnmarshalProto(f, orp.FrameTypeHello, hello); err != nil {
		s.logger.Warn("parse HELLO", "uri", uri, "err", err)
		return
	}
	if hello.AgentUri != uri {
		s.logger.Warn("HELLO uri mismatch", "cert_uri", uri, "claimed_uri", hello.AgentUri)
		return
	}
	if err := orp.WriteFrame(ctrl, orp.FrameTypeHelloAck, &orpv1.HelloAck{}); err != nil {
		s.logger.Warn("write HELLO_ACK", "uri", uri, "err", err)
		return
	}

	ac := &AgentConn{conn: conn, uri: uri, ctrl: ctrl}
	s.reg.RegisterAgent(uri, ac)
	s.logger.Info("agent connected", "uri", uri)
	defer func() {
		s.reg.UnregisterAgent(ctx, uri)
		s.logger.Info("agent disconnected", "uri", uri)
	}()

	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Control loop on stream 0.
	go s.controlLoop(connCtx, ac, ctrl)

	// Stream loop: every freshly accepted stream from this conn is an
	// OPEN_STREAM from the consumer side of this agent.
	for {
		stream, err := conn.AcceptStream(connCtx)
		if err != nil {
			return
		}
		go s.handleConsumerStream(connCtx, ac, stream)
	}
}

func (s *Server) controlLoop(ctx context.Context, ac *AgentConn, ctrl transport.Stream) {
	for {
		f, err := orp.ParseFrame(ctrl)
		if err != nil {
			return
		}
		switch f.Type {
		case orp.FrameTypeRegister:
			s.handleRegister(ctx, ac, ctrl, f)
		case orp.FrameTypePing:
			_ = orp.WriteFrame(ctrl, orp.FrameTypePong, &orpv1.HelloAck{})
		case orp.FrameTypeObservedAddrQuery:
			s.handleObservedAddrQuery(ac, ctrl, f)
		case orp.FrameTypeCandidateOffer, orp.FrameTypeCandidateAnswer:
			s.forwardCandidate(ac, f)
		case orp.FrameTypeStreamCheckpoint:
			s.forwardCheckpoint(ac, f)
		case orp.FrameTypeMigrateToP2P:
			s.handleMigrateToP2P(ac, f)
		default:
			s.logger.Warn("unexpected control frame", "type", f.Type, "from", ac.uri)
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (s *Server) handleRegister(ctx context.Context, ac *AgentConn, ctrl transport.Stream, f *orp.Frame) {
	reg := &orpv1.Register{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeRegister, reg); err != nil {
		s.logger.Warn("bad REGISTER", "err", err)
		return
	}
	id, err := s.reg.RegisterService(ctx, ac.uri, reg.ServiceName, reg.LocalAddr)
	if err != nil {
		s.logger.Warn("register rejected", "name", reg.ServiceName, "err", err)
		return
	}
	s.logger.Info("registered", "name", reg.ServiceName, "agent", ac.uri)
	_ = orp.WriteFrame(ctrl, orp.FrameTypeRegisterAck, &orpv1.RegisterAck{
		ServiceId: id,
	})
}

// handleConsumerStream reads an OPEN_STREAM, looks up the provider,
// asks the provider to open an incoming stream, and splices the two
// once the provider sends STREAM_ACCEPT.
func (s *Server) handleConsumerStream(ctx context.Context, caller *AgentConn, consumerStream transport.Stream) {
	streamStart := time.Now()
	defer consumerStream.Close()
	if s.metrics != nil {
		s.metrics.streamActive.Inc()
		defer func() {
			s.metrics.streamActive.Dec()
			s.metrics.streamOpenDuration.Observe(time.Since(streamStart))
		}()
	}

	f, err := orp.ParseFrame(consumerStream)
	if err != nil {
		s.logger.Warn("edge: consumer-stream parse failed",
			"caller", caller.uri, "err", err)
		return
	}
	// A fresh stream may carry STREAM_RESUME instead of OPEN_STREAM
	// when an agent is reconnecting after a relay failure.
	if f.Type == orp.FrameTypeStreamResume {
		s.handleResumeHalf(ctx, consumerStream, f)
		return
	}
	// MIGRATE_TO_RELAY arrives on a fresh stream when an agent is
	// demoting a P2P session back to relay-mediated. The pairing
	// logic is identical to STREAM_RESUME — re-use the matcher so
	// both halves splice once they arrive.
	if f.Type == orp.FrameTypeMigrateToRelay {
		s.handleMigrateToRelay(consumerStream, f)
		return
	}
	if f.Type != orp.FrameTypeOpenStream {
		s.logger.Warn("first frame not OPEN_STREAM", "type", f.Type, "from", caller.uri)
		return
	}
	open := &orpv1.OpenStream{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeOpenStream, open); err != nil {
		s.logger.Warn("edge: OPEN_STREAM unmarshal failed",
			"caller", caller.uri, "err", err)
		return
	}
	s.logger.Debug("edge: OPEN_STREAM received",
		"caller", caller.uri, "target", open.TargetService, "method", open.Method)

	// Caller-side policy check first — if the consumer's view denies,
	// we never bother resolving.
	var p2pMode policy.P2PMode
	var relayMode policy.RelayMode
	if s.policy != nil {
		dec := s.evaluate(caller.uri, open.TargetService, open.Method)
		s.recordAudit(caller.uri, open.TargetService, open.Method, dec)
		if dec.Decision == policy.DecisionDeny {
			_ = orp.WriteFrame(consumerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
				Code: 403, Reason: "denied: " + dec.Reason,
			})
			return
		}
		p2pMode = dec.P2PMode
		relayMode = dec.RelayMode
		s.logger.Debug("edge: policy evaluated (caller-side)",
			"caller", caller.uri, "target", open.TargetService, "method", open.Method,
			"decision", dec.Decision.String(), "relay_mode", relayMode.String(),
			"p2p_mode", p2pMode.String(), "reason", dec.Reason)
	}

	prov, remote, err := s.reg.Resolve(ctx, caller.uri, open.TargetService)
	if errors.Is(err, registry.ErrProviderRemote) {
		if s.pool == nil || remote == nil || remote.Endpoint == "" {
			_ = orp.WriteFrame(consumerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
				Code: 502, Reason: "inter-relay forwarding unavailable",
			})
			return
		}
		s.forwardToPeer(ctx, caller.uri, open, consumerStream, remote)
		return
	}
	if err != nil {
		_ = orp.WriteFrame(consumerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
			Code: 404, Reason: "service not found",
		})
		return
	}
	// Callee-side policy check — now that we know the resolved
	// provider URI, evaluate from the provider's perspective. A
	// FORBIDDEN / REQUIRED on either side combines with the
	// caller-side mode via CombineP2PModes.
	if s.policy != nil {
		callee := s.evaluate(prov.AgentURI(), caller.uri, open.Method)
		s.recordAudit(prov.AgentURI(), caller.uri, open.Method, callee)
		s.logger.Debug("edge: policy evaluated (callee-side)",
			"provider", prov.AgentURI(), "caller", caller.uri, "method", open.Method,
			"decision", callee.Decision.String(), "relay_mode", callee.RelayMode.String(),
			"p2p_mode", callee.P2PMode.String(), "reason", callee.Reason)
		if callee.Decision == policy.DecisionDeny {
			_ = orp.WriteFrame(consumerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
				Code: 403, Reason: "denied (callee): " + callee.Reason,
			})
			return
		}
		p2pMode = policy.CombineP2PModes(p2pMode, callee.P2PMode)
		// Note: callee.RelayMode is intentionally NOT combined here —
		// caller-side relay_mode wins. The Debug log above makes that
		// visible if the two sides disagree.
	}

	// Final mode decision for this stream — logged once at Info so
	// production logs always show splice vs forward without --log-level=debug.
	// Also surfaces the silent-downgrade case (policy says forward but the
	// relay has no forward plane configured, so the data path falls back
	// to splice).
	effectiveRelayMode := relayMode
	if relayMode == policy.RelayModeForward && s.forward == nil {
		s.logger.Warn("edge: policy requests forward but forward plane is disabled — falling back to splice (start relay with --listen-forward)",
			"stream_id", open.StreamId, "caller", caller.uri, "provider", prov.AgentURI())
		effectiveRelayMode = policy.RelayModeSplice
	}
	s.logger.Info("edge: stream mode resolved",
		"stream_id", open.StreamId, "caller", caller.uri, "provider", prov.AgentURI(),
		"service", open.TargetService,
		"policy_relay_mode", relayMode.String(),
		"effective_relay_mode", effectiveRelayMode.String(),
		"p2p_mode", p2pMode.String())

	s.logger.Debug("edge: OpenIncoming begin",
		"stream_id", open.StreamId, "consumer", caller.uri,
		"provider", prov.AgentURI(), "service", open.TargetService)
	provStream, err := prov.OpenIncoming(open.TargetService, open.Method, caller.uri, open.StreamId)
	if err != nil {
		s.logger.Warn("edge: OpenIncoming failed",
			"stream_id", open.StreamId, "consumer", caller.uri,
			"provider", prov.AgentURI(), "service", open.TargetService, "err", err)
		_ = orp.WriteFrame(consumerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
			Code: 502, Reason: "provider stream open failed",
		})
		return
	}
	s.logger.Debug("edge: OpenIncoming ok",
		"stream_id", open.StreamId, "consumer", caller.uri, "provider", prov.AgentURI())
	defer func() { _ = provStream.Close() }()

	// Record the (consumer, provider) pair so candidate frames can
	// route between them. The entry only lives as long as the splice.
	// On collision, reject with 409 so the consumer regenerates its
	// stream id rather than colliding with an active splice.
	pair := streamPair{consumerURI: caller.uri, providerURI: prov.AgentURI()}
	if !s.recordPair(open.StreamId, pair) {
		s.logger.Warn("stream id collision rejected",
			"stream_id", open.StreamId, "consumer", caller.uri, "provider", prov.AgentURI())
		_ = orp.WriteFrame(consumerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
			Code: 409, Reason: "stream id collision",
		})
		return
	}
	s.logger.Debug("edge: stream pair recorded",
		"stream_id", open.StreamId, "consumer", caller.uri, "provider", prov.AgentURI())
	defer func() {
		s.logger.Debug("edge: stream pair forgotten",
			"stream_id", open.StreamId, "consumer", caller.uri, "provider", prov.AgentURI())
		s.forgetPair(open.StreamId)
	}()

	// p2p_mode=required enforcement: arm a promotion timer. If
	// MIGRATE_TO_P2P (recorded into migratedLRU) does not arrive
	// within RequiredPromotionTimeout, tear down the splice — the
	// stream is policy-required to flow direct, so a relay-mediated
	// path is a policy violation.
	if p2pMode == policy.P2PModeRequired && s.migrated != nil {
		killCtx, killCancel := context.WithCancel(ctx)
		defer killCancel()
		go s.enforceRequiredPromotion(killCtx, open.StreamId, consumerStream)
	}

	// Wait for STREAM_ACCEPT from the provider.
	ack, err := orp.ParseFrame(provStream)
	if err != nil {
		s.logger.Warn("edge: provider STREAM_ACCEPT parse failed",
			"caller", caller.uri, "provider", prov.AgentURI(),
			"stream_id", open.StreamId, "err", err)
		return
	}
	switch ack.Type {
	case orp.FrameTypeStreamAccept:
	case orp.FrameTypeStreamReject:
		s.logger.Info("edge: provider rejected stream",
			"caller", caller.uri, "provider", prov.AgentURI(), "stream_id", open.StreamId)
		_ = orp.WriteFrame(consumerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
			Code: 503, Reason: "provider rejected",
		})
		return
	default:
		s.logger.Warn("edge: unexpected provider ack frame",
			"caller", caller.uri, "provider", prov.AgentURI(),
			"type", ack.Type, "stream_id", open.StreamId)
		return
	}

	// relay_mode=FORWARD: skip splice. Allocate a pair of ids on
	// the mini-TURN forwarding plane and tell each agent (via its
	// stream-0 ctrl) which allocation it owns and which one to send
	// to. The data streams are kept open as a liveness signal —
	// when either side tears down we free the allocations.
	if relayMode == policy.RelayModeForward && s.forward != nil {
		provAC, _ := s.reg.LookupAgent(prov.AgentURI()).(*AgentConn)
		if provAC == nil {
			s.logger.Warn("edge: forward — provider control channel unavailable",
				"caller", caller.uri, "provider", prov.AgentURI(), "stream_id", open.StreamId)
			_ = orp.WriteFrame(consumerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
				Code: 502, Reason: "forward: provider control channel unavailable",
			})
			return
		}
		consumerAlloc := s.forward.Allocate()
		providerAlloc := s.forward.Allocate()
		defer s.forward.Forget(consumerAlloc)
		defer s.forward.Forget(providerAlloc)

		fwdEndpoint := s.forward.Endpoint().String()
		s.logger.Info("edge: forward — allocations granted",
			"stream_id", open.StreamId, "caller", caller.uri, "provider", prov.AgentURI(),
			"consumer_alloc", consumerAlloc, "provider_alloc", providerAlloc,
			"endpoint", fwdEndpoint)
		if err := caller.WriteCtrl(orp.FrameTypeAllocGranted, &orpv1.AllocGranted{
			StreamId:        open.StreamId,
			MyAllocation:    consumerAlloc,
			PeerAllocation:  providerAlloc,
			ForwardEndpoint: fwdEndpoint,
		}); err != nil {
			s.logger.Warn("edge: AllocGranted write to consumer failed",
				"stream_id", open.StreamId, "caller", caller.uri, "err", err)
			return
		}
		if err := provAC.WriteCtrl(orp.FrameTypeAllocGranted, &orpv1.AllocGranted{
			StreamId:        open.StreamId,
			MyAllocation:    providerAlloc,
			PeerAllocation:  consumerAlloc,
			ForwardEndpoint: fwdEndpoint,
		}); err != nil {
			s.logger.Warn("edge: AllocGranted write to provider failed",
				"stream_id", open.StreamId, "provider", prov.AgentURI(), "err", err)
			return
		}
		// Park: drain both data streams so we exit (and free
		// allocs) when either side tears down. In forward mode
		// these streams carry no payload — the data plane is on
		// UDP via the forwarding plane.
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(io.Discard, consumerStream); done <- struct{}{} }()
		go func() { _, _ = io.Copy(io.Discard, provStream); done <- struct{}{} }()
		<-done
		s.logger.Info("edge: forward — stream torn down, releasing allocations",
			"stream_id", open.StreamId, "consumer_alloc", consumerAlloc, "provider_alloc", providerAlloc)
		return
	}

	// Splice mode: notify both agents on their ctrl that the data
	// plane is up before bytes start flowing. Agents block on
	// {StreamReady | AllocGranted} after Dial / STREAM_ACCEPT so a
	// definitive signal here removes any need for a timeout race.
	// Best-effort — provAC may be nil for non-AgentConn providers
	// (synthetic registry entries in tests); the smoke and prod
	// paths always have one.
	provAC, _ := s.reg.LookupAgent(prov.AgentURI()).(*AgentConn)
	_ = caller.WriteCtrl(orp.FrameTypeStreamReady, &orpv1.StreamReady{StreamId: open.StreamId})
	if provAC != nil {
		_ = provAC.WriteCtrl(orp.FrameTypeStreamReady, &orpv1.StreamReady{StreamId: open.StreamId})
	}

	_ = splice.Bidirectional(consumerStream, provStream)
}

// AgentConn is the relay's view of one connected agent. It implements
// registry.Provider so the same pointer is used as the lookup target
// for service registration.
type AgentConn struct {
	conn transport.Conn
	uri  string

	// ctrl is the agent's stream-0 control channel. The relay writes
	// here only via WriteCtrl, which serializes against the
	// controlLoop reader. Set once during serveConn before any other
	// goroutine sees this AgentConn.
	ctrl   transport.Stream
	ctrlMu sync.Mutex
}

func (a *AgentConn) AgentURI() string { return a.uri }

func (a *AgentConn) String() string { return a.uri }

// WriteCtrl serialises a single framed proto onto the agent's stream-0
// control channel under ctrlMu. Used for any relay -> agent ctrl frame
// originating outside controlLoop's request/response pattern (e.g. an
// AllocGranted notification from handleConsumerStream once policy
// resolves to relay_mode=FORWARD).
func (a *AgentConn) WriteCtrl(typ orp.FrameType, msg proto.Message) error {
	a.ctrlMu.Lock()
	defer a.ctrlMu.Unlock()
	return orp.WriteFrame(a.ctrl, typ, msg)
}

// OpenIncoming opens a fresh stream toward the provider agent and
// writes an INCOMING_STREAM frame carrying the consumer's stream_id;
// the agent will reply on the same stream with STREAM_ACCEPT or
// STREAM_REJECT.
func (a *AgentConn) OpenIncoming(service, method, caller string, streamID uint64) (registry.Stream, error) {
	s, err := a.conn.OpenStream(context.Background())
	if err != nil {
		return nil, err
	}
	err = orp.WriteFrame(s, orp.FrameTypeIncomingStream, &orpv1.IncomingStream{
		TargetService:  service,
		Method:         method,
		SourceAgentUri: caller,
		StreamId:       streamID,
	})
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// evaluate consults the cache first, falls back to the engine, and
// caches the result.
func (s *Server) evaluate(caller, target, method string) policy.Result {
	evalStart := time.Now()
	defer func() {
		if s.metrics != nil {
			s.metrics.policyEvalDuration.Observe(time.Since(evalStart))
		}
	}()

	if s.cache != nil {
		if r, ok := s.cache.Get(caller, target, method); ok {
			if s.metrics != nil {
				s.metrics.policyCacheHits.Inc()
			}
			return r
		}
		if s.metrics != nil {
			s.metrics.policyCacheMisses.Inc()
		}
	}
	r := s.policy.Decide(caller, target, method)
	if s.cache != nil {
		s.cache.Put(caller, target, method, r)
	}
	return r
}

// recordAudit best-effort fire-and-forget to the audit emitter.
func (s *Server) recordAudit(caller, target, method string, r policy.Result) {
	if s.audit == nil {
		return
	}
	tenant := ""
	if n, err := identity.Parse(caller); err == nil {
		tenant = n.Tenant
	}
	dec := pbcontrol.Decision_DECISION_ALLOW
	if r.Decision == policy.DecisionDeny {
		dec = pbcontrol.Decision_DECISION_DENY
	}
	s.audit.Emit(&pbcontrol.AuditEvent{
		TsUnixMs: time.Now().UnixMilli(),
		Tenant:   tenant,
		Caller:   caller,
		Target:   target,
		Method:   method,
		Decision: dec,
		Reason:   r.Reason,
	})
}

// servePeerRelay handles a connection from a peer relay (Role=relay).
// Each accepted stream is expected to carry FORWARD_STREAM as its
// first frame; the relay then dispatches as if the consumer were
// local, but skipping policy (peer relay already evaluated it).
func (s *Server) servePeerRelay(ctx context.Context, conn transport.Conn, peerURI string) {
	s.logger.Info("peer relay connected", "uri", peerURI)
	defer s.logger.Info("peer relay disconnected", "uri", peerURI)
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleForwardedStream(ctx, st)
	}
}

func (s *Server) handleForwardedStream(ctx context.Context, peerStream transport.Stream) {
	defer peerStream.Close()
	f, err := orp.ParseFrame(peerStream)
	if err != nil {
		return
	}
	if f.Type != orp.FrameTypeForwardStream {
		s.logger.Warn("peer relay first frame not FORWARD_STREAM", "type", f.Type)
		return
	}
	in := &orpv1.IncomingStream{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeForwardStream, in); err != nil {
		return
	}

	// Local-only resolve: peer relay already routed to us, so we expect
	// the provider to be on this relay's local agent map.
	prov, remote, err := s.reg.Resolve(ctx, in.SourceAgentUri, in.TargetService)
	if err != nil || remote != nil {
		_ = orp.WriteFrame(peerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
			Code: 503, Reason: "no local provider for forwarded stream",
		})
		return
	}

	provStream, err := prov.OpenIncoming(in.TargetService, in.Method, in.SourceAgentUri, in.StreamId)
	if err != nil {
		_ = orp.WriteFrame(peerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
			Code: 502, Reason: "provider open failed",
		})
		return
	}
	defer func() { _ = provStream.Close() }()

	ack, err := orp.ParseFrame(provStream)
	if err != nil || ack.Type != orp.FrameTypeStreamAccept {
		_ = orp.WriteFrame(peerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
			Code: 503, Reason: "provider rejected",
		})
		return
	}
	if err := orp.WriteFrame(peerStream, orp.FrameTypeStreamAccept, &orpv1.StreamAccept{}); err != nil {
		return
	}
	_ = splice.Bidirectional(peerStream, provStream)
}

// forwardToPeer opens a forwarded stream on the cached peer-relay
// connection, splices it with the consumer stream, and on dial /
// open errors drops the cached peer conn so the next attempt
// redials.
func (s *Server) forwardToPeer(ctx context.Context, callerURI string, open *orpv1.OpenStream, consumerStream transport.Stream, remote *registry.Remote) {
	if s.metrics != nil {
		s.metrics.intraRelayHops.Inc()
	}
	peer, err := s.pool.Get(ctx, remote.RelayID, remote.Endpoint)
	if err != nil {
		s.logger.Warn("dial peer relay", "id", remote.RelayID, "err", err)
		_ = orp.WriteFrame(consumerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
			Code: 502, Reason: "peer relay unreachable",
		})
		return
	}
	peerStream, err := intra.ForwardStream(ctx, peer, open.TargetService, open.Method, callerURI)
	if err != nil {
		s.logger.Warn("forward to peer", "id", remote.RelayID, "err", err)
		// Cached conn may be dead; drop so the next attempt redials.
		s.pool.Drop(remote.RelayID)
		_ = orp.WriteFrame(consumerStream, orp.FrameTypeStreamReject, &orpv1.StreamReject{
			Code: 502, Reason: "peer relay forward failed",
		})
		return
	}
	defer peerStream.Close()
	_ = splice.Bidirectional(consumerStream, peerStream)
}

// forwardCandidate routes a CANDIDATE_OFFER or CANDIDATE_ANSWER
// frame from the sender to its peer's control stream. Stream id
// identifies which paired splice the candidates belong to (recorded
// at handleConsumerStream entry). The relay is a blind forwarder
// here — it does not interpret the candidate payload.
func (s *Server) forwardCandidate(from *AgentConn, f *orp.Frame) {
	var streamID uint64
	switch f.Type {
	case orp.FrameTypeCandidateOffer:
		var c orpv1.CandidateOffer
		if err := orp.UnmarshalProto(f, orp.FrameTypeCandidateOffer, &c); err != nil {
			s.logger.Warn("edge: CANDIDATE_OFFER unmarshal failed",
				"from", from.uri, "err", err)
			return
		}
		streamID = c.StreamId
	case orp.FrameTypeCandidateAnswer:
		var c orpv1.CandidateAnswer
		if err := orp.UnmarshalProto(f, orp.FrameTypeCandidateAnswer, &c); err != nil {
			s.logger.Warn("edge: CANDIDATE_ANSWER unmarshal failed",
				"from", from.uri, "err", err)
			return
		}
		streamID = c.StreamId
	default:
		return
	}
	peerURI := s.peerOf(streamID, from.uri)
	if peerURI == "" {
		s.logger.Warn("candidate forward: no peer", "stream_id", streamID, "from", from.uri)
		return
	}
	peer := s.reg.LookupAgent(peerURI)
	if peer == nil {
		s.logger.Warn("candidate forward: peer not connected", "peer_uri", peerURI)
		return
	}
	ac, ok := peer.(*AgentConn)
	if !ok {
		return
	}
	// Re-serialize the original frame onto peer's control stream.
	data, err := f.MarshalBinary()
	if err != nil {
		return
	}
	ac.ctrlMu.Lock()
	defer ac.ctrlMu.Unlock()
	if _, err := ac.ctrl.Write(data); err != nil {
		s.logger.Warn("candidate forward: write peer ctrl", "err", err)
		return
	}
	s.logger.Debug("edge: candidate frame forwarded",
		"frame_type", f.Type, "stream_id", streamID, "from", from.uri, "to", peerURI)
}

// forwardCheckpoint routes a STREAM_CHECKPOINT from one agent's
// control stream to its splice peer's control stream. The relay is
// opaque to the checkpoint payload; it only needs the (caller, peer)
// mapping that handleConsumerStream already records in
// `s.pairs[stream_id]`.
func (s *Server) forwardCheckpoint(from *AgentConn, f *orp.Frame) {
	cp := &orpv1.StreamCheckpoint{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeStreamCheckpoint, cp); err != nil {
		return
	}
	peerURI := s.peerOf(cp.StreamId, from.uri)
	if peerURI == "" {
		// Unknown stream id (already torn down or never paired).
		// Drop silently — this is a best-effort path.
		return
	}
	peer := s.reg.LookupAgent(peerURI)
	if peer == nil {
		return
	}
	ac, ok := peer.(*AgentConn)
	if !ok {
		return
	}
	data, err := f.MarshalBinary()
	if err != nil {
		return
	}
	ac.ctrlMu.Lock()
	defer ac.ctrlMu.Unlock()
	if _, err := ac.ctrl.Write(data); err != nil {
		s.logger.Warn("checkpoint forward: write peer ctrl", "err", err)
	}
}

// handleObservedAddrQuery is the STUN-equivalent path used during
// P2P promotion: the agent's QUIC RemoteAddr is the NAT-mapped public
// endpoint, so we just echo it back as the agent's server-reflexive
// candidate.
func (s *Server) handleObservedAddrQuery(ac *AgentConn, ctrl transport.Stream, f *orp.Frame) {
	q := &orpv1.ObservedAddrQuery{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeObservedAddrQuery, q); err != nil {
		return
	}
	addr := ac.conn.RemoteAddr()
	host, port, err := splitAddr(addr.String())
	if err != nil {
		s.logger.Warn("observed addr parse", "remote", addr.String(), "err", err)
		return
	}
	_ = orp.WriteFrame(ctrl, orp.FrameTypeObservedAddrResp, &orpv1.ObservedAddrResp{
		RequestId: q.RequestId,
		Ip:        host,
		Port:      uint32(port), // #nosec G115 -- TCP/UDP port, fits in uint16 let alone uint32
	})
}

// splitAddr splits "ip:port" or "[ip6]:port" into (ip, port).
func splitAddr(s string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// RequiredPromotionTimeout bounds how long a `p2p_mode=required`
// stream may flow through the relay before MIGRATE_TO_P2P arrives.
// Past the timeout the relay tears down the splice so the stream
// fails fast at the application — keeping the splice would silently
// violate the policy. Exposed as a var so integration tests can
// shrink it without waiting 10 s.
var RequiredPromotionTimeout = 10 * time.Second

// enforceRequiredPromotion polls the migrated LRU; on timeout it
// closes consumerStream so the splice goroutine exits and the agent
// surfaces a connection error to its application. Returns early if
// MIGRATE_TO_P2P arrived (the LRU has the entry) or ctx cancelled
// (splice naturally completed).
func (s *Server) enforceRequiredPromotion(ctx context.Context, streamID uint64, consumerStream transport.Stream) {
	deadline := time.NewTimer(RequiredPromotionTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if s.migrated.Lookup(resume.StreamID(streamID)) != nil {
				// Promotion happened; nothing more to enforce.
				return
			}
		case <-deadline.C:
			s.logger.Warn("required p2p promotion timeout — closing splice",
				"stream_id", streamID)
			_ = consumerStream.Close()
			return
		}
	}
}

// handleMigrateToP2P records the agent's promotion in the migrated
// LRU. Once both agents promote, the active relay splice will tear
// itself down naturally as the agents close their data streams
// toward the relay; this handler exists so a subsequent
// MIGRATE_TO_RELAY can pick the metadata back up within
// MigrationTTL. Idempotent: same stream_id from either side
// overwrites.
func (s *Server) handleMigrateToP2P(ac *AgentConn, f *orp.Frame) {
	m := &orpv1.MigrateToP2P{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeMigrateToP2P, m); err != nil {
		s.logger.Warn("edge: MIGRATE_TO_P2P unmarshal failed",
			"from", ac.uri, "err", err)
		return
	}
	pair := streamPair{}
	s.pairsMu.Lock()
	if p, ok := s.pairs[m.StreamId]; ok {
		pair = p
	}
	s.pairsMu.Unlock()
	// Fall back to "this side is the only known URI" if the splice
	// row has already been forgotten (race with stream close).
	if pair.consumerURI == "" {
		pair.consumerURI = ac.uri
	} else if pair.providerURI == "" {
		pair.providerURI = ac.uri
	}
	s.migrated.Note(&migratedStream{
		id:          resume.StreamID(m.StreamId),
		consumerURI: pair.consumerURI,
		providerURI: pair.providerURI,
	})
	s.logger.Info("stream migrated to p2p", "stream_id", m.StreamId, "by", ac.uri)
}

// handleMigrateToRelay re-uses the resumeMatcher to re-pair the two
// halves and splice. If the migrated LRU has prior metadata for the
// stream, we annotate the log and discard the entry on success.
func (s *Server) handleMigrateToRelay(st transport.Stream, f *orp.Frame) {
	m := &orpv1.MigrateToRelay{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeMigrateToRelay, m); err != nil {
		s.logger.Warn("edge: MIGRATE_TO_RELAY unmarshal failed", "err", err)
		_ = st.Close()
		return
	}
	id := resume.StreamID(m.StreamId)
	prior := s.migrated.Lookup(id)
	if prior != nil {
		s.logger.Info("migrate-to-relay arrived",
			"stream_id", m.StreamId, "reason", m.Reason,
			"prior_consumer", prior.consumerURI, "prior_provider", prior.providerURI)
	}
	half := &halfStream{
		id:         id,
		stream:     st,
		myPos:      int64(m.MyPosition),      // #nosec G115 -- byte count, fits in int64
		peerAckPos: int64(m.PeerAckPosition), // #nosec G115 -- byte count, fits in int64
	}
	matched := <-s.resumer.Submit(half)
	if matched == nil {
		_ = st.Close()
		return
	}
	if prior != nil {
		s.migrated.Discard(id)
	}
	_ = splice.Bidirectional(st, matched.stream)
	_ = st.Close()
	_ = matched.stream.Close()
}

// handleResumeHalf parks one half of a STREAM_RESUME pair in the
// matcher and, when the other half arrives within ResumeWindow,
// splices the two streams.
//
// The agents' own STREAM_RESUME payloads carry the byte counters they
// will use to drive retransmission from their ring buffers; the relay
// itself does not need to interpret those numbers — it only needs to
// connect the two new streams so bytes flow.
func (s *Server) handleResumeHalf(_ context.Context, st transport.Stream, f *orp.Frame) {
	rj := &orpv1.StreamResume{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeStreamResume, rj); err != nil {
		s.logger.Warn("edge: STREAM_RESUME unmarshal failed", "err", err)
		_ = st.Close()
		return
	}
	s.logger.Debug("edge: STREAM_RESUME received",
		"stream_id", rj.StreamId,
		"my_pos", rj.MyPosition, "peer_ack_pos", rj.PeerAckPosition)
	half := &halfStream{
		id:         resume.StreamID(rj.StreamId),
		stream:     st,
		myPos:      int64(rj.MyPosition),      // #nosec G115 -- byte count, fits in int64
		peerAckPos: int64(rj.PeerAckPosition), // #nosec G115 -- byte count, fits in int64
	}
	matched := <-s.resumer.Submit(half)
	if matched == nil {
		// Window expired without a peer; close half so the agent can
		// surface the failure to the application.
		s.logger.Warn("edge: STREAM_RESUME window expired (no peer)",
			"stream_id", rj.StreamId)
		_ = st.Close()
		return
	}
	s.logger.Debug("edge: STREAM_RESUME matched",
		"stream_id", rj.StreamId)
	// Echo peer's STREAM_RESUME payload onto this half's stream so the
	// local agent learns peer.peer_ack_position and can drive the
	// retransmit-from-ring step. The echo is written before splice
	// begins so it sits ahead of any peer app bytes in the byte order.
	_ = orp.WriteFrame(st, orp.FrameTypeStreamResume, &orpv1.StreamResume{
		StreamId:        uint64(half.id),
		MyPosition:      uint64(matched.myPos),      // #nosec G115 -- byte count, never negative
		PeerAckPosition: uint64(matched.peerAckPos), // #nosec G115 -- byte count, never negative
	})
	_ = splice.Bidirectional(st, matched.stream)
	_ = st.Close()
	_ = matched.stream.Close()
}

// uriFromConn extracts the URI SAN from the peer leaf cert.
func uriFromConn(conn transport.Conn) (string, error) {
	st := conn.TLS()
	if len(st.PeerCertificates) == 0 {
		return "", errors.New("edge: peer presented no certificate")
	}
	leaf := st.PeerCertificates[0]
	if len(leaf.URIs) == 0 {
		return "", errors.New("edge: leaf cert has no URI SAN")
	}
	return leaf.URIs[0].String(), nil
}
