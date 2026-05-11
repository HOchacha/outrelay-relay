// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package intra is the inter-relay forwarding plane. When a consumer
// agent's OPEN_STREAM resolves to a provider on a peer relay, the
// receiving relay opens a fresh stream on a long-lived QUIC connection
// to that peer (lazily dialed) and writes a FORWARD_STREAM frame.
// The peer relay then opens INCOMING_STREAM toward its locally
// connected provider agent and splices the two halves.
package intra

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
)

// Pool maintains long-lived QUIC connections to peer relays, keyed by
// relay id. Connections are dialed lazily on first Get for a given id.
//
// A failed dial is not cached: every Get retries from scratch, which
// is fine for the small relay fan-out and avoids stale state.
type Pool struct {
	tlsConf *tls.Config
	logger  *slog.Logger

	mu    sync.Mutex
	conns map[string]transport.Conn // relay-id -> conn
}

// NewPool constructs an empty pool. tlsConf is used for outbound mTLS
// to peer relays — typically the same client cert/CA as the local
// relay's listener, with the relay's URI SAN. A nil logger disables
// logging.
func NewPool(tlsConf *tls.Config, logger *slog.Logger) *Pool {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Pool{
		tlsConf: tlsConf,
		logger:  logger,
		conns:   map[string]transport.Conn{},
	}
}

// Get returns a connection to peer relay with id at endpoint, dialing
// if necessary. Concurrent callers wait on a single dial.
func (p *Pool) Get(ctx context.Context, relayID, endpoint string) (transport.Conn, error) {
	p.mu.Lock()
	if c, ok := p.conns[relayID]; ok {
		p.mu.Unlock()
		p.logger.Debug("intra: pool hit", "relay_id", relayID)
		return c, nil
	}
	p.mu.Unlock()

	// Dial outside the lock so we don't block other relay-id lookups.
	p.logger.Debug("intra: dialing peer relay",
		"relay_id", relayID, "endpoint", endpoint)
	c, err := transport.DialQUIC(ctx, endpoint, p.tlsConf, nil)
	if err != nil {
		p.logger.Warn("intra: dial peer failed",
			"relay_id", relayID, "endpoint", endpoint, "err", err)
		return nil, fmt.Errorf("intra: dial peer %s at %s: %w", relayID, endpoint, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.conns[relayID]; ok {
		// Race: another caller dialed first. Close ours.
		p.logger.Debug("intra: dial race; reusing existing",
			"relay_id", relayID)
		_ = c.Close()
		return existing, nil
	}
	p.conns[relayID] = c
	p.logger.Info("intra: peer relay connected",
		"relay_id", relayID, "endpoint", endpoint)
	return c, nil
}

// Drop forgets the cached conn for relayID and closes it. Called when
// a stream open on the cached conn fails — the next Get will redial.
func (p *Pool) Drop(relayID string) {
	p.mu.Lock()
	c, ok := p.conns[relayID]
	delete(p.conns, relayID)
	p.mu.Unlock()
	if ok {
		p.logger.Info("intra: dropping peer conn", "relay_id", relayID)
		_ = c.Close()
	}
}

// Close terminates every cached conn.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, c := range p.conns {
		_ = c.Close()
		delete(p.conns, id)
	}
	return nil
}

// ForwardStream opens a fresh stream on conn, writes FORWARD_STREAM
// with (target, callerURI, method), and returns the stream — the
// caller splices it with the consumer's stream. The peer relay's
// reply (STREAM_ACCEPT or STREAM_REJECT) arrives as the next frame
// on the same stream and is parsed here.
func ForwardStream(ctx context.Context, conn transport.Conn, target, method, callerURI string) (transport.Stream, error) {
	s, err := conn.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("intra: open peer stream: %w", err)
	}
	if err := orp.WriteFrame(s, orp.FrameTypeForwardStream, &orpv1.IncomingStream{
		TargetService:  target,
		Method:         method,
		SourceAgentUri: callerURI,
	}); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("intra: write FORWARD_STREAM: %w", err)
	}
	// Peer's reply arrives as STREAM_ACCEPT or STREAM_REJECT.
	f, err := orp.ParseFrame(s)
	if err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("intra: read peer reply: %w", err)
	}
	switch f.Type {
	case orp.FrameTypeStreamAccept:
		return s, nil
	case orp.FrameTypeStreamReject:
		_ = s.Close()
		rej := &orpv1.StreamReject{}
		_ = orp.UnmarshalProto(f, orp.FrameTypeStreamReject, rej)
		return nil, fmt.Errorf("intra: peer rejected: %d %s", rej.Code, rej.Reason)
	default:
		_ = s.Close()
		return nil, fmt.Errorf("intra: peer sent unexpected frame type %v", f.Type)
	}
}

// ErrNotPeerStream is returned when a caller attempts to handle a
// stream that does not start with FORWARD_STREAM.
var ErrNotPeerStream = errors.New("intra: not a forwarded stream")
