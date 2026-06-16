// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package forward is the relay's mini-TURN data plane.
// When a stream's policy is `relay_mode = forward`, the relay
// does NOT terminate QUIC for it. Instead each agent gets an
// allocation id, opens a UDP socket, and sends packets to this
// plane's forwarding port with the peer's allocation id as a
// 4-byte big-endian prefix. The plane reads the prefix, looks
// up the registered UDP endpoint for that allocation, and writes
// the trailing payload to it. The agents establish their own
// end-to-end QUIC connection over the forwarded UDP path, so
// this plane sees only ciphertext — no QUIC encrypt / decrypt
// cost for the relay.
//
// Wire format (per UDP datagram from agent to relay):
//
//   [peer_alloc: uint32 BE] [payload: N bytes]
//
// peer_alloc == 0 is a registration packet whose payload is
// [my_alloc: uint32 BE]; the plane records (my_alloc, src) so
// future packets prefixed with that id are forwarded back to src.
// peer_alloc != 0 is a data packet; the plane forwards
// [payload] (without the prefix) to the registered endpoint for
// peer_alloc.
//
// Allocations are simple monotonic uint32 counters starting at 1.
// Allocations have no expiry in this prototype — the relay tracks
// them for the lifetime of the stream they back. Allocations are
// freed via Forget (called from edge.go on stream teardown).

package forward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultAllocIdleTTL is the default window an allocation entry may sit
// without observed activity (no register, no forwarded packet from its
// agent src) before the GC loop reclaims it. Sized to comfortably
// outlive a couple of e2e QUIC keepalive intervals — agents that are
// still healthy will keep their entry warm.
const DefaultAllocIdleTTL = 60 * time.Second

// allocEntry records who owns an allocation, where it is registered, and
// when it was last observed as alive. uri is the cert-verified URI of the
// agent the allocation was issued to — owner identity is a first-class
// property of every entry so audit logs, bulk teardown, and (Phase 2)
// wire-level register verification all share one source of truth.
// lastSeen is atomic so the data-path forwarder can bump it under RLock;
// the GC loop takes the full write lock when it actually evicts.
type allocEntry struct {
	uri      string // cert URI of the owning agent
	src      netip.AddrPort
	lastSeen atomic.Int64 // unix nanos
}

// Plane is the relay's UDP forwarding plane.
//
// All allocations are owned by an agent URI from the moment they are
// issued. byAlloc is the forwarding-fast-path index; byURI lets the
// caller release every alloc belonging to a disconnected agent in one
// call (ForgetAgent). src2id is the reverse data-path index used to
// bump lastSeen in O(1).
type Plane struct {
	udp    *net.UDPConn
	logger *slog.Logger

	mu      sync.RWMutex
	byAlloc map[uint32]*allocEntry         // alloc_id -> entry
	byURI   map[string]map[uint32]struct{} // agent URI -> set of allocs
	src2id  map[netip.AddrPort]uint32      // reverse index: agent src -> alloc id

	nextID  atomic.Uint32
	idleTTL time.Duration // 0 disables the GC loop
}

// NewPlane binds a UDP socket at addr (e.g. "0.0.0.0:9443") and
// returns a Plane ready to Run. Allocations skip 0 since 0 means
// "registration packet" on the wire.
func NewPlane(addr string, logger *slog.Logger) (*Plane, error) {
	if logger == nil {
		logger = slog.Default()
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("forward: resolve %s: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("forward: bind %s: %w", addr, err)
	}
	p := &Plane{
		udp:     conn,
		logger:  logger,
		byAlloc: map[uint32]*allocEntry{},
		byURI:   map[string]map[uint32]struct{}{},
		src2id:  map[netip.AddrPort]uint32{},
		idleTTL: DefaultAllocIdleTTL,
	}
	// nextID starts at 1 (never assign 0 — reserved for the
	// registration sentinel on the wire).
	p.nextID.Store(0)
	return p, nil
}

// SetIdleTTL overrides the default allocation idle timeout. Pass 0 to
// disable the GC loop entirely (entries then live until explicit Forget
// or process exit). Call before Run.
func (p *Plane) SetIdleTTL(d time.Duration) { p.idleTTL = d }

// Endpoint returns the UDP socket address the plane is bound to.
// Use this to populate AllocGranted.forward_endpoint.
func (p *Plane) Endpoint() netip.AddrPort {
	return p.udp.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Allocate issues a fresh allocation id (1+) owned by uri. The agent's
// registration packet later binds the id to its UDP source endpoint.
// uri is the cert-verified URI of the agent the allocation is being
// issued to; storing it up front lets ForgetAgent, OwnerOf, and Phase 2
// register verification all share the same authoritative mapping.
//
// Allocate panics on empty uri — callers must always pass a verified
// identity. Callers that don't have a URI yet are misusing the API.
func (p *Plane) Allocate(uri string) uint32 {
	if uri == "" {
		panic("forward: Allocate called with empty URI")
	}
	var id uint32
	for {
		id = p.nextID.Add(1)
		if id != 0 {
			break
		}
		// Wraparound — skip reserved 0.
		p.logger.Warn("forward: alloc id wraparound (skipping 0)")
	}
	entry := &allocEntry{uri: uri}
	p.mu.Lock()
	p.byAlloc[id] = entry
	set, ok := p.byURI[uri]
	if !ok {
		set = map[uint32]struct{}{}
		p.byURI[uri] = set
	}
	set[id] = struct{}{}
	p.mu.Unlock()
	p.logger.Info("forward: allocation issued", "alloc_id", id, "uri", uri)
	return id
}

// Forget releases a single allocation. Subsequent packets prefixed
// with this id are dropped. Called from edge.go when the underlying
// stream tears down.
func (p *Plane) Forget(id uint32) {
	p.mu.Lock()
	entry, existed := p.byAlloc[id]
	if existed {
		delete(p.byAlloc, id)
		delete(p.src2id, entry.src)
		if set, ok := p.byURI[entry.uri]; ok {
			delete(set, id)
			if len(set) == 0 {
				delete(p.byURI, entry.uri)
			}
		}
	}
	p.mu.Unlock()
	// `existed=false` after the first Forget is normal when the agent
	// never sent its registration packet; a second Forget for the same
	// id is a caller bug (double-release).
	uri := ""
	if entry != nil {
		uri = entry.uri
	}
	p.logger.Info("forward: allocation released",
		"alloc_id", id, "uri", uri, "was_registered", existed)
}

// ForgetAgent releases every allocation owned by uri in one shot.
// Returns the number of allocations actually released.
//
// Called from edge.go's serveConn defer the moment an agent's control
// connection drops, so an agent that crashes without graceful teardown
// no longer has to wait out the idle-TTL window (~60s) for its forward
// resources to be reclaimed.
func (p *Plane) ForgetAgent(uri string) int {
	if uri == "" {
		return 0
	}
	p.mu.Lock()
	set, ok := p.byURI[uri]
	if !ok {
		p.mu.Unlock()
		return 0
	}
	released := 0
	for id := range set {
		entry, present := p.byAlloc[id]
		if !present {
			continue
		}
		delete(p.byAlloc, id)
		delete(p.src2id, entry.src)
		released++
	}
	delete(p.byURI, uri)
	p.mu.Unlock()
	if released > 0 {
		p.logger.Info("forward: bulk teardown", "uri", uri, "released", released)
	}
	return released
}

// OwnerOf returns the URI the allocation was issued to, if it still
// exists. Used by Phase 2 register verification and by audit logging.
func (p *Plane) OwnerOf(id uint32) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.byAlloc[id]
	if !ok {
		return "", false
	}
	return entry.uri, true
}

// Lookup returns the registered endpoint for an allocation id, if
// any. Mostly for tests.
func (p *Plane) Lookup(id uint32) (netip.AddrPort, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.byAlloc[id]
	if !ok {
		return netip.AddrPort{}, false
	}
	return entry.src, true
}

// Run drives the forwarding loop until ctx is cancelled or the
// listener is closed. Errors from individual packets are logged
// and dropped — the loop never exits on a single bad packet.
//
// Also starts the allocation GC loop if idleTTL > 0; the GC reclaims
// entries whose agent src has not sent a packet within the window,
// guarding against the leak that would otherwise happen when an
// agent crashes or migrates without calling Forget on edge.go.
func (p *Plane) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = p.udp.Close()
	}()
	if p.idleTTL > 0 {
		go p.gcLoop(ctx)
	}
	buf := make([]byte, 65536)
	for {
		n, srcAP, err := p.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("forward: read: %w", err)
		}
		if n < 4 {
			p.logger.Debug("forward: dropping short packet",
				"src", srcAP.String(), "len", n)
			continue
		}
		peerAlloc := binary.BigEndian.Uint32(buf[:4])
		if peerAlloc == 0 {
			// Registration: trailing payload is [my_alloc: u32 BE].
			if n < 8 {
				p.logger.Warn("forward: invalid registration packet",
					"src", srcAP.String(), "len", n)
				continue
			}
			myAlloc := binary.BigEndian.Uint32(buf[4:8])
			p.register(myAlloc, srcAP)
			continue
		}
		// Data: forward to the registered endpoint, payload only.
		// Also bump the sender's lastSeen — observing a packet from
		// srcAP proves the sender is alive, regardless of how its
		// peer (the forwarding target) is doing. Use the reverse
		// index so the bump stays O(1).
		now := time.Now().UnixNano()
		p.mu.RLock()
		entry, ok := p.byAlloc[peerAlloc]
		var senderEntry *allocEntry
		if senderID, srcOk := p.src2id[srcAP]; srcOk {
			senderEntry = p.byAlloc[senderID]
		}
		p.mu.RUnlock()
		if senderEntry != nil {
			senderEntry.lastSeen.Store(now)
		}
		if !ok {
			p.logger.Debug("forward: drop (alloc not registered)",
				"alloc_id", peerAlloc, "src", srcAP.String())
			continue
		}
		if _, err := p.udp.WriteToUDPAddrPort(buf[4:n], entry.src); err != nil {
			p.logger.Debug("forward: write to peer endpoint failed",
				"alloc_id", peerAlloc, "dst", entry.src.String(), "err", err)
		}
	}
}

// gcLoop periodically evicts allocation entries whose lastSeen is
// older than idleTTL. Runs until ctx cancels. Ticker period is
// idleTTL/4 (capped at 5s minimum) so eviction granularity is well
// under one TTL.
func (p *Plane) gcLoop(ctx context.Context) {
	interval := p.idleTTL / 4
	interval = max(interval, time.Second)
	interval = min(interval, 5*time.Second)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			p.gcOnce(now)
		}
	}
}

// gcOnce evicts entries whose lastSeen is older than idleTTL relative
// to now. Holds the write lock for the scan. Keeps byURI in sync.
func (p *Plane) gcOnce(now time.Time) {
	cutoff := now.Add(-p.idleTTL).UnixNano()
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, entry := range p.byAlloc {
		if entry.lastSeen.Load() < cutoff {
			delete(p.byAlloc, id)
			delete(p.src2id, entry.src)
			if set, ok := p.byURI[entry.uri]; ok {
				delete(set, id)
				if len(set) == 0 {
					delete(p.byURI, entry.uri)
				}
			}
			p.logger.Info("forward: allocation idle-timeout",
				"alloc_id", id, "uri", entry.uri, "src", entry.src.String(),
				"idle_s", int(now.Sub(time.Unix(0, entry.lastSeen.Load())).Seconds()))
		}
	}
}

// register binds an existing allocation's UDP src endpoint. The entry
// must already exist — i.e. the relay must have called Allocate(uri)
// before this packet arrived. A register packet for an unknown alloc is
// silently dropped: under the URI-primary model, allocations are only
// born through Allocate (which records the owning URI), never lazily
// from an inbound packet. Phase 2 will additionally gate this on a
// nonce armed by the control-plane FrameTypeForwardRegister handler;
// Phase 1 keeps the behaviour permissive (first-write-wins on src) to
// minimise wire churn while the data model is repositioned.
func (p *Plane) register(allocID uint32, src netip.AddrPort) {
	now := time.Now().UnixNano()
	p.mu.Lock()
	entry, existed := p.byAlloc[allocID]
	if !existed {
		p.mu.Unlock()
		p.logger.Debug("forward: drop register (unknown alloc)",
			"alloc_id", allocID, "src", src.String())
		return
	}
	oldSrc := entry.src
	wasNew := !oldSrc.IsValid()
	if oldSrc != src {
		if oldSrc.IsValid() {
			delete(p.src2id, oldSrc)
		}
		entry.src = src
		p.src2id[src] = allocID
	}
	entry.lastSeen.Store(now)
	uri := entry.uri
	p.mu.Unlock()
	switch {
	case wasNew:
		p.logger.Debug("forward: allocation registered",
			"alloc_id", allocID, "uri", uri, "src", src.String())
	case oldSrc != src:
		p.logger.Info("forward: allocation reclaimed",
			"alloc_id", allocID, "uri", uri,
			"old", oldSrc.String(), "new", src.String())
	}
}

// Close shuts the forwarding socket down. Run returns shortly
// after.
func (p *Plane) Close() error {
	return p.udp.Close()
}

// ErrPlaneClosed is returned by helpers when the plane has been
// shut down.
var ErrPlaneClosed = errors.New("forward: plane closed")
