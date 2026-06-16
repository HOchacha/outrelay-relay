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

// PunchNonceSize is the length of the random nonce an agent embeds in
// both its control-plane FrameTypeForwardRegister and its UDP punch
// packet. 16 bytes (2^128 space) is comfortably above what a foreign
// src could brute-force inside the pending window.
const PunchNonceSize = 16

// DefaultPendingTTL is how long a control-plane ForwardRegister-armed
// pending entry stays valid waiting for the matching UDP punch. Five
// seconds covers control/UDP reordering and the worst-case NAT
// pinhole-creation delay without leaving the slot guessable for long.
const DefaultPendingTTL = 5 * time.Second

// pendingEntry is the cert-URI + nonce binding installed by the
// control-plane FrameTypeForwardRegister handler (edge.handleForwardRegister).
// The UDP register loop consults it: a punch whose alloc_id has no
// pending entry, or whose embedded nonce does not match, is dropped
// without touching the live byAlloc table.
type pendingEntry struct {
	uri     string
	nonce   [PunchNonceSize]byte
	expires time.Time
}

// queuedPunch holds an arrived UDP punch whose ArmPending hasn't been
// called yet — typical race between the control-plane ForwardRegister
// (sub-ms processing) and the data-plane punch (sent immediately by
// forward.Dial). Without this buffer the agent's punch loses the race
// and the alloc never binds. Each entry has a short TTL; ArmPending
// drains a queued punch immediately if the nonce matches.
type queuedPunch struct {
	src     netip.AddrPort
	nonce   [PunchNonceSize]byte
	expires time.Time
}

// ErrUnknownAlloc / ErrOwnerMismatch are returned by ArmPending so the
// edge handler can map them to a precise ForwardRegisterReject reason.
var (
	ErrUnknownAlloc  = errors.New("forward: alloc not issued")
	ErrOwnerMismatch = errors.New("forward: alloc owner mismatch")
)

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
// bump lastSeen in O(1). pending holds nonces armed by the control
// plane (FrameTypeForwardRegister) that the UDP punch must match
// before its src is bound to an alloc.
type Plane struct {
	udp    *net.UDPConn
	logger *slog.Logger

	mu      sync.RWMutex
	byAlloc map[uint32]*allocEntry         // alloc_id -> entry
	byURI   map[string]map[uint32]struct{} // agent URI -> set of allocs
	src2id  map[netip.AddrPort]uint32      // reverse index: agent src -> alloc id
	pending map[uint32]*pendingEntry       // alloc_id -> armed nonce + owner
	queued  map[uint32]*queuedPunch        // alloc_id -> punch waiting for ArmPending

	nextID     atomic.Uint32
	idleTTL    time.Duration // 0 disables the GC loop
	pendingTTL time.Duration // 0 means use DefaultPendingTTL
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
		udp:        conn,
		logger:     logger,
		byAlloc:    map[uint32]*allocEntry{},
		byURI:      map[string]map[uint32]struct{}{},
		src2id:     map[netip.AddrPort]uint32{},
		pending:    map[uint32]*pendingEntry{},
		queued:     map[uint32]*queuedPunch{},
		idleTTL:    DefaultAllocIdleTTL,
		pendingTTL: DefaultPendingTTL,
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

// SetPendingTTL overrides the default register-pending TTL (how long
// an armed ForwardRegister stays valid waiting for the UDP punch).
// Mostly for tests; production callers should use the default.
func (p *Plane) SetPendingTTL(d time.Duration) { p.pendingTTL = d }

// ArmPending installs a (uri, nonce) binding for allocID that the
// matching UDP punch must satisfy before its src is bound to the
// alloc. Called by edge.handleForwardRegister after it has verified
// that ac.uri owns the alloc.
//
// Returns ErrUnknownAlloc if the alloc was never issued, or
// ErrOwnerMismatch if it belongs to a different URI — either of those
// the edge handler maps to a ForwardRegisterReject reason. Re-arming
// the same alloc with a new nonce is permitted (it replaces the prior
// pending entry; the previous nonce can no longer satisfy a punch).
func (p *Plane) ArmPending(allocID uint32, uri string, nonce [PunchNonceSize]byte) error {
	if uri == "" {
		return ErrOwnerMismatch
	}
	ttl := p.pendingTTL
	if ttl <= 0 {
		ttl = DefaultPendingTTL
	}
	now := time.Now()
	p.mu.Lock()
	entry, ok := p.byAlloc[allocID]
	if !ok {
		p.mu.Unlock()
		return ErrUnknownAlloc
	}
	if entry.uri != uri {
		p.mu.Unlock()
		return ErrOwnerMismatch
	}
	// If a punch arrived ahead of us (common race: agent sends ctrl
	// frame and UDP punch back-to-back, UDP wins to the relay), drain
	// it now if the nonce matches.
	var (
		drained    bool
		drainedSrc netip.AddrPort
	)
	if q, queuedOK := p.queued[allocID]; queuedOK {
		delete(p.queued, allocID)
		if now.Before(q.expires) && q.nonce == nonce {
			oldSrc := entry.src
			if oldSrc != q.src {
				if oldSrc.IsValid() {
					delete(p.src2id, oldSrc)
				}
				entry.src = q.src
				p.src2id[q.src] = allocID
			}
			entry.lastSeen.Store(now.UnixNano())
			drained = true
			drainedSrc = q.src
		}
	}
	if !drained {
		p.pending[allocID] = &pendingEntry{
			uri:     uri,
			nonce:   nonce,
			expires: now.Add(ttl),
		}
	}
	p.mu.Unlock()
	if drained {
		p.logger.Debug("forward: allocation registered (drained queued punch)",
			"alloc_id", allocID, "uri", uri, "src", drainedSrc.String())
	}
	return nil
}

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
	// Initialise lastSeen to "now" so a freshly issued alloc waiting
	// for its register packet survives a full idleTTL window. Without
	// this the GC sees lastSeen=0 < cutoff and reaps the entry on the
	// very next tick, even though the agent simply hasn't punched yet.
	entry.lastSeen.Store(time.Now().UnixNano())
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
// stream tears down. Any pending / queued register state for the
// alloc is reaped as well so memory tracks the live byAlloc set
// rather than waiting on TTL expiry.
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
	delete(p.pending, id)
	delete(p.queued, id)
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
// Returns the number of allocations actually released. Also drains
// any pending / queued register state owned by uri so the maps don't
// linger past the agent's lifetime.
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
		delete(p.pending, id)
		delete(p.queued, id)
		released++
	}
	delete(p.byURI, uri)
	// Stray pending / queued entries that survived because their alloc
	// already got Forget'd elsewhere are scrubbed by gcOnce; nothing
	// else to do here.
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
			// Registration: [my_alloc: u32 BE] [nonce: PunchNonceSize bytes].
			// The nonce must match what the agent claimed on its
			// control-plane FrameTypeForwardRegister — see register().
			if n < 8+PunchNonceSize {
				p.logger.Warn("forward: invalid registration packet",
					"src", srcAP.String(), "len", n,
					"want_len", 8+PunchNonceSize)
				continue
			}
			myAlloc := binary.BigEndian.Uint32(buf[4:8])
			var nonce [PunchNonceSize]byte
			copy(nonce[:], buf[8:8+PunchNonceSize])
			p.register(myAlloc, srcAP, nonce)
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
// to now and reaps any expired pending / queued register state. Holds
// the write lock for the scan. Keeps byURI in sync.
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
			delete(p.pending, id)
			delete(p.queued, id)
			p.logger.Info("forward: allocation idle-timeout",
				"alloc_id", id, "uri", entry.uri, "src", entry.src.String(),
				"idle_s", int(now.Sub(time.Unix(0, entry.lastSeen.Load())).Seconds()))
		}
	}
	// pending / queued live independently of byAlloc — an agent that
	// arms a pending entry and then crashes before its alloc gets
	// Forget'd would otherwise leak the pending row until the next
	// ArmPending / register touched it. Sweep expired ones here.
	for id, pend := range p.pending {
		if now.After(pend.expires) {
			delete(p.pending, id)
			p.logger.Debug("forward: pending entry GC", "alloc_id", id, "uri", pend.uri)
		}
	}
	for id, q := range p.queued {
		if now.After(q.expires) {
			delete(p.queued, id)
			p.logger.Debug("forward: queued punch GC", "alloc_id", id, "src", q.src.String())
		}
	}
}

// register binds an existing allocation's UDP src endpoint, but only
// after verifying the punch's nonce matches the pending entry armed by
// the control plane (edge.handleForwardRegister → ArmPending). A
// register packet whose alloc has no pending entry, whose nonce
// disagrees, or whose pending entry has already expired is dropped.
//
// Under the URI-primary model, this is the wire-level enforcement of
// "the agent on the other end of the control mTLS connection is the
// only one who can claim this alloc's UDP src": the nonce never leaves
// that control stream in cleartext, so a spoofed punch cannot match
// without first compromising the mTLS channel.
func (p *Plane) register(allocID uint32, src netip.AddrPort, nonce [PunchNonceSize]byte) {
	now := time.Now().UnixNano()
	ttl := p.pendingTTL
	if ttl <= 0 {
		ttl = DefaultPendingTTL
	}
	p.mu.Lock()
	pend, hasPending := p.pending[allocID]
	if !hasPending {
		// Punch arrived before ArmPending — queue it briefly so
		// ArmPending can drain it on arrival (race between the agent's
		// back-to-back ctrl ForwardRegister + UDP punch). Same TTL as
		// pending; an unmatched punch is dropped on expiry.
		p.queued[allocID] = &queuedPunch{
			src:     src,
			nonce:   nonce,
			expires: time.Unix(0, now).Add(ttl),
		}
		p.mu.Unlock()
		p.logger.Debug("forward: queueing register (no pending entry yet)",
			"alloc_id", allocID, "src", src.String())
		return
	}
	if time.Now().After(pend.expires) {
		delete(p.pending, allocID)
		p.mu.Unlock()
		p.logger.Warn("forward: drop register (pending expired)",
			"alloc_id", allocID, "src", src.String())
		return
	}
	if pend.nonce != nonce {
		p.mu.Unlock()
		p.logger.Warn("forward: drop register (nonce mismatch)",
			"alloc_id", allocID, "src", src.String())
		return
	}
	entry, existed := p.byAlloc[allocID]
	if !existed {
		// The owning agent disconnected (ForgetAgent ran) between
		// ArmPending and the punch arriving. Clean up the stale pending
		// entry and drop.
		delete(p.pending, allocID)
		p.mu.Unlock()
		p.logger.Warn("forward: drop register (alloc forgotten before punch)",
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
	delete(p.pending, allocID)
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
