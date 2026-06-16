// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package forward

// Tests for the allocation idle-TTL GC loop.
//
// The plane reclaims allocation entries whose lastSeen timestamp is
// older than the configured idleTTL. lastSeen is bumped on register
// and on every forwarded packet from the sender's src. Eviction runs
// on a ticker driven by Run; gcOnce is exposed to tests so we can
// drive it deterministically.

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func newTestPlane(t *testing.T) *Plane {
	t.Helper()
	p, err := NewPlane("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("NewPlane: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// armAndRegister is a test helper that mirrors the control-plane +
// data-plane handshake the agent does for real: arm a pending entry
// with a fresh nonce, then call register with the matching nonce.
// Keeps the rest of the idle-TTL / src-rebind tests focused on
// post-register behaviour without the Phase 2 nonce mechanics
// cluttering every call site.
func armAndRegister(t *testing.T, p *Plane, id uint32, uri string, src netip.AddrPort) {
	t.Helper()
	var nonce [PunchNonceSize]byte
	// Vary the nonce per-call so re-arming doesn't accidentally reuse
	// a stale entry's bytes. Distinct alloc + src + monotonic salt is
	// enough — we're testing register, not the RNG.
	nonce[0] = byte(id)
	nonce[1] = byte(id >> 8)
	nonce[2] = byte(id >> 16)
	nonce[3] = byte(id >> 24)
	nonce[4] = byte(src.Port())
	nonce[5] = byte(src.Port() >> 8)
	nonce[15] = byte(time.Now().UnixNano())
	if err := p.ArmPending(id, uri, nonce); err != nil {
		t.Fatalf("ArmPending(%d, %q): %v", id, uri, err)
	}
	p.register(id, src, nonce)
}

// TestGCOnceEvictsIdleAllocs — entries older than idleTTL are removed
// from both allocs and src2id. Fresh entries are preserved.
func TestGCOnceEvictsIdleAllocs(t *testing.T) {
	t.Parallel()
	p := newTestPlane(t)
	p.idleTTL = 100 * time.Millisecond

	idStale := p.Allocate("outrelay://acme/agent/stale")
	idFresh := p.Allocate("outrelay://acme/agent/fresh")
	srcStale := netip.MustParseAddrPort("10.0.0.1:9001")
	srcFresh := netip.MustParseAddrPort("10.0.0.2:9002")
	armAndRegister(t, p, idStale, "outrelay://acme/agent/stale", srcStale)
	armAndRegister(t, p, idFresh, "outrelay://acme/agent/fresh", srcFresh)

	// Backdate the stale entry past the cutoff.
	p.mu.RLock()
	staleEntry := p.byAlloc[idStale]
	p.mu.RUnlock()
	staleEntry.lastSeen.Store(time.Now().Add(-time.Second).UnixNano())

	p.gcOnce(time.Now())

	if _, ok := p.Lookup(idStale); ok {
		t.Fatal("stale alloc should have been evicted")
	}
	if _, ok := p.Lookup(idFresh); !ok {
		t.Fatal("fresh alloc must survive gcOnce")
	}
	// src2id reverse index must also be cleared for the evicted entry.
	p.mu.RLock()
	_, staleRev := p.src2id[srcStale]
	_, freshRev := p.src2id[srcFresh]
	p.mu.RUnlock()
	if staleRev {
		t.Fatal("src2id reverse entry for evicted alloc should be gone")
	}
	if !freshRev {
		t.Fatal("src2id reverse entry for surviving alloc must be intact")
	}
}

// TestRegisterBumpsLastSeen — re-registration of the same alloc id
// updates lastSeen and prevents eviction.
func TestRegisterBumpsLastSeen(t *testing.T) {
	t.Parallel()
	p := newTestPlane(t)
	p.idleTTL = 100 * time.Millisecond

	id := p.Allocate("outrelay://acme/agent/aaa")
	src := netip.MustParseAddrPort("10.0.0.1:9001")
	armAndRegister(t, p, id, "outrelay://acme/agent/aaa", src)

	// Backdate, then re-register — should bring lastSeen forward.
	p.mu.RLock()
	entry := p.byAlloc[id]
	p.mu.RUnlock()
	entry.lastSeen.Store(time.Now().Add(-time.Second).UnixNano())
	armAndRegister(t, p, id, "outrelay://acme/agent/aaa", src)

	p.gcOnce(time.Now())
	if _, ok := p.Lookup(id); !ok {
		t.Fatal("alloc should survive after re-registration bumped lastSeen")
	}
}

// TestRegisterReclaimsSrc2idOnSrcChange — re-registering an alloc with
// a different src address removes the old src from the reverse index.
func TestRegisterReclaimsSrc2idOnSrcChange(t *testing.T) {
	t.Parallel()
	p := newTestPlane(t)

	id := p.Allocate("outrelay://acme/agent/aaa")
	srcOld := netip.MustParseAddrPort("10.0.0.1:9001")
	srcNew := netip.MustParseAddrPort("10.0.0.1:9002")

	armAndRegister(t, p, id, "outrelay://acme/agent/aaa", srcOld)
	armAndRegister(t, p, id, "outrelay://acme/agent/aaa", srcNew)

	p.mu.RLock()
	_, oldStillThere := p.src2id[srcOld]
	newID, newRegistered := p.src2id[srcNew]
	p.mu.RUnlock()

	if oldStillThere {
		t.Fatal("old src should be removed from src2id after reclaim")
	}
	if !newRegistered || newID != id {
		t.Fatalf("new src must map to id=%d, got id=%d ok=%v", id, newID, newRegistered)
	}
}

// TestArmPendingUnknownAlloc — ArmPending on an alloc that was never
// issued must surface ErrUnknownAlloc so edge.handleForwardRegister
// can map it to a ForwardRegisterReject{reason:"unknown_alloc"}.
func TestArmPendingUnknownAlloc(t *testing.T) {
	t.Parallel()
	p := newTestPlane(t)
	var nonce [PunchNonceSize]byte
	if err := p.ArmPending(0xDEAD, "outrelay://acme/agent/a", nonce); err == nil {
		t.Fatal("ArmPending on unknown alloc should fail")
	} else if !errors.Is(err, ErrUnknownAlloc) {
		t.Fatalf("got %v, want ErrUnknownAlloc", err)
	}
}

// TestArmPendingOwnerMismatch — ArmPending with a URI that doesn't
// match the alloc's owner must surface ErrOwnerMismatch. This is the
// wire-level enforcement of "the agent on the other end of the mTLS
// control connection is the only one who can claim this alloc".
func TestArmPendingOwnerMismatch(t *testing.T) {
	t.Parallel()
	p := newTestPlane(t)
	id := p.Allocate("outrelay://acme/agent/owner")
	var nonce [PunchNonceSize]byte
	err := p.ArmPending(id, "outrelay://acme/agent/imposter", nonce)
	if !errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("got %v, want ErrOwnerMismatch", err)
	}
	// And the alloc must still be empty — nothing was bound.
	if entry, ok := p.byAlloc[id]; ok && entry.src.IsValid() {
		t.Fatalf("alloc src bound on owner mismatch: %v", entry.src)
	}
}

// TestRegisterRejectsNonceMismatch — a punch whose nonce disagrees
// with the armed pending entry is dropped, leaving the alloc unbound.
func TestRegisterRejectsNonceMismatch(t *testing.T) {
	t.Parallel()
	p := newTestPlane(t)
	uri := "outrelay://acme/agent/a"
	id := p.Allocate(uri)
	armed := [PunchNonceSize]byte{0xAA}
	wrong := [PunchNonceSize]byte{0xBB}
	if err := p.ArmPending(id, uri, armed); err != nil {
		t.Fatalf("ArmPending: %v", err)
	}
	src := netip.MustParseAddrPort("10.0.0.1:9001")
	p.register(id, src, wrong)
	if got, ok := p.Lookup(id); ok && got == src {
		t.Fatal("alloc bound despite nonce mismatch")
	}
}

// TestRegisterDrainsQueuedPunch — when the UDP punch races ahead of
// the control-plane ArmPending, the punch is queued; the subsequent
// ArmPending must drain it and bind the src in one shot. This is the
// fast path the e2e test depends on.
func TestRegisterDrainsQueuedPunch(t *testing.T) {
	t.Parallel()
	p := newTestPlane(t)
	uri := "outrelay://acme/agent/a"
	id := p.Allocate(uri)
	nonce := [PunchNonceSize]byte{0xCD}
	src := netip.MustParseAddrPort("10.0.0.1:9001")

	// Punch arrives first — queued, alloc still unbound.
	p.register(id, src, nonce)
	if _, ok := p.Lookup(id); ok {
		// Lookup returns the src even when zero-valued — fine, but
		// the entry's src must not equal the punch's src yet.
		p.mu.RLock()
		bound := p.byAlloc[id].src
		p.mu.RUnlock()
		if bound == src {
			t.Fatal("alloc bound before ArmPending — queued path bypassed")
		}
	}

	// ArmPending arrives — should drain the queued punch and bind.
	if err := p.ArmPending(id, uri, nonce); err != nil {
		t.Fatalf("ArmPending: %v", err)
	}
	got, ok := p.Lookup(id)
	if !ok || got != src {
		t.Fatalf("Lookup after drain = (%v, %v), want (%v, true)", got, ok, src)
	}
}

// TestForgetReapsPendingAndQueued — Forget on a single alloc must
// also drop any pending / queued register state for that id, so the
// maps don't outlive the live byAlloc set.
func TestForgetReapsPendingAndQueued(t *testing.T) {
	t.Parallel()
	p := newTestPlane(t)
	uri := "outrelay://acme/agent/a"
	id := p.Allocate(uri)
	nonce := [PunchNonceSize]byte{0x11}

	// Path 1: pending armed but no punch yet → Forget should clear it.
	if err := p.ArmPending(id, uri, nonce); err != nil {
		t.Fatalf("ArmPending: %v", err)
	}
	p.mu.RLock()
	_, hadPending := p.pending[id]
	p.mu.RUnlock()
	if !hadPending {
		t.Fatal("ArmPending did not install pending entry")
	}
	p.Forget(id)
	p.mu.RLock()
	_, stillPending := p.pending[id]
	p.mu.RUnlock()
	if stillPending {
		t.Fatal("Forget left pending entry behind")
	}

	// Path 2: queued punch (punch arrived first) → Forget should clear it.
	id2 := p.Allocate(uri)
	p.register(id2, netip.MustParseAddrPort("10.0.0.1:9001"), nonce)
	p.mu.RLock()
	_, hadQueued := p.queued[id2]
	p.mu.RUnlock()
	if !hadQueued {
		t.Fatal("register did not queue punch")
	}
	p.Forget(id2)
	p.mu.RLock()
	_, stillQueued := p.queued[id2]
	p.mu.RUnlock()
	if stillQueued {
		t.Fatal("Forget left queued punch behind")
	}
}

// TestForgetAgentReapsPendingAndQueued — bulk teardown by URI drains
// pending / queued for every alloc the URI owned.
func TestForgetAgentReapsPendingAndQueued(t *testing.T) {
	t.Parallel()
	p := newTestPlane(t)
	uri := "outrelay://acme/agent/doomed"
	a := p.Allocate(uri)
	b := p.Allocate(uri)
	nonce := [PunchNonceSize]byte{0x22}
	if err := p.ArmPending(a, uri, nonce); err != nil {
		t.Fatalf("ArmPending a: %v", err)
	}
	p.register(b, netip.MustParseAddrPort("10.0.0.1:9001"), nonce)

	if got := p.ForgetAgent(uri); got != 2 {
		t.Fatalf("ForgetAgent released %d, want 2", got)
	}
	p.mu.RLock()
	_, stillPending := p.pending[a]
	_, stillQueued := p.queued[b]
	p.mu.RUnlock()
	if stillPending {
		t.Fatal("ForgetAgent left pending entry behind")
	}
	if stillQueued {
		t.Fatal("ForgetAgent left queued punch behind")
	}
}

// TestGCOnceReapsExpiredPendingAndQueued — pending / queued entries
// past their expiry are swept by the GC ticker even when no register
// or ArmPending call lazy-checks them.
func TestGCOnceReapsExpiredPendingAndQueued(t *testing.T) {
	t.Parallel()
	p := newTestPlane(t)
	p.idleTTL = time.Hour    // keep byAlloc out of this test
	p.pendingTTL = time.Hour // we'll backdate manually

	uri := "outrelay://acme/agent/a"
	a := p.Allocate(uri)
	b := p.Allocate(uri)
	nonce := [PunchNonceSize]byte{0x33}

	if err := p.ArmPending(a, uri, nonce); err != nil {
		t.Fatalf("ArmPending: %v", err)
	}
	p.register(b, netip.MustParseAddrPort("10.0.0.1:9001"), nonce)

	// Backdate both into the past so gcOnce treats them as expired.
	p.mu.Lock()
	p.pending[a].expires = time.Now().Add(-time.Second)
	p.queued[b].expires = time.Now().Add(-time.Second)
	p.mu.Unlock()

	p.gcOnce(time.Now())

	p.mu.RLock()
	_, stillPending := p.pending[a]
	_, stillQueued := p.queued[b]
	p.mu.RUnlock()
	if stillPending {
		t.Fatal("gcOnce did not reap expired pending entry")
	}
	if stillQueued {
		t.Fatal("gcOnce did not reap expired queued punch")
	}
	// The underlying allocs themselves must survive — only the
	// arm/queue rows were due for eviction.
	if _, ok := p.OwnerOf(a); !ok {
		t.Fatal("gcOnce wrongly evicted a live alloc")
	}
	if _, ok := p.OwnerOf(b); !ok {
		t.Fatal("gcOnce wrongly evicted a live alloc")
	}
}

// allocEntryAtomicSanity is a sanity check that the in-place
// atomic.Int64 on allocEntry is safe under the access pattern used by
// gcOnce + register (concurrent Store + Load).
func TestAllocEntryAtomicSanity(t *testing.T) {
	t.Parallel()
	e := &allocEntry{}
	var v atomic.Int64
	v.Store(42)
	e.lastSeen.Store(v.Load())
	if e.lastSeen.Load() != 42 {
		t.Fatalf("atomic int64 round-trip failed: got %d", e.lastSeen.Load())
	}
}
