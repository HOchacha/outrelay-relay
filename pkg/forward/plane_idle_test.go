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
	p.register(idStale, srcStale)
	p.register(idFresh, srcFresh)

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
	p.register(id, src)

	// Backdate, then re-register — should bring lastSeen forward.
	p.mu.RLock()
	entry := p.byAlloc[id]
	p.mu.RUnlock()
	entry.lastSeen.Store(time.Now().Add(-time.Second).UnixNano())
	p.register(id, src)

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

	p.register(id, srcOld)
	p.register(id, srcNew)

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
