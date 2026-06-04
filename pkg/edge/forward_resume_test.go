// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge

// forwardMatcher unit tests — internal to pkg/edge so they can poke
// at the unexported types directly. Mirrors resume_test.go structure
// because forwardMatcher mirrors resumeMatcher's contract.

import (
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/resume"
)

func TestForwardMatcherPairsBothHalves(t *testing.T) {
	t.Parallel()
	m := newForwardMatcher()
	id := resume.StreamID(0xcafef00d)

	a := &halfForwardResume{
		id: id, agentURI: "outrelay://acme/agent/aaa",
		myPos: 16768, peerAckPos: 16768,
	}
	b := &halfForwardResume{
		id: id, agentURI: "outrelay://acme/agent/bbb",
		myPos: 16768, peerAckPos: 16768,
	}

	chA := m.Submit(a)
	chB := m.Submit(b)

	gotA := waitMatchForward(t, chA, time.Second)
	gotB := waitMatchForward(t, chB, time.Second)
	if gotA != b {
		t.Fatalf("a paired with %v, want b", gotA)
	}
	if gotB != a {
		t.Fatalf("b paired with %v, want a", gotB)
	}
	if m.PendingCount() != 0 {
		t.Fatalf("pending=%d, want 0", m.PendingCount())
	}
}

// TestForwardMatcherPendingUntilPeer — a lone half parks; the matched
// channel must not fire until the peer arrives.
func TestForwardMatcherPendingUntilPeer(t *testing.T) {
	t.Parallel()
	m := newForwardMatcher()
	id := resume.StreamID(1)
	a := &halfForwardResume{id: id, agentURI: "a"}
	chA := m.Submit(a)

	if got := m.PendingCount(); got != 1 {
		t.Fatalf("pending=%d, want 1", got)
	}

	b := &halfForwardResume{id: id, agentURI: "b"}
	_ = m.Submit(b)

	if waitMatchForward(t, chA, time.Second) != b {
		t.Fatal("a did not pair with b")
	}
}

// TestForwardMatcherClosesOnTimeout — the timeout path closes the
// matched channel without sending. Long-running; -short skips.
func TestForwardMatcherClosesOnTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for ForwardResumeWindow")
	}
	t.Parallel()
	m := newForwardMatcher()
	a := &halfForwardResume{id: resume.StreamID(2), agentURI: "lone"}
	ch := m.Submit(a)

	select {
	case got, ok := <-ch:
		if ok || got != nil {
			t.Fatalf("expected closed-without-send, got got=%v ok=%v", got, ok)
		}
	case <-time.After(ForwardResumeWindow + time.Second):
		t.Fatal("timeout never fired")
	}
	if m.PendingCount() != 0 {
		t.Fatalf("pending=%d after expiry", m.PendingCount())
	}
}

// TestForwardMatcherIndependentStreamIDs — submissions on different
// stream ids must not cross-pair.
func TestForwardMatcherIndependentStreamIDs(t *testing.T) {
	t.Parallel()
	m := newForwardMatcher()
	a := &halfForwardResume{id: resume.StreamID(10), agentURI: "a"}
	b := &halfForwardResume{id: resume.StreamID(20), agentURI: "b"}

	chA := m.Submit(a)
	chB := m.Submit(b)

	// Neither should pair — they don't share an id.
	select {
	case got := <-chA:
		t.Fatalf("a unexpectedly paired with %+v", got)
	case got := <-chB:
		t.Fatalf("b unexpectedly paired with %+v", got)
	case <-time.After(100 * time.Millisecond):
		// expected
	}
	if got := m.PendingCount(); got != 2 {
		t.Fatalf("pending=%d, want 2", got)
	}
}

func waitMatchForward(t *testing.T, ch <-chan *halfForwardResume, d time.Duration) *halfForwardResume {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(d):
		t.Fatal("match channel did not fire")
		return nil
	}
}
