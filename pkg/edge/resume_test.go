// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge

// resume matcher unit test — internal to pkg/edge so it can poke at
// the unexported types directly.

import (
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/resume"
)

func TestResumeMatcherPairsBothHalves(t *testing.T) {
	t.Parallel()
	m := newResumeMatcher()
	id := resume.StreamID(0xdeadbeef)

	a := &halfStream{id: id, myPos: 100, peerAckPos: 50}
	b := &halfStream{id: id, myPos: 50, peerAckPos: 100}

	chA := m.Submit(a)
	chB := m.Submit(b)

	gotA := waitMatch(t, chA, time.Second)
	gotB := waitMatch(t, chB, time.Second)
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

// TestResumeMatcherPendingUntilPeer verifies a lone half stays parked
// in the matcher until its peer arrives — the matched channel does
// not fire early.
func TestResumeMatcherPendingUntilPeer(t *testing.T) {
	t.Parallel()
	m := newResumeMatcher()
	id := resume.StreamID(1)
	a := &halfStream{id: id}
	chA := m.Submit(a)

	if got := m.PendingCount(); got != 1 {
		t.Fatalf("pending=%d, want 1", got)
	}

	b := &halfStream{id: id}
	_ = m.Submit(b)

	if waitMatch(t, chA, time.Second) != b {
		t.Fatal("a did not pair with b")
	}
}

// TestResumeMatcherClosesOnTimeout verifies the timeout path closes
// the matched channel without sending. The test waits longer than
// ResumeWindow, so it is skipped under -short.
func TestResumeMatcherClosesOnTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for ResumeWindow")
	}
	t.Parallel()
	m := newResumeMatcher()
	a := &halfStream{id: resume.StreamID(2)}
	ch := m.Submit(a)

	select {
	case got, ok := <-ch:
		if ok || got != nil {
			t.Fatalf("expected closed-without-send, got got=%v ok=%v", got, ok)
		}
	case <-time.After(ResumeWindow + time.Second):
		t.Fatal("timeout never fired")
	}
	if m.PendingCount() != 0 {
		t.Fatalf("pending=%d after expiry", m.PendingCount())
	}
}

func waitMatch(t *testing.T, ch <-chan *halfStream, d time.Duration) *halfStream {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(d):
		t.Fatal("match channel did not fire")
		return nil
	}
}

// TestResumeMatcherDesignatesOneSplicer — exactly one of the two
// matched halves must own the splice. Both handleResumeHalf
// goroutines wake up on match; if both ran splice.Bidirectional the
// pair would have two concurrent readers per stream and bytes would
// be reordered under load (seen as a checksum mismatch on the
// CloudStack drain run).
func TestResumeMatcherDesignatesOneSplicer(t *testing.T) {
	t.Parallel()
	m := newResumeMatcher()
	id := resume.StreamID(0xfeed)

	a := &halfStream{id: id}
	b := &halfStream{id: id}
	chA := m.Submit(a)
	chB := m.Submit(b)
	waitMatch(t, chA, time.Second)
	waitMatch(t, chB, time.Second)

	if a.splicer == b.splicer {
		t.Fatalf("splicer flags: a=%v b=%v, want exactly one true", a.splicer, b.splicer)
	}
}
