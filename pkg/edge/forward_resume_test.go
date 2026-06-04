// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge

// forwardMatcher unit tests — internal to pkg/edge so they can poke
// at the unexported types directly. Mirrors resume_test.go structure
// because forwardMatcher mirrors resumeMatcher's contract.

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/resume"

	"github.com/boanlab/outrelay-relay/pkg/forward"
)

// TestForwardMatcherPairsSecondArrivalDrives — when both halves
// submit, only the 2nd arrival receives the peer (it drives the
// allocation grant). The 1st arrival's channel is closed without a
// value so its handler can bail as non-driver. timedOut stays false
// on the 1st arrival so it doesn't mistakenly bump the timeout
// counter.
func TestForwardMatcherPairsSecondArrivalDrives(t *testing.T) {
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

	// b is the 2nd arrival → drives, receives a as its peer.
	gotB := waitMatchForward(t, chB, time.Second)
	if gotB != a {
		t.Fatalf("b paired with %v, want a", gotB)
	}

	// a is the 1st arrival → channel closes without value.
	select {
	case got, ok := <-chA:
		if ok || got != nil {
			t.Fatalf("a expected closed-without-send (non-driver), got got=%v ok=%v", got, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("a's channel never resolved")
	}
	if a.timedOut {
		t.Fatal("a.timedOut set; non-driver path must not mark timeout")
	}
	if m.PendingCount() != 0 {
		t.Fatalf("pending=%d, want 0", m.PendingCount())
	}
}

// TestForwardMatcherPendingUntilPeer — a lone half parks; the matched
// channel must not fire until the peer arrives. When the peer does
// arrive, the lone half is the 1st arrival and its channel closes
// without value (the peer drives).
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
	chB := m.Submit(b)

	// b drives — peer is a.
	if got := waitMatchForward(t, chB, time.Second); got != a {
		t.Fatalf("b paired with %v, want a", got)
	}
	// a's channel is closed without value (it's non-driver).
	select {
	case got, ok := <-chA:
		if ok || got != nil {
			t.Fatalf("a non-driver path: got got=%v ok=%v", got, ok)
		}
	case <-time.After(time.Second):
		t.Fatal("a's channel never closed after peer arrived")
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

// fakeCtrlStream wraps a net.Conn so it satisfies transport.Stream.
// Used to mock AgentConn.ctrl in handleForwardResume tests so we can
// verify the AllocGranted bytes the handler writes back without
// spinning up real QUIC.
type fakeCtrlStream struct {
	net.Conn
}

func (s *fakeCtrlStream) StreamID() uint64  { return 0 }
func (s *fakeCtrlStream) CancelRead(uint64) {}

// TestHandleForwardResumePairsAndGrantsBoth — end-to-end through the
// edge.Server orchestration: two agents submit FORWARD_RESUME for the
// same stream id, handleForwardResume drives the matcher pair off the
// goroutine path, allocates two fresh plane ids, and writes an
// AllocGranted to each AgentConn's ctrl stream with the alloc ids
// swapped for each side. Locks in the wire shape Stage 6+7+8 on the
// agent depend on.
func TestHandleForwardResumePairsAndGrantsBoth(t *testing.T) {
	t.Parallel()

	plane, err := forward.NewPlane("127.0.0.1:0", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewPlane: %v", err)
	}
	defer func() { _ = plane.Close() }()
	planeCtx, planeCancel := context.WithCancel(t.Context())
	defer planeCancel()
	go func() { _ = plane.Run(planeCtx) }()

	srv := New("", nil, nil, nil, nil, nil, nil, plane, nil, slog.New(slog.DiscardHandler))

	// Build two AgentConn pairs, each with a pipe-backed ctrl stream
	// so the test side can read whatever WriteCtrl emits.
	mkPair := func(uri string) (*AgentConn, net.Conn) {
		serverEnd, testEnd := net.Pipe()
		ac := &AgentConn{uri: uri, ctrl: &fakeCtrlStream{Conn: serverEnd}}
		return ac, testEnd
	}
	aAC, aRead := mkPair("outrelay://acme/agent/aaa")
	bAC, bRead := mkPair("outrelay://acme/agent/bbb")
	defer func() { _ = aRead.Close() }()
	defer func() { _ = bRead.Close() }()

	streamID := uint64(0xcafef00d)
	frame := func(stream uint64, myPos, peerAck uint64) *orp.Frame {
		f, ferr := orp.MarshalProto(orp.FrameTypeForwardResume, &orpv1.ForwardResume{
			StreamId:        stream,
			MyPosition:      myPos,
			PeerAckPosition: peerAck,
		})
		if ferr != nil {
			t.Fatalf("marshal: %v", ferr)
		}
		return f
	}

	srv.handleForwardResume(aAC, frame(streamID, 16768, 16768))
	srv.handleForwardResume(bAC, frame(streamID, 16768, 16768))

	// Each side should observe an AllocGranted with the same stream id.
	readGranted := func(t *testing.T, r net.Conn) *orpv1.AllocGranted {
		t.Helper()
		_ = r.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, ferr := orp.ParseFrame(r)
		if ferr != nil {
			t.Fatalf("ParseFrame: %v", ferr)
		}
		if f.Type != orp.FrameTypeAllocGranted {
			t.Fatalf("frame type: got %v want AllocGranted", f.Type)
		}
		g := &orpv1.AllocGranted{}
		if uerr := orp.UnmarshalProto(f, orp.FrameTypeAllocGranted, g); uerr != nil {
			t.Fatalf("unmarshal: %v", uerr)
		}
		return g
	}

	aGranted := readGranted(t, aRead)
	bGranted := readGranted(t, bRead)

	if aGranted.StreamId != streamID || bGranted.StreamId != streamID {
		t.Fatalf("stream_id mismatch: a=%d b=%d want=%d",
			aGranted.StreamId, bGranted.StreamId, streamID)
	}
	if aGranted.MyAllocation == 0 || bGranted.MyAllocation == 0 {
		t.Fatalf("alloc 0 not allowed: a=%d b=%d",
			aGranted.MyAllocation, bGranted.MyAllocation)
	}
	if aGranted.MyAllocation == bGranted.MyAllocation {
		t.Fatalf("both sides got same MyAllocation %d", aGranted.MyAllocation)
	}
	// Each side's "my" is the other side's "peer".
	if aGranted.MyAllocation != bGranted.PeerAllocation {
		t.Fatalf("a.my=%d != b.peer=%d", aGranted.MyAllocation, bGranted.PeerAllocation)
	}
	if bGranted.MyAllocation != aGranted.PeerAllocation {
		t.Fatalf("b.my=%d != a.peer=%d", bGranted.MyAllocation, aGranted.PeerAllocation)
	}
	if aGranted.ForwardEndpoint == "" || bGranted.ForwardEndpoint == "" {
		t.Fatalf("forward endpoint empty: a=%q b=%q",
			aGranted.ForwardEndpoint, bGranted.ForwardEndpoint)
	}
}
