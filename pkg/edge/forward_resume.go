// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge

import (
	"sync"
	"time"

	"github.com/boanlab/OutRelay/lib/resume"
)

// ForwardResumeWindow is the matching window for FORWARD_RESUME: both
// halves of a resumed forward-mode stream must arrive within this
// window of each other. Mirrors resumeMatcher's ResumeWindow — same
// reasons (asymmetric reconnect detection on the two agents) apply.
const ForwardResumeWindow = 30 * time.Second

// halfForwardResume holds one side of a pending FORWARD_RESUME pair
// until the other side arrives or the window expires. Unlike
// halfStream, there is no transport.Stream to stitch — the matched
// pair feeds an allocation-grant write back on each agent's ctrl
// channel via its AgentConn.
type halfForwardResume struct {
	id resume.StreamID

	// agentURI is the URI of the agent that submitted this half. The
	// caller uses it to log which side already arrived; the splice
	// path it pairs with is identified by the (consumer, provider)
	// roles on the stream's existing pairs row when possible, but
	// FORWARD_RESUME does not require that row to still exist (relay
	// just restarted; pairs is empty).
	agentURI string

	// ac is the AgentConn whose ctrl stream the new AllocGranted
	// for this half will be written to.
	ac *AgentConn

	// myPos / peerAckPos are application-layer byte counters inside
	// the e2e QUIC tunnel — opaque to the relay. Carried through so
	// the peer's tunnel-internal STREAM_RESUME on the rebuilt direct
	// stream has them.
	myPos      uint64
	peerAckPos uint64

	arrivedAt time.Time
	matched   chan *halfForwardResume
}

// forwardMatcher pairs FORWARD_RESUME halves from two reconnecting
// agents by stream id. Same contract as resumeMatcher: Submit returns
// a channel that receives the peer half when (and if) it arrives, or
// closes after ForwardResumeWindow with no match.
//
// Once paired, the caller (handleForwardResume) is responsible for
// allocating two fresh forward-plane ids and writing AllocGranted to
// each AgentConn — the matcher itself does no allocation or wire I/O.
type forwardMatcher struct {
	mu      sync.Mutex
	pending map[resume.StreamID]*halfForwardResume
}

func newForwardMatcher() *forwardMatcher {
	return &forwardMatcher{pending: map[resume.StreamID]*halfForwardResume{}}
}

// Submit registers half. If a peer half is already waiting, both
// halves are paired: their matched channels each receive the other
// half and the entry is cleared. Otherwise self is parked until peer
// arrives or ForwardResumeWindow elapses (in which case matched is
// closed and the half is discarded).
func (m *forwardMatcher) Submit(self *halfForwardResume) <-chan *halfForwardResume {
	self.matched = make(chan *halfForwardResume, 1)
	self.arrivedAt = time.Now()

	m.mu.Lock()
	if peer, ok := m.pending[self.id]; ok {
		delete(m.pending, self.id)
		m.mu.Unlock()
		peer.matched <- self
		self.matched <- peer
		return self.matched
	}
	m.pending[self.id] = self
	m.mu.Unlock()

	go func() {
		t := time.NewTimer(ForwardResumeWindow)
		defer t.Stop()
		select {
		case <-self.matched:
			// already matched
		case <-t.C:
			m.mu.Lock()
			if cur, ok := m.pending[self.id]; ok && cur == self {
				delete(m.pending, self.id)
				m.mu.Unlock()
				close(self.matched)
				return
			}
			m.mu.Unlock()
		}
	}()
	return self.matched
}

// PendingCount is exposed for tests.
func (m *forwardMatcher) PendingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pending)
}
