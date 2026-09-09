// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge

import (
	"sync"
	"time"

	"github.com/boanlab/OutRelay/lib/resume"
	"github.com/boanlab/OutRelay/lib/transport"
)

// ResumeWindow is the matching window for stream-resume: both halves
// of a resumed stream must arrive within ResumeWindow of each other.
// Sized to absorb asymmetric reconnect detection — one side may get
// an explicit ApplicationError while the other waits out an idle
// timeout, so the slower half can still hit the same matcher entry.
const ResumeWindow = 30 * time.Second

// halfStream holds one side of a pending STREAM_RESUME pair until the
// other side arrives or the window expires.
type halfStream struct {
	id         resume.StreamID
	stream     transport.Stream
	myPos      int64
	peerAckPos int64
	arrivedAt  time.Time
	matched    chan *halfStream
	// uri identifies the agent that sent this half, so the relay can
	// record the pair for control-frame forwarding after resume.
	uri string
	// splicer is set on exactly one half of a matched pair: the one
	// whose goroutine runs the splice. The other half's goroutine
	// just waits on done, which the splicer closes when the splice
	// ends, so its stream stays open for the whole splice.
	splicer bool
	done    chan struct{}
}

// resumeMatcher pairs STREAM_RESUME halves from two reconnecting
// agents by stream id. Goroutine-safe; the relay's serveConn fans
// resume frames into Submit and waits on the returned channel.
type resumeMatcher struct {
	mu      sync.Mutex
	pending map[resume.StreamID]*halfStream
}

func newResumeMatcher() *resumeMatcher {
	return &resumeMatcher{pending: map[resume.StreamID]*halfStream{}}
}

// Submit registers half. If a peer half is already waiting, both halves
// are returned as a (self, peer) pair via their matched channels and
// the entry is cleared. Otherwise self is parked until peer arrives or
// ResumeWindow elapses (after which the half is discarded).
func (m *resumeMatcher) Submit(self *halfStream) <-chan *halfStream {
	self.matched = make(chan *halfStream, 1)
	self.arrivedAt = time.Now()

	m.mu.Lock()
	if peer, ok := m.pending[self.id]; ok {
		delete(m.pending, self.id)
		m.mu.Unlock()
		// The half that completes the pair owns the splice; the
		// parked one only waits for it to finish.
		self.splicer = true
		peer.splicer = false
		// Notify both halves of each other.
		peer.matched <- self
		self.matched <- peer
		return self.matched
	}
	self.done = make(chan struct{})
	m.pending[self.id] = self
	m.mu.Unlock()

	// Expire the half if no peer arrives in time.
	go func() {
		t := time.NewTimer(ResumeWindow)
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
func (m *resumeMatcher) PendingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pending)
}
