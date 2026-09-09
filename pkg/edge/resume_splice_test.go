// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/resume"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-relay/pkg/edge"
	"github.com/boanlab/outrelay-relay/pkg/registry"
)

// resumedPair stands up one relay, connects two raw "agents" and drives
// both through STREAM_RESUME for the same stream id until the relay has
// echoed each side's positions. What comes back is a spliced pair plus
// the two control streams — the state an agent is in right after a
// successful relocation.
type resumedPair struct {
	id             resume.StreamID
	connA, connB   transport.Conn
	streamA, ctrlA transport.Stream
	streamB, ctrlB transport.Stream
}

func newResumedPair(t *testing.T) *resumedPair {
	t.Helper()

	ca, _ := pki.NewCA()
	relayName, _ := identity.NewRelay("acme", "relay-r")
	a, _ := identity.NewAgent("acme")
	b, _ := identity.NewAgent("acme")

	tlsServer := &tls.Config{
		Certificates: []tls.Certificate{*issueCert(t, ca, relayName)},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := transport.ListenQUIC("127.0.0.1:0", tlsServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctrl := startInProcessController(t)
	reg := registry.New(ctrl, "relay-r", "", nil)
	srv := edge.New(ln.Addr().String(), nil, reg, nil, nil, nil, nil, nil, nil, slog.New(slog.DiscardHandler))
	srvCtx, srvCancel := context.WithCancel(t.Context())
	t.Cleanup(srvCancel)
	go func() { _ = srv.RunListener(srvCtx, ln) }()

	dial := func(name identity.Name) (transport.Conn, transport.Stream) {
		conn, err := transport.DialQUIC(t.Context(), ln.Addr().String(), clientTLS(issueCert(t, ca, name), ca), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn, mustHandshake(t, conn, name)
	}
	connA, ctrlA := dial(a)
	connB, ctrlB := dial(b)

	id := resume.NewStreamID("acme", a.String(), b.String())
	open := func(conn transport.Conn) transport.Stream {
		st, err := conn.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() })
		if err := orp.WriteFrame(st, orp.FrameTypeStreamResume, &orpv1.StreamResume{StreamId: uint64(id)}); err != nil {
			t.Fatal(err)
		}
		return st
	}
	streamA := open(connA)
	streamB := open(connB)
	for _, st := range []transport.Stream{streamA, streamB} {
		f, err := orp.ParseFrame(st)
		if err != nil {
			t.Fatalf("read resume echo: %v", err)
		}
		if f.Type != orp.FrameTypeStreamResume {
			t.Fatalf("expected STREAM_RESUME echo, got %v", f.Type)
		}
	}
	return &resumedPair{id: id, connA: connA, connB: connB, streamA: streamA, ctrlA: ctrlA, streamB: streamB, ctrlB: ctrlB}
}

// TestResumeSplicePreservesByteOrderUnderLoad —
//
// A multi-megabyte payload pushed through a resumed pair in both
// directions at once must arrive byte-for-byte in order. The
// one-liner payloads in TestResumePairsBothHalvesAndSplices cannot
// tell a single splice from two concurrent ones competing for the
// same streams; the CloudStack drain run (64 MB, checksum mismatch)
// did.
func TestResumeSplicePreservesByteOrderUnderLoad(t *testing.T) {
	t.Parallel()
	p := newResumedPair(t)

	const total = 32 << 20
	const chunk = 4096
	payload := func(seed int64) []byte {
		buf := make([]byte, total)
		rand.New(rand.NewSource(seed)).Read(buf) // #nosec G404 -- test data
		return buf
	}
	aToB, bToA := payload(1), payload(2)

	pump := func(name string, dst, src transport.Stream, want []byte, wg *sync.WaitGroup) {
		defer wg.Done()
		go func() {
			for off := 0; off < len(want); off += chunk {
				if _, err := src.Write(want[off : off+chunk]); err != nil {
					t.Errorf("%s: write: %v", name, err)
					return
				}
			}
		}()
		got := make([]byte, len(want))
		if err := readDeadline(dst, got, 20*time.Second); err != nil {
			t.Errorf("%s: read: %v", name, err)
			return
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: payload corrupted: first divergence at %d (sha got %x want %x)",
				name, firstDiff(got, want), sha256.Sum256(got), sha256.Sum256(want))
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go pump("A->B", p.streamB, p.streamA, aToB, &wg)
	go pump("B->A", p.streamA, p.streamB, bToA, &wg)
	wg.Wait()
}

// TestResumeForwardsCheckpointsAfterMatch —
//
// Once a pair is re-spliced via STREAM_RESUME the relay must keep
// forwarding STREAM_CHECKPOINT between the two agents' control
// streams, exactly as it does for a pair created by OPEN_STREAM.
// Without it the peer's ring buffer is never acked after relocation
// and the stream silently stops being resumable a second time.
func TestResumeForwardsCheckpointsAfterMatch(t *testing.T) {
	t.Parallel()
	p := newResumedPair(t)

	want := &orpv1.StreamCheckpoint{StreamId: uint64(p.id), MyPosition: 4096, PeerAckPosition: 2048}
	if err := orp.WriteFrame(p.ctrlA, orp.FrameTypeStreamCheckpoint, want); err != nil {
		t.Fatal(err)
	}

	type result struct {
		f   *orp.Frame
		err error
	}
	done := make(chan result, 1)
	go func() {
		f, err := orp.ParseFrame(p.ctrlB)
		done <- result{f, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		got := &orpv1.StreamCheckpoint{}
		if err := orp.UnmarshalProto(r.f, orp.FrameTypeStreamCheckpoint, got); err != nil {
			t.Fatalf("expected STREAM_CHECKPOINT on B ctrl, got %v: %v", r.f.Type, err)
		}
		if got.StreamId != want.StreamId || got.MyPosition != want.MyPosition || got.PeerAckPosition != want.PeerAckPosition {
			t.Fatalf("checkpoint mismatch: got %+v want %+v", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("STREAM_CHECKPOINT was not forwarded to the peer after resume")
	}
}

func firstDiff(a, b []byte) int {
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			return i
		}
	}
	return -1
}

// TestPeerLossAfterResumeIsNotEOF —
//
// After a resumed pair is spliced, losing one agent's connection
// must surface on the other agent's stream as a transport error, not
// as io.EOF: EOF is what the agent bridge treats as "application is
// done", and it would tear the app connection down instead of
// parking for the next STREAM_RESUME.
func TestPeerLossAfterResumeIsNotEOF(t *testing.T) {
	t.Parallel()
	p := newResumedPair(t)

	// Prove the splice is live, then drop A's whole connection.
	go func() { _, _ = p.streamA.Write([]byte("x")) }()
	if err := readDeadline(p.streamB, make([]byte, 1), 3*time.Second); err != nil {
		t.Fatal(err)
	}
	_ = p.connA.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := p.streamB.Read(make([]byte, 1))
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("survivor read returned %v; want a stream reset, not EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("survivor read did not return after peer loss")
	}
}
