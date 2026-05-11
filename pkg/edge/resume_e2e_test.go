// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge_test

import (
	"context"
	"crypto/tls"
	"log/slog"
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

// TestResumePairsBothHalvesAndSplices —
//
// One relay accepts two fresh QUIC connections, each carrying a
// STREAM_RESUME frame for the same stream id. The relay's matcher
// pairs the halves and splices them. Bytes flow across the spliced
// pair just as they would after a real failover.
//
// This test does not exercise the full agent-side reconnect loop —
// the focus is the relay's STREAM_RESUME dispatch path. The agent's
// Session.Resume API is exercised by lib/resume's State + this
// relay-side splice together.
func TestResumePairsBothHalvesAndSplices(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()
	relayName, _ := identity.NewRelay("acme", "relay-r")
	a, _ := identity.NewAgent("acme")
	b, _ := identity.NewAgent("acme")

	relayCert := issueCert(t, ca, relayName)
	aCert := issueCert(t, ca, a)
	bCert := issueCert(t, ca, b)

	tlsServer := &tls.Config{
		Certificates: []tls.Certificate{*relayCert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := transport.ListenQUIC("127.0.0.1:0", tlsServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctrl := startInProcessController(t)
	reg := registry.New(ctrl, "relay-r", "", nil)
	srv := edge.New(ln.Addr().String(), nil, reg, nil, nil, nil, nil, nil, nil, slog.New(slog.DiscardHandler))
	srvCtx, srvCancel := context.WithCancel(t.Context())
	defer srvCancel()
	go func() { _ = srv.RunListener(srvCtx, ln) }()

	addr := ln.Addr().String()

	// Both "agents" dial, perform HELLO, then open a fresh stream
	// carrying STREAM_RESUME with a matching stream_id.
	id := resume.NewStreamID("acme", a.String(), b.String())

	connA, err := transport.DialQUIC(t.Context(), addr, clientTLS(aCert, ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connA.Close()
	_ = mustHandshake(t, connA, a)

	connB, err := transport.DialQUIC(t.Context(), addr, clientTLS(bCert, ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connB.Close()
	_ = mustHandshake(t, connB, b)

	streamA, err := connA.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer streamA.Close()
	const aSent uint64 = 100
	const aPeerAck uint64 = 50
	const bSent uint64 = 80
	const bPeerAck uint64 = 70
	if err := orp.WriteFrame(streamA, orp.FrameTypeStreamResume, &orpv1.StreamResume{
		StreamId:        uint64(id),
		MyPosition:      aSent,
		PeerAckPosition: aPeerAck,
	}); err != nil {
		t.Fatal(err)
	}

	streamB, err := connB.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer streamB.Close()
	if err := orp.WriteFrame(streamB, orp.FrameTypeStreamResume, &orpv1.StreamResume{
		StreamId:        uint64(id),
		MyPosition:      bSent,
		PeerAckPosition: bPeerAck,
	}); err != nil {
		t.Fatal(err)
	}

	// After matching, the relay echoes the peer's STREAM_RESUME payload
	// onto each side's stream so the local agent learns peer positions
	// and can drive retransmit.
	echoA := &orpv1.StreamResume{}
	if echoF, err := orp.ParseFrame(streamA); err != nil {
		t.Fatalf("read echo on A: %v", err)
	} else if err := orp.UnmarshalProto(echoF, orp.FrameTypeStreamResume, echoA); err != nil {
		t.Fatal(err)
	}
	if echoA.StreamId != uint64(id) || echoA.MyPosition != bSent || echoA.PeerAckPosition != bPeerAck {
		t.Fatalf("A echo mismatch: %+v", echoA)
	}
	echoB := &orpv1.StreamResume{}
	if echoF, err := orp.ParseFrame(streamB); err != nil {
		t.Fatalf("read echo on B: %v", err)
	} else if err := orp.UnmarshalProto(echoF, orp.FrameTypeStreamResume, echoB); err != nil {
		t.Fatal(err)
	}
	if echoB.StreamId != uint64(id) || echoB.MyPosition != aSent || echoB.PeerAckPosition != aPeerAck {
		t.Fatalf("B echo mismatch: %+v", echoB)
	}

	// After echoes, splice connects the two streams. Whatever A
	// writes appears at B and vice versa.
	want := []byte("post-resume")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := streamA.Write(want); err != nil {
			t.Errorf("write A: %v", err)
		}
	}()

	got := make([]byte, len(want))
	if err := readDeadline(streamB, got, 3*time.Second); err != nil {
		t.Fatalf("read B: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}

	// Reverse direction works too.
	go func() {
		_, _ = streamB.Write([]byte("pong-back"))
	}()
	got2 := make([]byte, len("pong-back"))
	if err := readDeadline(streamA, got2, 3*time.Second); err != nil {
		t.Fatalf("read A: %v", err)
	}
	if string(got2) != "pong-back" {
		t.Fatalf("reverse got %q", got2)
	}

	wg.Wait()
}
