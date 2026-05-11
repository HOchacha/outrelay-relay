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
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-relay/pkg/edge"
	"github.com/boanlab/outrelay-relay/pkg/registry"
)

// TestMigrateToRelayPairsBothHalves —
//
// Two agents send MIGRATE_TO_RELAY on fresh streams with a matching
// stream id; the relay re-uses the resumeMatcher to pair them and
// splice begins. Bytes flow afterwards just like a fresh stream —
// this is the demotion-from-P2P fast path.
//
// MIGRATE_TO_P2P metadata seeding is exercised by the internal
// migrate_test.go; here we verify the end-to-end pairing and splice
// work even without prior LRU state.
func TestMigrateToRelayPairsBothHalves(t *testing.T) {
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
	const streamID uint64 = 0xc0ffee

	connA, _ := transport.DialQUIC(t.Context(), addr, clientTLS(aCert, ca), nil)
	defer connA.Close()
	_ = mustHandshake(t, connA, a)
	connB, _ := transport.DialQUIC(t.Context(), addr, clientTLS(bCert, ca), nil)
	defer connB.Close()
	_ = mustHandshake(t, connB, b)

	streamA, _ := connA.OpenStream(t.Context())
	defer streamA.Close()
	if err := orp.WriteFrame(streamA, orp.FrameTypeMigrateToRelay, &orpv1.MigrateToRelay{
		StreamId:        streamID,
		MyPosition:      100,
		PeerAckPosition: 80,
		Reason:          "rtt_timeout",
	}); err != nil {
		t.Fatal(err)
	}
	streamB, _ := connB.OpenStream(t.Context())
	defer streamB.Close()
	if err := orp.WriteFrame(streamB, orp.FrameTypeMigrateToRelay, &orpv1.MigrateToRelay{
		StreamId:        streamID,
		MyPosition:      80,
		PeerAckPosition: 100,
		Reason:          "rtt_timeout",
	}); err != nil {
		t.Fatal(err)
	}

	// After matching, splice connects the two streams.
	want := []byte("post-demote")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = streamA.Write(want)
	}()
	got := make([]byte, len(want))
	if err := readDeadline(streamB, got, 3*time.Second); err != nil {
		t.Fatalf("read after demote: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
	wg.Wait()
}
