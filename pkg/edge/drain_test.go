// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge_test

import (
	"context"
	"crypto/tls"
	"log/slog"
	"slices"
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

// TestDrainSendsGoawayThenCloses —
//
// Relay-side initiation of a planned relocation. Drain must deliver
// one GOAWAY (with the given targets, reason, deadline) on every
// connected agent's ctrl, then — once the deadline passes — close
// links that are still up so a stuck agent falls back to the crash
// path rather than pinning the relay open.
func TestDrainSendsGoawayThenCloses(t *testing.T) {
	t.Parallel()

	targets := []string{"10.0.0.2:7443"}
	ca, _ := pki.NewCA()
	relayName, _ := identity.NewRelay("acme", "relay-r1")
	relayCert := issueCert(t, ca, relayName)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{*relayCert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := transport.ListenQUIC("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctrl := startInProcessController(t)
	reg := registry.New(ctrl, "relay-r1", "", nil)
	srv := edge.New(ln.Addr().String(), nil, reg, nil, nil, nil, nil, nil, nil, slog.New(slog.DiscardHandler))
	relayCtx, cancelRelay := context.WithCancel(t.Context())
	defer cancelRelay()
	go func() { _ = srv.RunListener(relayCtx, ln) }()

	// Two agents connected, neither will react to GOAWAY (they are
	// hand-rolled), so the deadline path is what closes them.
	type link struct {
		conn transport.Conn
		ctrl transport.Stream
	}
	var links []link
	for i := 0; i < 2; i++ {
		name, _ := identity.NewAgent("acme")
		conn, err := transport.DialQUIC(t.Context(), ln.Addr().String(), clientTLS(issueCert(t, ca, name), ca), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		links = append(links, link{conn: conn, ctrl: mustHandshake(t, conn, name)})
	}

	const deadline = 300 * time.Millisecond
	start := time.Now()
	drained := make(chan struct{})
	go func() {
		srv.Drain(t.Context(), targets, "drain", deadline)
		close(drained)
	}()

	for i, l := range links {
		f, err := orp.ParseFrame(l.ctrl)
		if err != nil {
			t.Fatalf("agent %d: read GOAWAY: %v", i, err)
		}
		g := &orpv1.Goaway{}
		if err := orp.UnmarshalProto(f, orp.FrameTypeGoaway, g); err != nil {
			t.Fatalf("agent %d: %v", i, err)
		}
		if !slices.Equal(g.TargetEndpoints, targets) || g.Reason != "drain" ||
			time.Duration(g.DeadlineMs)*time.Millisecond != deadline || len(g.StreamIds) != 0 {
			t.Fatalf("agent %d: GOAWAY = %+v", i, g)
		}
	}
	// GOAWAY must arrive well before the deadline, not at it.
	if since := time.Since(start); since > deadline/2 {
		t.Fatalf("GOAWAY delivered late: %v", since)
	}

	select {
	case <-drained:
	case <-time.After(deadline + 2*time.Second):
		t.Fatal("Drain did not return after deadline")
	}
	for i, l := range links {
		acceptCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		_, err := l.conn.AcceptStream(acceptCtx)
		timedOut := acceptCtx.Err() != nil
		cancel()
		if err == nil || timedOut {
			t.Fatalf("agent %d: link still open after drain deadline (err=%v)", i, err)
		}
	}
}

// TestDrainDefaultsToSuccessors: with no explicit targets, Drain hands
// out the successor list the relay already advertises.
func TestDrainDefaultsToSuccessors(t *testing.T) {
	t.Parallel()

	successors := []string{"10.0.0.5:7443", "10.0.0.6:7443"}
	ca, _ := pki.NewCA()
	relayName, _ := identity.NewRelay("acme", "relay-r1")
	relayCert := issueCert(t, ca, relayName)
	ln, err := transport.ListenQUIC("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*relayCert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctrl := startInProcessController(t)
	srv := edge.New(ln.Addr().String(), nil, registry.New(ctrl, "relay-r1", "", nil), nil, nil, nil, nil, nil, nil, slog.New(slog.DiscardHandler))
	srv.SetSuccessors(successors)
	relayCtx, cancelRelay := context.WithCancel(t.Context())
	defer cancelRelay()
	go func() { _ = srv.RunListener(relayCtx, ln) }()

	name, _ := identity.NewAgent("acme")
	conn, err := transport.DialQUIC(t.Context(), ln.Addr().String(), clientTLS(issueCert(t, ca, name), ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	agentCtrl := mustHandshake(t, conn, name)

	go srv.Drain(t.Context(), nil, "upgrade", 100*time.Millisecond)
	f, err := orp.ParseFrame(agentCtrl)
	if err != nil {
		t.Fatal(err)
	}
	g := &orpv1.Goaway{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeGoaway, g); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(g.TargetEndpoints, successors) || g.Reason != "upgrade" {
		t.Fatalf("GOAWAY = %+v, want targets %v", g, successors)
	}
}
