// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge_test

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"testing"
	"time"

	pbcontrol "github.com/boanlab/OutRelay/lib/control/v1"
	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-relay/pkg/edge"
	"github.com/boanlab/outrelay-relay/pkg/registry"
)

// TestCandidateForwardRoundTrip —
//
// Two agents (provider P + consumer C) register and open a stream.
// C sends CANDIDATE_OFFER on its control stream; relay routes the
// frame to P's control stream by stream_id. P sends CANDIDATE_ANSWER
// back; relay routes to C. Both directions complete the round-trip.
//
// Scope is the relay's control-frame routing only — the agents'
// connectivity checks and MIGRATE_TO_P2P promotion are exercised
// elsewhere.
func TestCandidateForwardRoundTrip(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()
	ctrlClient := startInProcessController(t)
	relayName, _ := identity.NewRelay("acme", "relay-r")
	provName, _ := identity.NewAgent("acme")
	consName, _ := identity.NewAgent("acme")
	relayCert := issueCert(t, ca, relayName)
	provCert := issueCert(t, ca, provName)
	consCert := issueCert(t, ca, consName)

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

	reg := registry.New(ctrlClient, "relay-r", "", nil)
	srv := edge.New(ln.Addr().String(), nil, reg, nil, nil, nil, nil, nil, nil, slog.New(slog.DiscardHandler))
	srvCtx, srvCancel := context.WithCancel(t.Context())
	defer srvCancel()
	go func() { _ = srv.RunListener(srvCtx, ln) }()

	addr := ln.Addr().String()

	// Provider connects, registers svc-echo, and serves an echo backend.
	provConn, err := transport.DialQUIC(t.Context(), addr, clientTLS(provCert, ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer provConn.Close()
	provCtrl := mustHandshake(t, provConn, provName)
	mustRegister(t, provCtrl, "svc-echo")

	echoLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echoLn.Close()
	go runEchoServer(echoLn)

	provCtx, provCancel := context.WithCancel(t.Context())
	defer provCancel()
	go runProvider(provCtx, provConn, echoLn.Addr().String())

	// Wait for the controller to record svc-echo.
	if !waitFor(time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		resp, err := ctrlClient.Resolve(ctx, &pbcontrol.ResolveRequest{
			Tenant: "acme", ServiceName: "svc-echo",
		})
		return err == nil && len(resp.Providers) > 0
	}) {
		t.Fatal("svc-echo never registered")
	}

	// Consumer connects and opens a stream so the relay records the
	// pair in s.pairs.
	consConn, err := transport.DialQUIC(t.Context(), addr, clientTLS(consCert, ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer consConn.Close()
	consCtrl := mustHandshake(t, consConn, consName)

	const streamID uint64 = 0xfeedface
	dataStream, err := consConn.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer dataStream.Close()
	if err := orp.WriteFrame(dataStream, orp.FrameTypeOpenStream, &orpv1.OpenStream{
		TargetService: "svc-echo",
		StreamId:      streamID,
	}); err != nil {
		t.Fatal(err)
	}
	// Drive 1 byte so we know splice has started (and the pair has
	// been recorded by the relay).
	if _, err := dataStream.Write([]byte("k")); err != nil {
		t.Fatal(err)
	}
	echoBuf := make([]byte, 1)
	if err := readDeadline(dataStream, echoBuf, 2*time.Second); err != nil {
		t.Fatalf("echo: %v", err)
	}

	// Now send CANDIDATE_OFFER from consumer; expect provider's
	// control stream to surface it.
	offer := &orpv1.CandidateOffer{
		StreamId: streamID,
		Candidates: []*orpv1.Candidate{
			{Kind: "host", Ip: "192.0.2.1", Port: 30001, Priority: 70},
			{Kind: "srflx", Ip: "203.0.113.5", Port: 30002, Priority: 20},
		},
	}
	if err := orp.WriteFrame(consCtrl, orp.FrameTypeCandidateOffer, offer); err != nil {
		t.Fatal(err)
	}

	got, err := readCandidate(t, provCtrl, orp.FrameTypeCandidateOffer, 2*time.Second)
	if err != nil {
		t.Fatalf("provider read OFFER: %v", err)
	}
	gotOffer, ok := got.(*orpv1.CandidateOffer)
	if !ok {
		t.Fatalf("expected CandidateOffer, got %T", got)
	}
	if gotOffer.StreamId != streamID || len(gotOffer.Candidates) != 2 {
		t.Fatalf("forwarded payload mismatch: %+v", gotOffer)
	}

	// Provider replies with ANSWER; consumer should see it.
	answer := &orpv1.CandidateAnswer{
		StreamId: streamID,
		Candidates: []*orpv1.Candidate{
			{Kind: "host", Ip: "198.51.100.7", Port: 40001, Priority: 70},
		},
	}
	if err := orp.WriteFrame(provCtrl, orp.FrameTypeCandidateAnswer, answer); err != nil {
		t.Fatal(err)
	}
	got2, err := readCandidate(t, consCtrl, orp.FrameTypeCandidateAnswer, 2*time.Second)
	if err != nil {
		t.Fatalf("consumer read ANSWER: %v", err)
	}
	gotAnswer, ok := got2.(*orpv1.CandidateAnswer)
	if !ok {
		t.Fatalf("expected CandidateAnswer, got %T", got2)
	}
	if gotAnswer.StreamId != streamID || len(gotAnswer.Candidates) != 1 {
		t.Fatalf("answer mismatch: %+v", gotAnswer)
	}
}

// readCandidate reads frames from ctrl, skipping unrelated control
// traffic (e.g. PONG), until one of the requested type appears or
// timeout. The return is the parsed *orpv1.CandidateOffer or
// *orpv1.CandidateAnswer.
func readCandidate(t *testing.T, ctrl transport.Stream, want orp.FrameType, total time.Duration) (any, error) {
	t.Helper()
	type result struct {
		v   any
		err error
	}
	done := make(chan result, 1)
	go func() {
		for {
			f, err := orp.ParseFrame(ctrl)
			if err != nil {
				done <- result{err: err}
				return
			}
			if f.Type != want {
				continue
			}
			switch want {
			case orp.FrameTypeCandidateOffer:
				m := &orpv1.CandidateOffer{}
				if err := orp.UnmarshalProto(f, want, m); err != nil {
					done <- result{err: err}
					return
				}
				done <- result{v: m}
			case orp.FrameTypeCandidateAnswer:
				m := &orpv1.CandidateAnswer{}
				if err := orp.UnmarshalProto(f, want, m); err != nil {
					done <- result{err: err}
					return
				}
				done <- result{v: m}
			}
			return
		}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-time.After(total):
		return nil, context.DeadlineExceeded
	}
}
