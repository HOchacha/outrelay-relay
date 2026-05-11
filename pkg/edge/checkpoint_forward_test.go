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

// TestCheckpointForwardRoundTrip —
//
// Two agents register, open a stream so the relay records their pair,
// then one side writes STREAM_CHECKPOINT on its control stream. The
// relay must route the frame onto the peer's control stream by
// stream_id with the payload preserved. Mirrors candidate_forward_test
// since both use the same per-stream control routing path.
func TestCheckpointForwardRoundTrip(t *testing.T) {
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

	consConn, err := transport.DialQUIC(t.Context(), addr, clientTLS(consCert, ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer consConn.Close()
	consCtrl := mustHandshake(t, consConn, consName)

	const streamID uint64 = 0xcafef00d
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
	// Trigger one byte through splice so the relay has the pair recorded.
	if _, err := dataStream.Write([]byte("k")); err != nil {
		t.Fatal(err)
	}
	echoBuf := make([]byte, 1)
	if err := readDeadline(dataStream, echoBuf, 2*time.Second); err != nil {
		t.Fatalf("echo: %v", err)
	}

	cp := &orpv1.StreamCheckpoint{
		StreamId:        streamID,
		MyPosition:      4096,
		PeerAckPosition: 1024,
	}
	if err := orp.WriteFrame(consCtrl, orp.FrameTypeStreamCheckpoint, cp); err != nil {
		t.Fatal(err)
	}

	got, err := readCheckpoint(t, provCtrl, 2*time.Second)
	if err != nil {
		t.Fatalf("provider read CHECKPOINT: %v", err)
	}
	if got.StreamId != streamID || got.MyPosition != 4096 || got.PeerAckPosition != 1024 {
		t.Fatalf("forwarded payload mismatch: %+v", got)
	}
}

// readCheckpoint reads frames from ctrl, skipping unrelated control
// traffic, until a STREAM_CHECKPOINT appears or timeout fires.
func readCheckpoint(t *testing.T, ctrl transport.Stream, total time.Duration) (*orpv1.StreamCheckpoint, error) {
	t.Helper()
	type result struct {
		v   *orpv1.StreamCheckpoint
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
			if f.Type != orp.FrameTypeStreamCheckpoint {
				continue
			}
			m := &orpv1.StreamCheckpoint{}
			if err := orp.UnmarshalProto(f, orp.FrameTypeStreamCheckpoint, m); err != nil {
				done <- result{err: err}
				return
			}
			done <- result{v: m}
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
