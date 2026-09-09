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

	pb "github.com/boanlab/OutRelay/lib/control/v1"
	"github.com/boanlab/outrelay-relay/pkg/edge"
	"github.com/boanlab/outrelay-relay/pkg/registry"
)

// TestSuccessorsAdvertisedToBothSides —
//
// Relocation invariant: both halves of a stream must learn the same
// ordered list of fallback relays *before* the stream carries bytes,
// because a crashed relay cannot tell anyone where to go. The relay
// therefore publishes its successor list in HELLO_ACK (session-level)
// and repeats it per stream in INCOMING_STREAM (provider side) and
// STREAM_READY (both sides).
func TestSuccessorsAdvertisedToBothSides(t *testing.T) {
	t.Parallel()

	successors := []string{"10.0.0.2:7443", "10.0.0.3:7443"}

	ca, _ := pki.NewCA()
	relayName, _ := identity.NewRelay("acme", "relay-r1")
	provName, _ := identity.NewAgent("acme")
	consName, _ := identity.NewAgent("acme")
	relayCert := issueCert(t, ca, relayName)
	provCert := issueCert(t, ca, provName)
	consCert := issueCert(t, ca, consName)

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
	srv.SetSuccessors(successors)
	relayCtx, cancelRelay := context.WithCancel(t.Context())
	defer cancelRelay()
	go func() { _ = srv.RunListener(relayCtx, ln) }()
	relayAddr := ln.Addr().String()

	// Provider: HELLO, REGISTER, then accept exactly one stream.
	provConn, err := transport.DialQUIC(t.Context(), relayAddr, clientTLS(provCert, ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer provConn.Close()
	provCtrl, provAck := handshakeAck(t, provConn, provName)
	if !slices.Equal(provAck.SuccessorEndpoints, successors) {
		t.Fatalf("provider HELLO_ACK successors = %v, want %v", provAck.SuccessorEndpoints, successors)
	}
	mustRegister(t, provCtrl, "svc-x")
	if !waitFor(time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		resp, err := ctrl.Resolve(ctx, &pb.ResolveRequest{Tenant: "acme", ServiceName: "svc-x"})
		return err == nil && len(resp.Providers) > 0
	}) {
		t.Fatal("svc-x never registered")
	}

	// Consumer: HELLO, OPEN_STREAM.
	consConn, err := transport.DialQUIC(t.Context(), relayAddr, clientTLS(consCert, ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer consConn.Close()
	consCtrl, consAck := handshakeAck(t, consConn, consName)
	if !slices.Equal(consAck.SuccessorEndpoints, successors) {
		t.Fatalf("consumer HELLO_ACK successors = %v, want %v", consAck.SuccessorEndpoints, successors)
	}
	stream, err := consConn.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := orp.WriteFrame(stream, orp.FrameTypeOpenStream, &orpv1.OpenStream{
		TargetService: "svc-x", StreamId: 42,
	}); err != nil {
		t.Fatal(err)
	}

	// Provider side: INCOMING_STREAM carries resume_relays.
	acceptCtx, acceptCancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer acceptCancel()
	inStream, err := provConn.AcceptStream(acceptCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer inStream.Close()
	in := &orpv1.IncomingStream{}
	if f, err := orp.ParseFrame(inStream); err != nil {
		t.Fatal(err)
	} else if err := orp.UnmarshalProto(f, orp.FrameTypeIncomingStream, in); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(in.ResumeRelays, successors) {
		t.Fatalf("INCOMING_STREAM resume_relays = %v, want %v", in.ResumeRelays, successors)
	}
	if err := orp.WriteFrame(inStream, orp.FrameTypeStreamAccept, &orpv1.StreamAccept{}); err != nil {
		t.Fatal(err)
	}

	// Both ctrl channels: STREAM_READY carries the same list.
	for _, side := range []struct {
		name string
		ctrl transport.Stream
	}{{"consumer", consCtrl}, {"provider", provCtrl}} {
		ready := &orpv1.StreamReady{}
		f, err := orp.ParseFrame(side.ctrl)
		if err != nil {
			t.Fatalf("%s: read STREAM_READY: %v", side.name, err)
		}
		if err := orp.UnmarshalProto(f, orp.FrameTypeStreamReady, ready); err != nil {
			t.Fatalf("%s: %v", side.name, err)
		}
		if ready.StreamId != 42 || !slices.Equal(ready.ResumeRelays, successors) {
			t.Fatalf("%s: STREAM_READY = %+v, want stream 42 with %v", side.name, ready, successors)
		}
	}
}

// handshakeAck is mustHandshake but also returns the parsed HELLO_ACK.
func handshakeAck(t *testing.T, conn transport.Conn, name identity.Name) (transport.Stream, *orpv1.HelloAck) {
	t.Helper()
	ctrl, err := conn.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := orp.WriteFrame(ctrl, orp.FrameTypeHello, &orpv1.Hello{
		ProtocolVersion: "orp/1", AgentUri: name.String(),
	}); err != nil {
		t.Fatal(err)
	}
	f, err := orp.ParseFrame(ctrl)
	if err != nil {
		t.Fatal(err)
	}
	ack := &orpv1.HelloAck{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeHelloAck, ack); err != nil {
		t.Fatal(err)
	}
	return ctrl, ack
}
