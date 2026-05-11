// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge_test

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-relay/pkg/edge"
	"github.com/boanlab/outrelay-relay/pkg/registry"
)

// TestObservedAddrEcho —
//
// An agent sends OBSERVED_ADDR_QUERY on its control stream after
// HELLO; the relay replies with the agent's QUIC RemoteAddr (the
// NAT-mapped server-reflexive endpoint). The agent uses this as
// its "srflx" candidate during P2P promotion.
func TestObservedAddrEcho(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()
	relayName, _ := identity.NewRelay("acme", "relay-r")
	a, _ := identity.NewAgent("acme")

	relayCert := issueCert(t, ca, relayName)
	aCert := issueCert(t, ca, a)

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

	conn, err := transport.DialQUIC(t.Context(), ln.Addr().String(), clientTLS(aCert, ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctrlStream := mustHandshake(t, conn, a)

	if err := orp.WriteFrame(ctrlStream, orp.FrameTypeObservedAddrQuery, &orpv1.ObservedAddrQuery{
		RequestId: 42,
	}); err != nil {
		t.Fatal(err)
	}

	f, err := orp.ParseFrame(ctrlStream)
	if err != nil {
		t.Fatalf("parse frame: %v", err)
	}
	if f.Type != orp.FrameTypeObservedAddrResp {
		t.Fatalf("unexpected frame type: %v", f.Type)
	}
	r := &orpv1.ObservedAddrResp{}
	if err := orp.UnmarshalProto(f, orp.FrameTypeObservedAddrResp, r); err != nil {
		t.Fatal(err)
	}
	if r.RequestId != 42 {
		t.Fatalf("request id mismatch: got %d", r.RequestId)
	}
	// Agent's QUIC LocalAddr is its own outbound src — what the
	// relay should echo. Compare loosely on host (it's loopback).
	localHost, _, _ := net.SplitHostPort(conn.LocalAddr().String())
	// 127.0.0.1 vs ::1 — accept either IPv4 / IPv6 loopback.
	if !strings.HasPrefix(r.Ip, "127.") && r.Ip != "::1" && r.Ip != localHost {
		t.Fatalf("relay echoed %s; expected loopback or %s", r.Ip, localHost)
	}
}
