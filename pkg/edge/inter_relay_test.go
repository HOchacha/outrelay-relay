// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/boanlab/OutRelay/lib/control/v1"
	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"
	ctrlreg "github.com/boanlab/OutRelay/pkg/registry"
	"github.com/boanlab/OutRelay/pkg/registry/store"

	"github.com/boanlab/outrelay-relay/pkg/edge"
	"github.com/boanlab/outrelay-relay/pkg/intra"
	"github.com/boanlab/outrelay-relay/pkg/registry"
)

// TestE2EInterRelayForward —
//
// Provider agent connects to relay-A. Consumer agent connects to
// relay-B. Both relays share one controller. Consumer's OPEN_STREAM
// resolves to relay-A; relay-B forwards via pkg/intra to relay-A,
// which routes to its locally connected provider. Verifies the
// inter-relay path round-trips bytes end-to-end.
func TestE2EInterRelayForward(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()
	ctrlClient := startCtrl(t)

	// Issue identities.
	provName, _ := identity.NewAgent("acme")
	consName, _ := identity.NewAgent("acme")
	relayAName, _ := identity.NewRelay("acme", "relay-a")
	relayBName, _ := identity.NewRelay("acme", "relay-b")

	provCert := issueCertHere(t, ca, provName)
	consCert := issueCertHere(t, ca, consName)
	relayACert := issueCertHere(t, ca, relayAName)
	relayBCert := issueCertHere(t, ca, relayBName)

	// Spin up two relay listeners.
	relayAListenAddr, relayAClose := startRelay(t, ca, relayACert, ctrlClient, relayAName.String())
	defer relayAClose()
	relayBListenAddr, relayBClose := startRelay(t, ca, relayBCert, ctrlClient, relayBName.String())
	defer relayBClose()

	// Self-register both relays so the controller's Resolve can JOIN
	// the endpoint into Provider.RelayEndpoint.
	upsertCtx, upsertCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer upsertCancel()
	if _, err := ctrlClient.UpsertRelay(upsertCtx, &pb.UpsertRelayRequest{
		Id: relayAName.String(), Endpoint: relayAListenAddr,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ctrlClient.UpsertRelay(upsertCtx, &pb.UpsertRelayRequest{
		Id: relayBName.String(), Endpoint: relayBListenAddr,
	}); err != nil {
		t.Fatal(err)
	}

	// Provider connects to relay-A and registers svc-echo, serving an
	// echo backend.
	echoLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echoLn.Close()
	go runEchoServer(echoLn)

	provConn, err := transport.DialQUIC(t.Context(), relayAListenAddr, clientTLS(provCert, ca), nil)
	if err != nil {
		t.Fatalf("prov dial: %v", err)
	}
	defer provConn.Close()
	provCtrl := mustHandshake(t, provConn, provName)
	mustRegister(t, provCtrl, "svc-echo")
	provCtx, provCancel := context.WithCancel(t.Context())
	defer provCancel()
	go runProvider(provCtx, provConn, echoLn.Addr().String())

	// Wait for the controller to see svc-echo and resolve it to relay-A.
	if !waitFor(time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		resp, err := ctrlClient.Resolve(ctx, &pb.ResolveRequest{
			Tenant: "acme", ServiceName: "svc-echo",
		})
		if err != nil || len(resp.Providers) == 0 {
			return false
		}
		return resp.Providers[0].RelayEndpoint == relayAListenAddr
	}) {
		t.Fatal("controller never saw svc-echo with relay-A endpoint")
	}

	// Consumer connects to relay-B and dials svc-echo. relay-B should
	// detect the provider is on relay-A and forward.
	consConn, err := transport.DialQUIC(t.Context(), relayBListenAddr, clientTLS(consCert, ca), nil)
	if err != nil {
		t.Fatalf("cons dial: %v", err)
	}
	defer consConn.Close()
	mustHandshake(t, consConn, consName)

	stream, err := consConn.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := orp.WriteFrame(stream, orp.FrameTypeOpenStream, &orpv1.OpenStream{
		TargetService: "svc-echo",
	}); err != nil {
		t.Fatal(err)
	}
	want := []byte("inter-relay echo")
	if _, err := stream.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if err := readDeadline(stream, got, 5*time.Second); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
}

// startRelay spins one relay listener wired to the shared controller
// gRPC client and returns its listen address plus a cleanup func.
func startRelay(t *testing.T, ca *pki.CA, cert *tls.Certificate, ctrl pb.RegistryClient, relayID string) (string, func()) {
	t.Helper()
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientCAs:    ca.CertPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := transport.ListenQUIC("127.0.0.1:0", tlsConf, nil)
	if err != nil {
		t.Fatal(err)
	}

	reg := registry.New(ctrl, relayID, "", nil)
	pool := intra.NewPool(&tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}, nil)
	srv := edge.New(ln.Addr().String(), nil, reg, nil, nil, nil, pool, nil, nil, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithCancel(t.Context())
	go func() { _ = srv.RunListener(ctx, ln) }()
	addr := ln.Addr().String()
	return addr, func() {
		cancel()
		_ = ln.Close()
		_ = pool.Close()
	}
}

func issueCertHere(t *testing.T, ca *pki.CA, name identity.Name) *tls.Certificate {
	t.Helper()
	csrDER, key, err := pki.NewCSR(name)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := ca.Sign(csrDER, name, 0)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key, Leaf: leaf}
}

// startCtrl returns a connected gRPC client to a fresh in-memory
// controller. Only the Registry service is wired; this test does not
// exercise policy or audit.
func startCtrl(t *testing.T) pb.RegistryClient {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	pb.RegisterRegistryServer(gs, ctrlreg.New(st, nil))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(func() { gs.GracefulStop(); _ = st.Close() })

	cc, err := grpc.NewClient(ln.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return pb.NewRegistryClient(cc)
}
