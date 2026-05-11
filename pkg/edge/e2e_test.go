// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
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
	"github.com/boanlab/outrelay-relay/pkg/registry"
)

// TestE2EConsumerProviderSplice —
//
// One relay, two minimal in-test agents (provider P + consumer C),
// one TCP echo backend. The "agents" here are hand-rolled inside the
// test to avoid a cross-module test dependency on outrelay-agent —
// the agent binary's session package gets its own unit tests against
// a stub relay. Together they cover the wire protocol from both sides.
//
// Flow under test: HELLO, REGISTER, OPEN_STREAM, INCOMING_STREAM,
// STREAM_ACCEPT, splice plane.
func TestE2EConsumerProviderSplice(t *testing.T) {
	t.Parallel()

	ca, err := pki.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	relayName, _ := identity.NewAgent("acme")
	provName, _ := identity.NewAgent("acme")
	consName, _ := identity.NewAgent("acme")

	relayCert := issueCert(t, ca, relayName)
	provCert := issueCert(t, ca, provName)
	consCert := issueCert(t, ca, consName)

	// Local TCP echo backend on P's side.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go runEchoServer(echoLn)

	// Start the relay listening with mTLS.
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

	// Spin up a controller in-process so the relay can publish/resolve.
	ctrl := startInProcessController(t)
	reg := registry.New(ctrl, "relay-test", "", nil)

	srv := edge.New(ln.Addr().String(), nil, reg, nil, nil, nil, nil, nil, nil, slog.New(slog.DiscardHandler))
	relayCtx, cancelRelay := context.WithCancel(t.Context())
	defer cancelRelay()
	go func() { _ = srv.RunListener(relayCtx, ln) }()

	relayAddr := ln.Addr().String()

	// Provider client: connect, HELLO, REGISTER, accept incoming streams,
	// dial echo backend on accept and splice them.
	provClientTLS := clientTLS(provCert, ca)
	provConn, err := transport.DialQUIC(t.Context(), relayAddr, provClientTLS, nil)
	if err != nil {
		t.Fatalf("provider dial: %v", err)
	}
	defer provConn.Close()

	provCtrl := mustHandshake(t, provConn, provName)
	mustRegister(t, provCtrl, "svc-echo")

	// Wait for the controller to see the registration.
	if !waitFor(time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		resp, err := ctrl.Resolve(ctx, &pb.ResolveRequest{
			Tenant: "acme", ServiceName: "svc-echo",
		})
		return err == nil && len(resp.Providers) > 0
	}) {
		t.Fatal("svc-echo never registered with controller")
	}

	provCtx, provCancel := context.WithCancel(t.Context())
	defer provCancel()
	go runProvider(provCtx, provConn, echoLn.Addr().String())

	// Consumer client: connect, HELLO, OPEN_STREAM, write+read echo.
	consClientTLS := clientTLS(consCert, ca)
	consConn, err := transport.DialQUIC(t.Context(), relayAddr, consClientTLS, nil)
	if err != nil {
		t.Fatalf("consumer dial: %v", err)
	}
	defer consConn.Close()

	_ = mustHandshake(t, consConn, consName)

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

	want := []byte("hello via relay")
	if _, err := stream.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if err := readDeadline(stream, got, 3*time.Second); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
}

// runEchoServer accepts forever and echoes each connection.
func runEchoServer(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}(c)
	}
}

// runProvider implements the minimum provider behavior: accept fresh
// streams from the relay, parse INCOMING_STREAM, ACCEPT, then splice
// the relay stream with a fresh local backend connection.
func runProvider(ctx context.Context, conn transport.Conn, backendAddr string) {
	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(s transport.Stream) {
			f, err := orp.ParseFrame(s)
			if err != nil {
				_ = s.Close()
				return
			}
			if f.Type != orp.FrameTypeIncomingStream {
				_ = s.Close()
				return
			}
			in := &orpv1.IncomingStream{}
			if err := orp.UnmarshalProto(f, orp.FrameTypeIncomingStream, in); err != nil {
				_ = s.Close()
				return
			}
			backend, err := net.Dial("tcp", backendAddr)
			if err != nil {
				_ = orp.WriteFrame(s, orp.FrameTypeStreamReject, &orpv1.StreamReject{
					Code: 502, Reason: err.Error(),
				})
				_ = s.Close()
				return
			}
			if err := orp.WriteFrame(s, orp.FrameTypeStreamAccept, &orpv1.StreamAccept{}); err != nil {
				_ = backend.Close()
				_ = s.Close()
				return
			}
			bridge(s, backend)
		}(s)
	}
}

// bridge wires two ReadWriteClosers in both directions until either side EOFs.
func bridge(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

func mustHandshake(t *testing.T, conn transport.Conn, name identity.Name) transport.Stream {
	t.Helper()
	ctrl, err := conn.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := orp.WriteFrame(ctrl, orp.FrameTypeHello, &orpv1.Hello{
		ProtocolVersion: "orp/1",
		AgentUri:        name.String(),
	}); err != nil {
		t.Fatal(err)
	}
	f, err := orp.ParseFrame(ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != orp.FrameTypeHelloAck {
		t.Fatalf("expected HELLO_ACK, got %v", f.Type)
	}
	return ctrl
}

func mustRegister(t *testing.T, ctrl transport.Stream, svc string) {
	t.Helper()
	if err := orp.WriteFrame(ctrl, orp.FrameTypeRegister, &orpv1.Register{
		ServiceName: svc,
	}); err != nil {
		t.Fatal(err)
	}
	f, err := orp.ParseFrame(ctrl)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != orp.FrameTypeRegisterAck {
		t.Fatalf("expected REGISTER_ACK, got %v", f.Type)
	}
}

func clientTLS(cert *tls.Certificate, ca *pki.CA) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      ca.CertPool(),
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}
}

func issueCert(t *testing.T, ca *pki.CA, name identity.Name) *tls.Certificate {
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

func readDeadline(r io.Reader, buf []byte, d time.Duration) error {
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(r, buf)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		return context.DeadlineExceeded
	}
}

func waitFor(total time.Duration, predicate func() bool) bool {
	deadline := time.Now().Add(total)
	for time.Now().Before(deadline) {
		if predicate() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// startInProcessController spins a controller gRPC server backed by an
// in-memory SQLite store and returns a connected client.
func startInProcessController(t *testing.T) pb.RegistryClient {
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
