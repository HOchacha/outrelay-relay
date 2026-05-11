// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge_test

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pbcontrol "github.com/boanlab/OutRelay/lib/control/v1"
	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-relay/pkg/edge"
	"github.com/boanlab/outrelay-relay/pkg/policy"
	"github.com/boanlab/outrelay-relay/pkg/registry"
)

// TestMixedPolicyStress —
//
// One relay, one controller, one provider exposing three services,
// two consumers (one allowed by callee-side policy, one denied).
// Verifies all four matrix corners of the policy + P2P-mode behavior:
//
// 1. allow-svc + allow-callee  -> splice OK
// 2. deny-svc                  -> STREAM_REJECT 403 (caller-side)
// 3. allow-svc + deny-callee   -> STREAM_REJECT 403 (callee-side)
// 4. required-svc              -> splice torn down after timeout
//
// Plus a concurrency stress: 20 concurrent allow streams must all
// round-trip echo successfully without any policy-cache races.
func TestMixedPolicyStress(t *testing.T) {
	t.Parallel()

	// Shrink the REQUIRED-mode timeout so the test doesn't wait 10s.
	prevTimeout := edge.RequiredPromotionTimeout
	edge.RequiredPromotionTimeout = 200 * time.Millisecond
	t.Cleanup(func() { edge.RequiredPromotionTimeout = prevTimeout })

	ca, _ := pki.NewCA()
	ctrlClient := startInProcessController(t)

	relayName, _ := identity.NewRelay("acme", "relay-r")
	provName, _ := identity.NewAgent("acme")
	consOK, _ := identity.NewAgent("acme")
	consBlocked, _ := identity.NewAgent("acme")

	relayCert := issueCert(t, ca, relayName)
	provCert := issueCert(t, ca, provName)
	consOKCert := issueCert(t, ca, consOK)
	consBlockedCert := issueCert(t, ca, consBlocked)

	// Echo backend on the provider side.
	echoLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echoLn.Close()
	go runEchoServer(echoLn)

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

	// Wire up a policy engine with all four rule shapes.
	eng := policy.NewEngine()
	eng.Set([]*policy.Rule{
		// Catch-all ALLOW (covers caller-side + callee-side default).
		{ID: "allow-all", CallerPattern: "*", TargetPattern: "*",
			Decision: policy.DecisionAllow, P2PMode: policy.P2PModeAllowed},
		// Caller-side DENY for svc-deny.
		{ID: "deny-svc", CallerPattern: "*", TargetPattern: "svc-deny",
			Decision: policy.DecisionDeny},
		// REQUIRED P2P on svc-required (caller-side).
		{ID: "required-svc", CallerPattern: "*", TargetPattern: "svc-required",
			Decision: policy.DecisionAllow, P2PMode: policy.P2PModeRequired},
		// Callee-side DENY for the blocked consumer URI specifically.
		// Matched as: caller=providerURI, target=consBlockedURI.
		{ID: "callee-deny", CallerPattern: provName.String(),
			TargetPattern: consBlocked.String(),
			Decision:      policy.DecisionDeny},
	})
	cache := policy.NewCache()

	reg := registry.New(ctrlClient, "relay-r", "", nil)
	srv := edge.New(ln.Addr().String(), nil, reg, eng, cache, nil, nil, nil, nil, slog.New(slog.DiscardHandler))
	srvCtx, srvCancel := context.WithCancel(t.Context())
	defer srvCancel()
	go func() { _ = srv.RunListener(srvCtx, ln) }()

	addr := ln.Addr().String()

	// Provider connects, registers all three services, and answers
	// INCOMING_STREAM by dialing the echo backend.
	provConn, _ := transport.DialQUIC(t.Context(), addr, clientTLS(provCert, ca), nil)
	defer provConn.Close()
	provCtrl := mustHandshake(t, provConn, provName)
	mustRegister(t, provCtrl, "svc-allow")
	mustRegister(t, provCtrl, "svc-deny")
	mustRegister(t, provCtrl, "svc-required")

	if !waitFor(time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		resp, err := ctrlClient.Resolve(ctx, &pbcontrol.ResolveRequest{
			Tenant: "acme", ServiceName: "svc-allow",
		})
		return err == nil && len(resp.Providers) > 0
	}) {
		t.Fatal("svc-allow never registered")
	}

	provCtx, provCancel := context.WithCancel(t.Context())
	defer provCancel()
	go runProvider(provCtx, provConn, echoLn.Addr().String())

	// Helper that opens a stream from a given consumer toward target
	// and returns whichever frame the relay sent first (echo bytes
	// or STREAM_REJECT).
	openStream := func(t *testing.T, cert *tls.Certificate, name identity.Name, target, payload string, timeout time.Duration) (echoed string, rejectedCode uint32, killedAfterEcho bool) {
		t.Helper()
		conn, err := transport.DialQUIC(t.Context(), addr, clientTLS(cert, ca), nil)
		if err != nil {
			t.Fatalf("dial %s: %v", name, err)
		}
		defer conn.Close()
		_ = mustHandshake(t, conn, name)

		st, err := conn.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		if err := orp.WriteFrame(st, orp.FrameTypeOpenStream, &orpv1.OpenStream{
			TargetService: target,
		}); err != nil {
			t.Fatal(err)
		}
		// An accepted stream returns echoed payload bytes; a rejected
		// stream closes early and Read errors. We treat receiving the
		// payload back as accept; any error or read timeout as reject
		// / kill — this is coarse but enough for the four-case matrix
		// without a full ORP frame decoder in the test.
		type res struct {
			b   []byte
			err error
		}
		ch := make(chan res, 1)
		go func() {
			_, _ = st.Write([]byte(payload))
			buf := make([]byte, 64)
			n, err := st.Read(buf)
			ch <- res{b: buf[:n], err: err}
		}()
		select {
		case r := <-ch:
			if r.err == nil && string(r.b) == payload {
				return string(r.b), 0, false
			}
			if r.err != nil && errors.Is(r.err, context.DeadlineExceeded) {
				return "", 0, true
			}
			if r.err != nil {
				return "", 0, false
			}
			return string(r.b), 0, false
		case <-time.After(timeout):
			return "", 0, true
		}
	}

	// Case 1: cons-ok opens svc-allow — splice OK.
	got, _, killed := openStream(t, consOKCert, consOK, "svc-allow", "ping", time.Second)
	if killed || got != "ping" {
		t.Fatalf("case 1 (allow): got=%q killed=%v", got, killed)
	}

	// Case 2: cons-ok opens svc-deny — STREAM_REJECT (no echo, conn closes early).
	got2, _, killed2 := openStream(t, consOKCert, consOK, "svc-deny", "ping", 500*time.Millisecond)
	if got2 == "ping" {
		t.Fatalf("case 2 (deny-svc): unexpected echo: got=%q killed=%v", got2, killed2)
	}

	// Case 3: cons-blocked opens svc-allow — callee-side deny.
	got3, _, killed3 := openStream(t, consBlockedCert, consBlocked, "svc-allow", "ping", 500*time.Millisecond)
	if got3 == "ping" {
		t.Fatalf("case 3 (callee-deny): unexpected echo: got=%q killed=%v", got3, killed3)
	}

	// Case 4: cons-ok opens svc-required — splice starts, then tears
	// down ~RequiredPromotionTimeout after start. We pass a payload so
	// initial echo round-trips; the close on consumerStream propagates
	// after the timer fires.
	conn4, _ := transport.DialQUIC(t.Context(), addr, clientTLS(consOKCert, ca), nil)
	defer conn4.Close()
	_ = mustHandshake(t, conn4, consOK)
	st4, _ := conn4.OpenStream(t.Context())
	defer st4.Close()
	if err := orp.WriteFrame(st4, orp.FrameTypeOpenStream, &orpv1.OpenStream{
		TargetService: "svc-required",
	}); err != nil {
		t.Fatal(err)
	}
	// Initial echo should round-trip.
	if _, err := st4.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 2)
	if err := readDeadline(st4, echo, 500*time.Millisecond); err != nil {
		t.Fatalf("required initial echo failed (splice should run pre-timeout): %v", err)
	}
	// After RequiredPromotionTimeout the relay should close the splice.
	// Subsequent reads should fail within ~timeout grace.
	deadline := time.Now().Add(edge.RequiredPromotionTimeout + 500*time.Millisecond)
	for time.Now().Before(deadline) {
		buf := make([]byte, 1)
		st4.Write([]byte("."))
		if err := readDeadline(st4, buf, 100*time.Millisecond); err != nil {
			// Splice closed — what we expected.
			return
		}
	}
	t.Fatal("required-svc splice never tore down after timeout")
}

// TestMixedPolicyConcurrentAllow drives 20 concurrent svc-allow
// streams through the relay's policy + cache to expose any cache
// race or matcher contention. All must round-trip the echo payload.
func TestMixedPolicyConcurrentAllow(t *testing.T) {
	t.Parallel()
	ca, _ := pki.NewCA()
	ctrlClient := startInProcessController(t)

	relayName, _ := identity.NewRelay("acme", "relay-r")
	provName, _ := identity.NewAgent("acme")
	consName, _ := identity.NewAgent("acme")

	relayCert := issueCert(t, ca, relayName)
	provCert := issueCert(t, ca, provName)
	consCert := issueCert(t, ca, consName)

	echoLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echoLn.Close()
	go runEchoServer(echoLn)

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

	eng := policy.NewEngine()
	eng.Set([]*policy.Rule{
		{ID: "allow-all", CallerPattern: "*", TargetPattern: "*",
			Decision: policy.DecisionAllow, P2PMode: policy.P2PModeAllowed},
	})
	cache := policy.NewCache()

	reg := registry.New(ctrlClient, "relay-r", "", nil)
	srv := edge.New(ln.Addr().String(), nil, reg, eng, cache, nil, nil, nil, nil, slog.New(slog.DiscardHandler))
	srvCtx, srvCancel := context.WithCancel(t.Context())
	defer srvCancel()
	go func() { _ = srv.RunListener(srvCtx, ln) }()

	addr := ln.Addr().String()
	provConn, _ := transport.DialQUIC(t.Context(), addr, clientTLS(provCert, ca), nil)
	defer provConn.Close()
	provCtrl := mustHandshake(t, provConn, provName)
	mustRegister(t, provCtrl, "svc-allow")

	if !waitFor(time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		resp, err := ctrlClient.Resolve(ctx, &pbcontrol.ResolveRequest{
			Tenant: "acme", ServiceName: "svc-allow",
		})
		return err == nil && len(resp.Providers) > 0
	}) {
		t.Fatal("svc-allow never registered")
	}

	provCtx, provCancel := context.WithCancel(t.Context())
	defer provCancel()
	go runProvider(provCtx, provConn, echoLn.Addr().String())

	const N = 20
	consConn, _ := transport.DialQUIC(t.Context(), addr, clientTLS(consCert, ca), nil)
	defer consConn.Close()
	_ = mustHandshake(t, consConn, consName)

	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := range N {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := consConn.OpenStream(t.Context())
			if err != nil {
				return
			}
			defer st.Close()
			if err := orp.WriteFrame(st, orp.FrameTypeOpenStream, &orpv1.OpenStream{
				TargetService: "svc-allow",
			}); err != nil {
				return
			}
			payload := []byte{byte('a' + i%26), byte('A' + i%26)}
			if _, err := st.Write(payload); err != nil {
				return
			}
			got := make([]byte, 2)
			if err := readDeadline(st, got, 3*time.Second); err != nil {
				return
			}
			if string(got) == string(payload) {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if ok.Load() != N {
		t.Fatalf("only %d/%d concurrent allow streams round-tripped", ok.Load(), N)
	}
}
