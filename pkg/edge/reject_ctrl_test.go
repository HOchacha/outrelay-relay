// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge_test

import (
	"context"
	"crypto/tls"
	"log/slog"
	"testing"
	"time"

	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-relay/pkg/edge"
	"github.com/boanlab/outrelay-relay/pkg/policy"
	"github.com/boanlab/outrelay-relay/pkg/registry"
)

// TestStreamRejectMirroredOnCtrl —
//
// A consumer that is denied by policy must learn about it on its
// stream-0 control stream, not only on the data stream. The agent
// blocks on {STREAM_READY | ALLOC_GRANTED} after OPEN_STREAM; without
// a negative signal there it times out, assumes splice and bridges
// the data stream — delivering the STREAM_REJECT frame bytes to the
// application as payload (feature-test t04 saw 57 bytes arrive under
// a deny rule).
func TestStreamRejectMirroredOnCtrl(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()
	ctrlClient := startInProcessController(t)
	relayName, _ := identity.NewRelay("acme", "relay-r")
	consName, _ := identity.NewAgent("acme")
	relayCert := issueCert(t, ca, relayName)
	consCert := issueCert(t, ca, consName)

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

	eng := policy.NewEngine()
	eng.Set([]*policy.Rule{
		{ID: "deny-svc", CallerPattern: "*", TargetPattern: "svc-deny",
			Decision: policy.DecisionDeny},
	})
	reg := registry.New(ctrlClient, "relay-r", "", nil)
	srv := edge.New(ln.Addr().String(), nil, reg, eng, policy.NewCache(), nil, nil, nil, nil, slog.New(slog.DiscardHandler))
	srvCtx, srvCancel := context.WithCancel(t.Context())
	defer srvCancel()
	go func() { _ = srv.RunListener(srvCtx, ln) }()

	conn, err := transport.DialQUIC(t.Context(), ln.Addr().String(), clientTLS(consCert, ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctrl := mustHandshake(t, conn, consName)

	const streamID = 4242
	st, err := conn.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := orp.WriteFrame(st, orp.FrameTypeOpenStream, &orpv1.OpenStream{
		TargetService: "svc-deny", StreamId: streamID,
	}); err != nil {
		t.Fatal(err)
	}

	// The data stream still carries the stream-scoped reject (wire
	// compatibility with agents that parse it there).
	f, err := orp.ParseFrame(st)
	if err != nil || f.Type != orp.FrameTypeStreamReject {
		t.Fatalf("data stream: expected STREAM_REJECT, got %v err=%v", f, err)
	}

	// And the control stream carries a mirror that names the stream.
	type res struct {
		f   *orp.Frame
		err error
	}
	ch := make(chan res, 1)
	go func() {
		f, err := orp.ParseFrame(ctrl)
		ch <- res{f, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("ctrl read: %v", r.err)
		}
		if r.f.Type != orp.FrameTypeStreamReject {
			t.Fatalf("ctrl: expected STREAM_REJECT, got %v", r.f.Type)
		}
		rej := &orpv1.StreamReject{}
		if err := orp.UnmarshalProto(r.f, orp.FrameTypeStreamReject, rej); err != nil {
			t.Fatal(err)
		}
		if rej.StreamId != streamID || rej.Code != 403 {
			t.Fatalf("ctrl STREAM_REJECT = {stream_id:%d code:%d reason:%q}, want stream_id=%d code=403",
				rej.StreamId, rej.Code, rej.Reason, streamID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no STREAM_REJECT mirrored on the control stream within 2s")
	}
}
