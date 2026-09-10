// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge_test

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/boanlab/OutRelay/lib/control/v1"
	"github.com/boanlab/OutRelay/lib/identity"
	"github.com/boanlab/OutRelay/lib/orp"
	orpv1 "github.com/boanlab/OutRelay/lib/orp/v1"
	"github.com/boanlab/OutRelay/lib/transport"
	"github.com/boanlab/OutRelay/pkg/pki"

	"github.com/boanlab/outrelay-relay/pkg/edge"
	"github.com/boanlab/outrelay-relay/pkg/policy"
	"github.com/boanlab/outrelay-relay/pkg/registry"
)

// failingCtrl is a real controller client whose RegisterService always
// fails with a terminal (non-connectivity) error.
type failingCtrl struct{ pb.RegistryClient }

func (failingCtrl) RegisterService(context.Context, *pb.RegisterServiceRequest, ...grpc.CallOption) (*pb.RegisterServiceResponse, error) {
	return nil, status.Error(codes.Internal, "controller: db is read-only")
}

// A REGISTER the relay cannot publish must not be dropped silently:
// the agent blocks on REGISTER_ACK, so with no answer the provider
// sits "connected" but unreachable for its whole lifetime. The relay
// has to end the link so the agent's Expose fails and it retries via
// its normal reconnect path.
func TestRegisterFailureClosesAgentLink(t *testing.T) {
	t.Parallel()

	ca, _ := pki.NewCA()
	relayName, _ := identity.NewRelay("acme", "relay-r")
	provName, _ := identity.NewAgent("acme")
	relayCert := issueCert(t, ca, relayName)
	provCert := issueCert(t, ca, provName)

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

	reg := registry.New(failingCtrl{startInProcessController(t)}, "relay-r", "", nil)
	srv := edge.New(ln.Addr().String(), nil, reg, policy.NewEngine(), policy.NewCache(), nil, nil, nil, nil, slog.New(slog.DiscardHandler))
	srvCtx, srvCancel := context.WithCancel(t.Context())
	defer srvCancel()
	go func() { _ = srv.RunListener(srvCtx, ln) }()

	conn, err := transport.DialQUIC(t.Context(), ln.Addr().String(), clientTLS(provCert, ca), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctrl := mustHandshake(t, conn, provName)

	if err := orp.WriteFrame(ctrl, orp.FrameTypeRegister, &orpv1.Register{
		ServiceName: "echo", LocalAddr: "127.0.0.1:1",
	}); err != nil {
		t.Fatal(err)
	}

	type res struct {
		f   *orp.Frame
		err error
	}
	got := make(chan res, 1)
	go func() {
		f, err := orp.ParseFrame(ctrl)
		got <- res{f, err}
	}()
	select {
	case r := <-got:
		if r.err == nil {
			t.Fatalf("expected the link to close, got frame %v", r.f.Type)
		}
		if errors.Is(r.err, context.DeadlineExceeded) {
			t.Fatal(r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent still waiting for REGISTER_ACK 3s after a failed REGISTER")
	}
}
