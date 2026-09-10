// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package registry_test

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/boanlab/OutRelay/lib/control/v1"
	"github.com/boanlab/OutRelay/lib/identity"
	ctrlreg "github.com/boanlab/OutRelay/pkg/registry"
	"github.com/boanlab/OutRelay/pkg/registry/store"

	"github.com/boanlab/outrelay-relay/pkg/registry"
)

// A provider that connects while the controller is restarting must not
// be turned away: the relay's controller client fails fast while gRPC
// is in reconnect backoff, and a fail-fast REGISTER is dropped on the
// floor (no ack, no retry), leaving the service unreachable until the
// agent itself restarts. RegisterService has to wait for the
// controller to come back (bounded) instead of failing fast.
func TestRegisterServiceWaitsForControllerToComeBack(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	// Reserve an address, then leave it closed so the first dial is
	// refused and the client enters backoff.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	r := registry.New(pb.NewRegistryClient(cc), "relay-1", "", nil)
	name, _ := identity.NewAgent("acme")
	uri := name.String()

	// Prime the connection so it has actually failed once.
	_, _, _ = r.Resolve(ctx, uri, "nothing")

	// Bring the controller up 1.5 s later on the same address.
	go func() {
		time.Sleep(1500 * time.Millisecond)
		st, err := store.Open(ctx, ":memory:")
		if err != nil {
			t.Error(err)
			return
		}
		gs := grpc.NewServer()
		pb.RegisterRegistryServer(gs, ctrlreg.New(st, nil))
		l, err := net.Listen("tcp", addr)
		if err != nil {
			t.Error(err)
			return
		}
		go func() { _ = gs.Serve(l) }()
		t.Cleanup(func() { gs.Stop(); _ = st.Close() })
	}()

	id, err := r.RegisterService(ctx, uri, "echo", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("RegisterService during a controller restart failed fast: %v", err)
	}
	if id == "" {
		t.Fatal("empty service id")
	}
}
