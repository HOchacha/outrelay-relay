// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package registry_test

import (
	"context"
	"errors"
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

type fakeProvider struct{ uri string }

func (f *fakeProvider) AgentURI() string { return f.uri }
func (f *fakeProvider) String() string   { return f.uri }
func (f *fakeProvider) OpenIncoming(string, string, string, uint64) (registry.Stream, error) {
	return nil, errors.New("fake")
}

// startCtrl spins an in-process controller backed by an in-memory
// SQLite store and returns a connected gRPC client.
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

func TestRegistryFacade(t *testing.T) {
	t.Parallel()
	ctrl := startCtrl(t)
	r := registry.New(ctrl, "relay-1", "", nil)

	name, _ := identity.NewAgent("acme")
	uri := name.String()
	p := &fakeProvider{uri: uri}
	r.RegisterAgent(uri, p)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	if _, err := r.RegisterService(ctx, uri, "svc-x", "127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}

	got, _, err := r.Resolve(ctx, uri, "svc-x")
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentURI() != uri {
		t.Fatalf("got %s, want %s", got.AgentURI(), uri)
	}

	r.UnregisterAgent(ctx, uri)
	if _, _, err := r.Resolve(ctx, uri, "svc-x"); !errors.Is(err, registry.ErrServiceNotFound) {
		t.Fatalf("expected ErrServiceNotFound after dereg, got %v", err)
	}
}

func TestRegistryRemoteProviderError(t *testing.T) {
	t.Parallel()
	ctrl := startCtrl(t)

	// Two relays on the same controller. A registers the service;
	// B's Resolve should yield ErrProviderRemote.
	relayA := registry.New(ctrl, "relay-A", "us-east-1", nil)
	relayB := registry.New(ctrl, "relay-B", "ap-northeast-2", nil)
	name, _ := identity.NewAgent("acme")
	uri := name.String()
	relayA.RegisterAgent(uri, &fakeProvider{uri: uri})

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := relayA.RegisterService(ctx, uri, "svc-y", ""); err != nil {
		t.Fatal(err)
	}

	_, remote, err := relayB.Resolve(ctx, uri, "svc-y")
	if !errors.Is(err, registry.ErrProviderRemote) {
		t.Fatalf("expected ErrProviderRemote, got %v", err)
	}
	if remote == nil || remote.RelayID != "relay-A" {
		t.Fatalf("remote info: %+v", remote)
	}
}
