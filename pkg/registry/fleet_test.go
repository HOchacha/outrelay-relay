// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package registry_test

import (
	"slices"
	"testing"
	"time"

	pb "github.com/boanlab/OutRelay/lib/control/v1"

	"github.com/boanlab/outrelay-relay/pkg/registry"
)

func TestSuccessorsExcludesSelfAndPrefersSameRegion(t *testing.T) {
	t.Parallel()
	fleet := []*pb.RelayInstance{
		{Id: "r-eu-b", Region: "eu", Endpoint: "eu-b:7443"},
		{Id: "r-us-self", Region: "us", Endpoint: "self:7443"},
		{Id: "r-us-z", Region: "us", Endpoint: "us-z:7443"},
		{Id: "r-eu-a", Region: "eu", Endpoint: "eu-a:7443"},
		{Id: "r-us-a", Region: "us", Endpoint: "us-a:7443"},
	}
	got := registry.Successors("r-us-self", "us", fleet)
	want := []string{"us-a:7443", "us-z:7443", "eu-a:7443", "eu-b:7443"}
	if !slices.Equal(got, want) {
		t.Fatalf("successors = %v, want %v", got, want)
	}
}

func TestSuccessorsEmptyFleet(t *testing.T) {
	t.Parallel()
	if got := registry.Successors("r1", "us", nil); len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
	only := []*pb.RelayInstance{{Id: "r1", Region: "us", Endpoint: "self:7443"}}
	if got := registry.Successors("r1", "us", only); len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

// TestHeartbeatPublishesSuccessors: the heartbeat loop upserts this
// relay, reads the fleet snapshot back, and reports the successor
// list through the callback whenever it changes.
func TestHeartbeatPublishesSuccessors(t *testing.T) {
	t.Parallel()
	ctrl := startCtrl(t)

	// A peer relay is already registered.
	if _, err := ctrl.UpsertRelay(t.Context(), &pb.UpsertRelayRequest{
		Id: "r2", Region: "us", Endpoint: "10.0.0.2:7443",
	}); err != nil {
		t.Fatal(err)
	}

	updates := make(chan []string, 8)
	hb := registry.NewHeartbeat(ctrl, "r1", "us", "10.0.0.1:7443", 20*time.Millisecond, nil)
	hb.OnSuccessors(func(s []string) { updates <- s })
	go hb.Run(t.Context())

	select {
	case got := <-updates:
		if !slices.Equal(got, []string{"10.0.0.2:7443"}) {
			t.Fatalf("first update = %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no successor update")
	}

	// A third relay joins; the next heartbeat must pick it up.
	if _, err := ctrl.UpsertRelay(t.Context(), &pb.UpsertRelayRequest{
		Id: "r3", Region: "us", Endpoint: "10.0.0.3:7443",
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-updates:
		if !slices.Equal(got, []string{"10.0.0.2:7443", "10.0.0.3:7443"}) {
			t.Fatalf("second update = %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no update after r3 joined")
	}
}
