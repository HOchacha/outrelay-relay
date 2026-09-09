// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package registry

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	pb "github.com/boanlab/OutRelay/lib/control/v1"
)

// DefaultHeartbeatPeriod is how often a relay re-upserts itself with
// the controller and refreshes its view of the fleet. Must stay well
// under the controller's RelayLivenessWindow.
const DefaultHeartbeatPeriod = 30 * time.Second

// Successors derives the ordered fallback list this relay advertises
// to agents from a controller fleet snapshot: every relay but self,
// same-region relays first, each group sorted by id so all relays in
// a region produce the same order for the same fleet (determinism
// matters: both halves of a stream must agree on the list, and they
// may have been told it by the same relay at different heartbeats).
func Successors(selfID, region string, fleet []*pb.RelayInstance) []string {
	var same, other []*pb.RelayInstance
	for _, r := range fleet {
		if r.Id == selfID || r.Endpoint == "" {
			continue
		}
		if r.Region == region {
			same = append(same, r)
		} else {
			other = append(other, r)
		}
	}
	byID := func(a, b *pb.RelayInstance) int {
		if a.Id < b.Id {
			return -1
		}
		if a.Id > b.Id {
			return 1
		}
		return 0
	}
	slices.SortFunc(same, byID)
	slices.SortFunc(other, byID)
	out := make([]string, 0, len(same)+len(other))
	for _, r := range same {
		out = append(out, r.Endpoint)
	}
	for _, r := range other {
		out = append(out, r.Endpoint)
	}
	return out
}

// Heartbeat periodically upserts this relay with the controller and
// turns the returned fleet snapshot into a successor list. Consumers
// (edge.Server.SetSuccessors) subscribe via OnSuccessors and are
// called only when the list changes.
type Heartbeat struct {
	ctrl     pb.RegistryClient
	id       string
	region   string
	endpoint string
	period   time.Duration
	logger   *slog.Logger

	mu   sync.Mutex
	last []string
	subs []func([]string)
}

// NewHeartbeat configures (but does not start) a heartbeat loop.
// period <= 0 selects DefaultHeartbeatPeriod.
func NewHeartbeat(ctrl pb.RegistryClient, id, region, endpoint string, period time.Duration, logger *slog.Logger) *Heartbeat {
	if period <= 0 {
		period = DefaultHeartbeatPeriod
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Heartbeat{ctrl: ctrl, id: id, region: region, endpoint: endpoint, period: period, logger: logger}
}

// OnSuccessors registers fn to be called with the new successor list
// each time it changes. Safe to call before Run.
func (h *Heartbeat) OnSuccessors(fn func([]string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subs = append(h.subs, fn)
}

// Run beats immediately, then every period, until ctx is done. A
// failed upsert is logged and retried at the next tick; the previous
// successor list stays in effect meanwhile.
func (h *Heartbeat) Run(ctx context.Context) {
	h.beat(ctx)
	t := time.NewTicker(h.period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.beat(ctx)
		}
	}
}

func (h *Heartbeat) beat(ctx context.Context) {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := h.ctrl.UpsertRelay(callCtx, &pb.UpsertRelayRequest{
		Id: h.id, Region: h.region, Endpoint: h.endpoint,
	})
	if err != nil {
		h.logger.Warn("relay heartbeat: upsert failed", "relay_id", h.id, "err", err)
		return
	}
	next := Successors(h.id, h.region, resp.Relays)

	h.mu.Lock()
	changed := !slices.Equal(next, h.last)
	if changed {
		h.last = next
	}
	subs := slices.Clone(h.subs)
	h.mu.Unlock()
	if !changed {
		return
	}
	h.logger.Info("relay heartbeat: successor list changed",
		"relay_id", h.id, "fleet", len(resp.Relays), "successors", next)
	for _, fn := range subs {
		fn(slices.Clone(next))
	}
}
