// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package policy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	pb "github.com/boanlab/OutRelay/lib/control/v1"
)

// Watcher subscribes to the controller's Policy.Watch and keeps the
// engine + cache in sync. Reconnects with backoff on stream errors.
type Watcher struct {
	client pb.PolicyClient
	tenant string
	engine *Engine
	cache  *Cache
	logger *slog.Logger
}

func NewWatcher(client pb.PolicyClient, tenant string, engine *Engine, cache *Cache, logger *slog.Logger) *Watcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Watcher{client: client, tenant: tenant, engine: engine, cache: cache, logger: logger}
}

// Run blocks until ctx cancels. On stream errors it sleeps with a
// fixed backoff and retries.
func (w *Watcher) Run(ctx context.Context) error {
	const backoff = 2 * time.Second
	for {
		if err := w.runOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Warn("policy watch stream error", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}

func (w *Watcher) runOnce(ctx context.Context) error {
	w.logger.Debug("policy: opening watch stream", "tenant", w.tenant)
	stream, err := w.client.Watch(ctx, &pb.WatchPoliciesRequest{Tenant: w.tenant})
	if err != nil {
		w.logger.Warn("policy: watch open failed", "tenant", w.tenant, "err", err)
		return err
	}
	// Accumulate the initial snapshot, then bulk-Set so we don't flap
	// the engine for every rule.
	var pending []*Rule
	inSnapshot := true
	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			w.logger.Info("policy: watch stream closed (EOF)", "tenant", w.tenant)
			return nil
		}
		if err != nil {
			return err
		}
		switch ev.Kind {
		case pb.PolicyEvent_POLICY_KIND_ADDED:
			if ev.Rule == nil {
				continue
			}
			if inSnapshot {
				pending = append(pending, FromPB(ev.Rule))
			} else {
				w.logger.Debug("policy: rule added (live)",
					"tenant", w.tenant, "rule_id", ev.Rule.Id)
				w.engine.Add(FromPB(ev.Rule))
				w.cache.Flush()
			}
		case pb.PolicyEvent_POLICY_KIND_REMOVED:
			if ev.RemovedId == "" {
				continue
			}
			w.logger.Debug("policy: rule removed (live)",
				"tenant", w.tenant, "rule_id", ev.RemovedId)
			w.engine.Remove(ev.RemovedId)
			w.cache.Flush()
		case pb.PolicyEvent_POLICY_KIND_SNAPSHOT_END:
			w.logger.Info("policy: snapshot applied",
				"tenant", w.tenant, "rule_count", len(pending))
			w.engine.Set(pending)
			w.cache.Flush()
			pending = nil
			inSnapshot = false
		}
	}
}
