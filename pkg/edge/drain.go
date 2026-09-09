// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// DrainDefaults are the GOAWAY parameters used when an operator
// trigger (SIGTERM, POST /debug/drain) does not specify its own.
type DrainDefaults struct {
	// Targets overrides the successor list; empty = advertised successors.
	Targets []string
	Reason  string
	// Deadline is how long agents get to leave before the relay closes
	// their links.
	Deadline time.Duration
}

// DrainFunc is what DrainHandler invokes; in production it wraps
// Server.Drain in a goroutine so the HTTP request returns at once.
type DrainFunc func(targets []string, reason string, deadline time.Duration)

// DrainHandler is the operator entry point for a planned relocation:
//
//	POST /debug/drain?to=host:port[,host:port...]&reason=<word>&deadline=<duration>
//
// All parameters are optional and fall back to defaults. The request
// is accepted (202) as soon as the drain has been started; progress
// is visible in the relay log.
func DrainHandler(defaults DrainDefaults, drain DrainFunc, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		targets := defaults.Targets
		if raw := strings.TrimSpace(q.Get("to")); raw != "" {
			targets = nil
			for _, ep := range strings.Split(raw, ",") {
				if ep = strings.TrimSpace(ep); ep != "" {
					targets = append(targets, ep)
				}
			}
		}
		reason := defaults.Reason
		if v := q.Get("reason"); v != "" {
			reason = v
		}
		deadline := defaults.Deadline
		if v := q.Get("deadline"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				http.Error(w, fmt.Sprintf("bad deadline %q: want a positive Go duration", v), http.StatusBadRequest)
				return
			}
			deadline = d
		}
		logger.Info("edge: drain requested via HTTP",
			"remote", r.RemoteAddr, "targets", targets, "reason", reason, "deadline", deadline)
		drain(targets, reason, deadline)
		// The parsed arguments are logged above, not echoed back: the
		// body stays a fixed string so nothing request-derived is
		// reflected into the response.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "draining\n")
	})
}
