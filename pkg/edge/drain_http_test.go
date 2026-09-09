// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package edge_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boanlab/outrelay-relay/pkg/edge"
)

// TestDrainHandlerParsesRequest: POST /debug/drain?to=a,b&reason=x&deadline=2s
// invokes the drain callback with the parsed arguments; GET and a bad
// deadline are rejected.
func TestDrainHandlerParsesRequest(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		gotTo    []string
		gotWhy   string
		gotDl    time.Duration
		called   int
		defaults = edge.DrainDefaults{Reason: "drain", Deadline: 5 * time.Second}
	)
	h := edge.DrainHandler(defaults, func(to []string, reason string, deadline time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		called++
		gotTo, gotWhy, gotDl = to, reason, deadline
	}, slog.New(slog.DiscardHandler))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/debug/drain?to=10.0.0.2:7443,10.0.0.3:7443&reason=upgrade&deadline=2s", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	mu.Lock()
	if called != 1 || !slices.Equal(gotTo, []string{"10.0.0.2:7443", "10.0.0.3:7443"}) || gotWhy != "upgrade" || gotDl != 2*time.Second {
		t.Fatalf("callback got to=%v reason=%q deadline=%v (called=%d)", gotTo, gotWhy, gotDl, called)
	}
	mu.Unlock()

	// Defaults apply when params are absent.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/debug/drain", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rec.Code)
	}
	mu.Lock()
	if called != 2 || len(gotTo) != 0 || gotWhy != "drain" || gotDl != 5*time.Second {
		t.Fatalf("defaults: to=%v reason=%q deadline=%v", gotTo, gotWhy, gotDl)
	}
	mu.Unlock()

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/drain", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/debug/drain?deadline=soon", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "deadline") {
		t.Fatalf("bad deadline: status=%d body=%s", rec.Code, rec.Body)
	}
	mu.Lock()
	defer mu.Unlock()
	if called != 2 {
		t.Fatalf("rejected requests must not drain (called=%d)", called)
	}
}
