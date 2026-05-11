// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package registry is the relay's view of service location.
// Authoritative state lives in the controller's registry — this
// package is a thin facade that combines (a) gRPC calls to the
// controller for the (tenant, name) -> (agent_uri, relay_id) mapping
// with (b) a local URI -> Provider map the relay uses to actually
// open INCOMING_STREAM toward the right connected agent.
package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	pb "github.com/boanlab/OutRelay/lib/control/v1"
	"github.com/boanlab/OutRelay/lib/identity"
)

var (
	ErrServiceNotFound = errors.New("registry: service not found")
	ErrProviderRemote  = errors.New("registry: provider on different relay")
)

// Provider is anything able to receive an INCOMING_STREAM dispatch.
// In production this is *edge.AgentConn; tests may inject a fake.
type Provider interface {
	AgentURI() string
	OpenIncoming(serviceName, method, callerURI string, streamID uint64) (Stream, error)
	String() string
}

// Stream is a minimal subset of transport.Stream — registry stays
// transport-agnostic.
type Stream interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// Registry is the relay's directory layer.
type Registry struct {
	ctrl    pb.RegistryClient
	relayID string
	logger  *slog.Logger
	// region is the relay instance's region label (--region flag).
	// Passed through to controller.Resolve so multi-region
	// deployments can prefer same-region providers and avoid an
	// unnecessary inter-relay hop.
	region string

	mu         sync.RWMutex
	agentConns map[string]Provider // agent URI -> conn
}

// New constructs a Registry that talks to the given controller client.
// relayID is the relay instance's identifier (typically its URI SAN);
// it is sent in every RegisterService / DeregisterAgent call so the
// controller knows where each provider lives. A nil logger disables
// logging.
func New(ctrl pb.RegistryClient, relayID, region string, logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Registry{
		ctrl:       ctrl,
		relayID:    relayID,
		region:     region,
		logger:     logger,
		agentConns: map[string]Provider{},
	}
}

// RegisterAgent records that agentURI -> p for as long as the agent
// is connected. Called by edge once HELLO completes.
func (r *Registry) RegisterAgent(uri string, p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.agentConns[uri] = p
}

// LookupAgent returns the locally connected Provider for uri, or
// nil if the agent is not on this relay. Used by candidate
// forwarding (edge.forwardCandidate) during P2P promotion.
func (r *Registry) LookupAgent(uri string) Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.agentConns[uri]
}

// UnregisterAgent removes the URI from the local map and tells the
// controller to drop all of the agent's services.
func (r *Registry) UnregisterAgent(ctx context.Context, uri string) {
	r.mu.Lock()
	delete(r.agentConns, uri)
	r.mu.Unlock()

	tenant := tenantOf(uri)
	if tenant == "" {
		r.logger.Warn("registry: deregister skipped (no tenant in uri)", "uri", uri)
		return
	}
	if _, err := r.ctrl.DeregisterAgent(ctx, &pb.DeregisterAgentRequest{
		Tenant:   tenant,
		AgentUri: uri,
		RelayId:  r.relayID,
	}); err != nil {
		r.logger.Warn("registry: controller deregister failed",
			"tenant", tenant, "uri", uri, "relay", r.relayID, "err", err)
		return
	}
	r.logger.Debug("registry: agent deregistered at controller",
		"tenant", tenant, "uri", uri)
}

// RegisterService publishes a service registration to the controller.
// The local agent_uri -> Provider map is unchanged (registered earlier
// when the connection was accepted).
func (r *Registry) RegisterService(ctx context.Context, agentURI, serviceName, localAddr string) (string, error) {
	tenant := tenantOf(agentURI)
	if tenant == "" {
		return "", fmt.Errorf("registry: cannot extract tenant from %q", agentURI)
	}
	resp, err := r.ctrl.RegisterService(ctx, &pb.RegisterServiceRequest{
		Tenant:      tenant,
		ServiceName: serviceName,
		AgentUri:    agentURI,
		RelayId:     r.relayID,
		LocalAddr:   localAddr,
	})
	if err != nil {
		return "", fmt.Errorf("registry: register: %w", err)
	}
	return resp.ServiceId, nil
}

// Remote identifies a provider on a peer relay. It is returned (along
// with ErrProviderRemote) when the resolved provider's relay_id does
// not match this relay's id, so the caller can dial the peer.
type Remote struct {
	RelayID  string
	Endpoint string
	AgentURI string
}

// Resolve asks the controller for the provider of (tenant, name) and
// returns either:
// - a local Provider plus nil error, when the provider's connection
// terminates on this relay; or
// - ErrServiceNotFound; or
// - ErrProviderRemote, in which case the second return is non-nil
// and carries the peer relay's id and endpoint so the caller
// (edge) can forward via pkg/intra.
func (r *Registry) Resolve(ctx context.Context, callerURI, name string) (Provider, *Remote, error) {
	tenant := tenantOf(callerURI)
	if tenant == "" {
		return nil, nil, fmt.Errorf("registry: cannot extract tenant from %q", callerURI)
	}
	resp, err := r.ctrl.Resolve(ctx, &pb.ResolveRequest{
		Tenant:       tenant,
		ServiceName:  name,
		CallerRegion: r.region,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("registry: resolve: %w", err)
	}
	if len(resp.Providers) == 0 {
		return nil, nil, ErrServiceNotFound
	}
	prov := resp.Providers[0]
	if prov.RelayId != r.relayID {
		return nil, &Remote{
			RelayID:  prov.RelayId,
			Endpoint: prov.RelayEndpoint,
			AgentURI: prov.AgentUri,
		}, ErrProviderRemote
	}
	r.mu.RLock()
	p, ok := r.agentConns[prov.AgentUri]
	r.mu.RUnlock()
	if !ok {
		return nil, nil, ErrServiceNotFound
	}
	return p, nil, nil
}

// tenantOf extracts the tenant segment from outrelay://<tenant>/...
func tenantOf(uri string) string {
	n, err := identity.Parse(uri)
	if err != nil {
		return ""
	}
	return n.Tenant
}
