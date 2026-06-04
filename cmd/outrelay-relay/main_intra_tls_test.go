// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package main

// Unit tests for verifyPeerIsRelay — the inter-relay TLS hook that
// rejects an agent-role leaf cert being accepted as a peer relay.

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"
)

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

func stateWithURIs(uris []*url.URL) tls.ConnectionState {
	leaf := &x509.Certificate{URIs: uris}
	return tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{leaf}},
	}
}

func TestVerifyPeerIsRelayAcceptsRelayURI(t *testing.T) {
	t.Parallel()
	cs := stateWithURIs([]*url.URL{mustURL(t, "outrelay://acme/relay/r-east")})
	if err := verifyPeerIsRelay(cs); err != nil {
		t.Fatalf("relay URI rejected: %v", err)
	}
}

func TestVerifyPeerIsRelayRejectsAgentURI(t *testing.T) {
	t.Parallel()
	cs := stateWithURIs([]*url.URL{
		mustURL(t, "outrelay://acme/agent/00000000-0000-0000-0000-000000000001"),
	})
	if err := verifyPeerIsRelay(cs); err == nil {
		t.Fatal("agent URI was accepted as a peer relay; want error")
	}
}

func TestVerifyPeerIsRelayRejectsNoURISAN(t *testing.T) {
	t.Parallel()
	cs := stateWithURIs(nil)
	if err := verifyPeerIsRelay(cs); err == nil {
		t.Fatal("cert without URI SAN accepted; want error")
	}
}

func TestVerifyPeerIsRelayRejectsForeignScheme(t *testing.T) {
	t.Parallel()
	cs := stateWithURIs([]*url.URL{mustURL(t, "https://example.com/relay/r1")})
	if err := verifyPeerIsRelay(cs); err == nil {
		t.Fatal("foreign-scheme URI accepted; want error")
	}
}

func TestVerifyPeerIsRelayRejectsEmptyVerifiedChain(t *testing.T) {
	t.Parallel()
	cs := tls.ConnectionState{} // no VerifiedChains
	if err := verifyPeerIsRelay(cs); err == nil {
		t.Fatal("empty chain accepted; want error")
	}
}

// TestVerifyPeerIsRelayAcceptsMultiURIWhenRelayPresent — a cert may
// carry several URI SANs; presence of any relay-role URI is enough.
func TestVerifyPeerIsRelayAcceptsMultiURIWhenRelayPresent(t *testing.T) {
	t.Parallel()
	cs := stateWithURIs([]*url.URL{
		mustURL(t, "outrelay://acme/agent/aaa"),
		mustURL(t, "outrelay://acme/relay/r-west"),
	})
	if err := verifyPeerIsRelay(cs); err != nil {
		t.Fatalf("multi-URI cert rejected when relay SAN present: %v", err)
	}
}
