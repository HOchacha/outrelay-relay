// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package splice_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/boanlab/outrelay-relay/pkg/splice"
)

// TestBidirectional uses two net.Pipe pairs to verify bytes flow in
// both directions through splice.Bidirectional.
func TestBidirectional(t *testing.T) {
	t.Parallel()
	// Client A <-> server A (via net.Pipe), Client B <-> server B.
	// splice connects server A and server B.
	clientA, serverA := net.Pipe()
	clientB, serverB := net.Pipe()

	go func() {
		if _, err := splice.Bidirectional(serverA, serverB); err != nil {
			t.Errorf("splice: %v", err)
		}
	}()

	// A -> B
	wantAB := []byte("ping")
	if _, err := clientA.Write(wantAB); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(wantAB))
	if _, err := io.ReadFull(clientB, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wantAB) {
		t.Fatalf("A->B: got %q want %q", got, wantAB)
	}

	// B -> A
	wantBA := []byte("pong")
	if _, err := clientB.Write(wantBA); err != nil {
		t.Fatal(err)
	}
	got2 := make([]byte, len(wantBA))
	if _, err := io.ReadFull(clientA, got2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, wantBA) {
		t.Fatalf("B->A: got %q want %q", got2, wantBA)
	}

	// Closing one side propagates EOF through splice; tear down both.
	_ = clientA.Close()
	_ = clientB.Close()

	// Allow goroutines to drain.
	time.Sleep(20 * time.Millisecond)
}

// TestBidirectionalReportsByteCount confirms the int64 return is the
// sum of bytes copied in both directions. Locks in the contract the
// relay's bytes_forwarded counter depends on. Uses TCP loopback
// (which supports CloseWrite) rather than net.Pipe so the splice's
// half-close logic mirrors production.
func TestBidirectionalReportsByteCount(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type sockPair struct {
		client net.Conn
		server net.Conn
	}
	mkPair := func() sockPair {
		accepted := make(chan net.Conn, 1)
		go func() {
			c, aerr := ln.Accept()
			if aerr != nil {
				accepted <- nil
				return
			}
			accepted <- c
		}()
		client, derr := net.Dial("tcp", ln.Addr().String())
		if derr != nil {
			t.Fatalf("dial: %v", derr)
		}
		server := <-accepted
		if server == nil {
			t.Fatal("accept failed")
		}
		return sockPair{client: client, server: server}
	}
	pa := mkPair()
	pb := mkPair()
	defer func() {
		_ = pa.client.Close()
		_ = pa.server.Close()
		_ = pb.client.Close()
		_ = pb.server.Close()
	}()

	done := make(chan struct {
		n   int64
		err error
	}, 1)
	go func() {
		n, derr := splice.Bidirectional(pa.server, pb.server)
		done <- struct {
			n   int64
			err error
		}{n, derr}
	}()

	ab := bytes.Repeat([]byte("A"), 1500)
	ba := bytes.Repeat([]byte("B"), 700)

	// Write+close in both directions; CloseWrite triggers the
	// half-close path inside splice.copyOne.
	go func() {
		_, _ = pa.client.Write(ab)
		_ = pa.client.(*net.TCPConn).CloseWrite()
	}()
	go func() {
		_, _ = pb.client.Write(ba)
		_ = pb.client.(*net.TCPConn).CloseWrite()
	}()

	gotB := make([]byte, len(ab))
	if _, err := io.ReadFull(pb.client, gotB); err != nil {
		t.Fatalf("drain B: %v", err)
	}
	gotA := make([]byte, len(ba))
	if _, err := io.ReadFull(pa.client, gotA); err != nil {
		t.Fatalf("drain A: %v", err)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("splice err: %v", r.err)
		}
		wantTotal := int64(len(ab) + len(ba))
		if r.n != wantTotal {
			t.Fatalf("total bytes: got %d want %d", r.n, wantTotal)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("splice did not return within deadline")
	}
}
