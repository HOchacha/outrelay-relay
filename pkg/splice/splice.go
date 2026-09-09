// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

// Package splice carries bytes bidirectionally between two streams
// after the relay has paired them. The relay never inspects the
// payload, just forwards bytes.
//
// The implementation uses io.CopyBuffer with a sync.Pool of 64 KiB
// buffers, one buffer per direction.
package splice

import (
	"errors"
	"io"
	"sync"
)

// BufferSize is the per-direction copy buffer.
const BufferSize = 64 * 1024

// AbortCode is the QUIC stream error code the relay uses when it
// resets the surviving side of a pair after the other side failed.
const AbortCode = 0x0A

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, BufferSize)
		return &b
	},
}

// HalfCloser is a stream that supports independent shutdown of the
// write half. quic.Stream and many net.Conn implementations satisfy
// this. We use it (when available) to propagate an EOF on one direction
// without tearing down the other.
type HalfCloser interface {
	CloseWrite() error
}

// Aborter is a stream whose both directions can be reset with an
// error code (QUIC RESET_STREAM + STOP_SENDING). quic.Stream satisfies
// it; the TCP+yamux fallback does not and degrades to CloseWrite.
type Aborter interface {
	CancelWrite(code uint64)
	CancelRead(code uint64)
}

// Bidirectional pipes a <-> b until either side EOFs or errors. It
// returns the total bytes copied across both directions (consumer→
// provider + provider→consumer) and the first non-EOF error observed,
// or nil if both directions closed cleanly.
//
// The byte total feeds the relay's bytes_forwarded counter for
// throughput observability. It counts payload bytes only — the
// 8-byte ORP frame headers consumed before splice begins are not
// included.
//
// Both streams are left to the caller to close fully — Bidirectional
// only signals half-close (CloseWrite) on the destination once the
// source EOFs, so the peer learns that no more data is coming.
func Bidirectional(a, b io.ReadWriter) (int64, error) {
	type copyResult struct {
		n   int64
		err error
	}
	resCh := make(chan copyResult, 2)
	go func() {
		n, err := copyOne(b, a)
		resCh <- copyResult{n: n, err: err}
	}() // a -> b
	go func() {
		n, err := copyOne(a, b)
		resCh <- copyResult{n: n, err: err}
	}() // b -> a

	var (
		total    int64
		firstErr error
	)
	for range 2 {
		r := <-resCh
		total += r.n
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
	}
	return total, firstErr
}

// copyOne copies src -> dst using a pooled buffer, then half-closes
// dst's write side if supported. EOF is normal completion. Returns
// the number of bytes copied even when an error follows so the caller
// can still account for partial transfers.
func copyOne(dst io.Writer, src io.Reader) (int64, error) {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)

	n, err := io.CopyBuffer(dst, src, *bufp)
	if err == nil || errors.Is(err, io.EOF) {
		// src is done for real: let dst's peer see a clean FIN.
		if hc, ok := dst.(HalfCloser); ok {
			_ = hc.CloseWrite()
		}
		return n, nil
	}
	// src (or dst) failed under us — relay-side connection loss,
	// drain, crash. The surviving peer must NOT see a FIN, which its
	// bridge would take as "application finished" and turn into a
	// tear-down of the app connection; a reset tells it the transport
	// broke, so it parks the stream and waits for STREAM_RESUME.
	if ab, ok := dst.(Aborter); ok {
		ab.CancelWrite(AbortCode)
		ab.CancelRead(AbortCode)
	} else if hc, ok := dst.(HalfCloser); ok {
		_ = hc.CloseWrite()
	}
	return n, err
}
