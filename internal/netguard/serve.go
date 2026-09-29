/*
Hiten | 2026
serve.go

Shared listen and accept loop for the raw TCP decoys (SSH, FTP,
SMB, MySQL). It gives port conflicts a readable error, backs off on
accept errors instead of spinning, closes open connections when the
context ends, and waits (up to a limit) for handlers to return so
their last events are published before the queue is closed.
*/

package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

var listening sync.Map // service -> address

// Listening returns the services whose listener is open.
func Listening() map[string]string {
	out := map[string]string{}
	listening.Range(func(k, v any) bool {
		out[k.(string)] = v.(string)
		return true
	})
	return out
}

type trackedListener struct {
	net.Listener
	service string
	once    sync.Once
}

func (t *trackedListener) Close() error {
	t.once.Do(func() { listening.Delete(t.service) })
	return t.Listener.Close()
}

// Listen opens a TCP listener and explains common failures.
func Listen(service, addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		listening.Store(service, ln.Addr().String())
		return &trackedListener{Listener: ln, service: service}, nil
	}
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return nil, fmt.Errorf("%s: %s is already in use by another program; change the %s port in config.yaml or stop that program", service, addr, service)
	case errors.Is(err, syscall.EACCES):
		return nil, fmt.Errorf("%s: permission denied for %s; ports below 1024 need extra privileges, use a higher port", service, addr)
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return nil, fmt.Errorf("%s: %s is not an address on this machine; check network.honeypot_host", service, addr)
	}
	return nil, fmt.Errorf("%s: listen %s: %w", service, addr, err)
}

// Serve runs handle for each connection until ctx ends.
func Serve(ctx context.Context, ln net.Listener, grace time.Duration, logger zerolog.Logger, handle func(net.Conn)) error {
	var (
		mu    sync.Mutex
		conns = map[net.Conn]struct{}{}
		wg    sync.WaitGroup
	)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		mu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	}()

	backoff := 5 * time.Millisecond
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			logger.Warn().Err(err).Msg("accept failed")
			time.Sleep(backoff)
			if backoff < time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 5 * time.Millisecond
		mu.Lock()
		conns[conn] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logger.Error().Interface("panic", r).Msg("connection handler panicked")
				}
				_ = conn.Close()
				mu.Lock()
				delete(conns, conn)
				mu.Unlock()
			}()
			handle(conn)
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(grace):
		logger.Warn().Msg("some connection handlers did not finish before shutdown")
	}
	return nil
}
