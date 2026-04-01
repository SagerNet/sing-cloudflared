package cloudflared

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

var connectionHookAccess sync.Mutex

func restoreConnectionHooks(t *testing.T) {
	t.Helper()

	connectionHookAccess.Lock()
	originalNewQUICConnection := newQUICConnection
	originalNewHTTP2Connection := newHTTP2Connection
	originalServeQUICConnection := serveQUICConnection
	originalServeHTTP2Connection := serveHTTP2Connection
	t.Cleanup(func() {
		newQUICConnection = originalNewQUICConnection
		newHTTP2Connection = originalNewHTTP2Connection
		serveQUICConnection = originalServeQUICConnection
		serveHTTP2Connection = originalServeHTTP2Connection
		connectionHookAccess.Unlock()
	})
}

func TestServeConnectionAutoFallbackSticky(t *testing.T) {
	t.Parallel()
	restoreConnectionHooks(t)

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = ""
	serviceInstance.initializeConnectionState(0)

	var quicCalls, http2Calls int
	newQUICConnection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, string, []string, uint8, time.Duration, N.Dialer, func(), logger.ContextLogger) (*QUICConnection, error) {
		quicCalls++
		return &QUICConnection{}, nil
	}
	serveQUICConnection = func(*QUICConnection, context.Context, StreamHandler) error {
		return errors.New("quic failed")
	}
	newHTTP2Connection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, []string, uint8, time.Duration, *Service, logger.ContextLogger) (*HTTP2Connection, error) {
		http2Calls++
		return &HTTP2Connection{}, nil
	}
	serveHTTP2Connection = func(*HTTP2Connection, context.Context) error {
		return errors.New("http2 failed")
	}

	if err := serviceInstance.serveConnection(0, &EdgeAddr{}); err == nil || err.Error() != "http2 failed" {
		t.Fatalf("expected HTTP/2 fallback error, got %v", err)
	}
	if state := serviceInstance.connectionState(0); state.protocol != "http2" {
		t.Fatalf("expected sticky HTTP/2 fallback, got %#v", state)
	}

	if err := serviceInstance.serveConnection(0, &EdgeAddr{}); err == nil || err.Error() != "http2 failed" {
		t.Fatalf("expected second HTTP/2 error, got %v", err)
	}
	if quicCalls != 1 {
		t.Fatalf("expected QUIC to be attempted once, got %d", quicCalls)
	}
	if http2Calls != 2 {
		t.Fatalf("expected HTTP/2 to be attempted twice, got %d", http2Calls)
	}
}

func TestSecondConnectionInitialProtocolUsesFirstSuccess(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = ""

	serviceInstance.notifyConnected(0, "http2")
	serviceInstance.initializeConnectionState(1)

	if state := serviceInstance.connectionState(1); state.protocol != "http2" {
		t.Fatalf("expected second connection to inherit HTTP/2, got %#v", state)
	}
}

func TestServeConnectionSkipsFallbackWhenQUICAlreadySucceeded(t *testing.T) {
	t.Parallel()
	restoreConnectionHooks(t)

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = ""
	serviceInstance.notifyConnected(0, "quic")
	serviceInstance.initializeConnectionState(1)

	var http2Calls int
	quicErr := errors.New("quic failed")
	newQUICConnection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, string, []string, uint8, time.Duration, N.Dialer, func(), logger.ContextLogger) (*QUICConnection, error) {
		return &QUICConnection{}, nil
	}
	serveQUICConnection = func(*QUICConnection, context.Context, StreamHandler) error {
		return quicErr
	}
	newHTTP2Connection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, []string, uint8, time.Duration, *Service, logger.ContextLogger) (*HTTP2Connection, error) {
		http2Calls++
		return &HTTP2Connection{}, nil
	}

	err := serviceInstance.serveConnection(1, &EdgeAddr{})
	if !errors.Is(err, quicErr) {
		t.Fatalf("expected QUIC error without fallback, got %v", err)
	}
	if http2Calls != 0 {
		t.Fatalf("expected no HTTP/2 fallback, got %d calls", http2Calls)
	}
	if state := serviceInstance.connectionState(1); state.protocol != "quic" {
		t.Fatalf("expected connection to remain on QUIC, got %#v", state)
	}
}

func TestNotifyConnectedResetsRetries(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = ""
	serviceInstance.initializeConnectionState(0)
	serviceInstance.incrementConnectionRetries(0)
	serviceInstance.incrementConnectionRetries(0)

	serviceInstance.notifyConnected(0, "http2")

	state := serviceInstance.connectionState(0)
	if state.retries != 0 {
		t.Fatalf("expected retries reset after success, got %d", state.retries)
	}
	if state.protocol != "http2" {
		t.Fatalf("expected protocol to be pinned to success, got %q", state.protocol)
	}
}

func TestNotifyConnectedSignalsOnlyOncePerConnection(t *testing.T) {
	t.Parallel()

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.connectedNotify = make(chan uint8, 2)
	serviceInstance.connectedIndices = make(map[uint8]struct{})

	serviceInstance.notifyConnected(0, "http2")
	serviceInstance.notifyConnected(0, "http2")

	select {
	case connected := <-serviceInstance.connectedNotify:
		if connected != 0 {
			t.Fatalf("unexpected connected index %d", connected)
		}
	case <-time.After(time.Second):
		t.Fatal("expected first connected notification")
	}

	select {
	case duplicate := <-serviceInstance.connectedNotify:
		t.Fatalf("unexpected duplicate notification %d", duplicate)
	default:
	}
}

func TestSafeServeConnectionRecoversPanic(t *testing.T) {
	t.Parallel()
	restoreConnectionHooks(t)

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = "quic"
	serviceInstance.initializeConnectionState(0)

	newQUICConnection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, string, []string, uint8, time.Duration, N.Dialer, func(), logger.ContextLogger) (*QUICConnection, error) {
		return &QUICConnection{}, nil
	}
	serveQUICConnection = func(*QUICConnection, context.Context, StreamHandler) error {
		panic("boom")
	}

	err := serviceInstance.safeServeConnection(0, &EdgeAddr{})
	if err == nil || !strings.Contains(err.Error(), "panic in serve connection") {
		t.Fatalf("expected recovered panic error, got %v", err)
	}
}

func TestSuperviseConnectionStopsOnPermanentRegistrationError(t *testing.T) {
	t.Parallel()
	restoreConnectionHooks(t)

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = "quic"
	serviceInstance.initializeConnectionState(0)

	permanentErr := &permanentRegistrationError{Err: errors.New("permanent register error")}
	newQUICConnection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, string, []string, uint8, time.Duration, N.Dialer, func(), logger.ContextLogger) (*QUICConnection, error) {
		return &QUICConnection{}, nil
	}
	serveQUICConnection = func(*QUICConnection, context.Context, StreamHandler) error {
		return permanentErr
	}

	serviceInstance.done.Add(1)
	done := make(chan struct{})
	go func() {
		serviceInstance.superviseConnection(0, []*EdgeAddr{{}})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected connection supervision to stop")
	}

	if retries := serviceInstance.connectionState(0).retries; retries != 0 {
		t.Fatalf("expected no retries for permanent registration error, got %d", retries)
	}

	select {
	case <-serviceInstance.ctx.Done():
		t.Fatal("expected permanent registration error to stop only this connection")
	default:
	}
}

func TestSuperviseConnectionCancelsServiceOnNonRemoteManagedError(t *testing.T) {
	t.Parallel()
	restoreConnectionHooks(t)

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = "quic"
	serviceInstance.initializeConnectionState(0)

	newQUICConnection = func(context.Context, *EdgeAddr, uint8, Credentials, uuid.UUID, string, []string, uint8, time.Duration, N.Dialer, func(), logger.ContextLogger) (*QUICConnection, error) {
		return &QUICConnection{}, nil
	}
	serveQUICConnection = func(*QUICConnection, context.Context, StreamHandler) error {
		return ErrNonRemoteManagedTunnelUnsupported
	}

	serviceInstance.done.Add(1)
	done := make(chan struct{})
	go func() {
		serviceInstance.superviseConnection(0, []*EdgeAddr{{}})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected connection supervision to stop")
	}

	select {
	case <-serviceInstance.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected service cancellation on non-remote-managed tunnel error")
	}
}

func TestSuperviseConnectionUsesRetryableDelayAndRotatesEdges(t *testing.T) {
	t.Parallel()
	restoreConnectionHooks(t)

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = "quic"
	serviceInstance.initializeConnectionState(0)

	edge1 := &EdgeAddr{}
	edge2 := &EdgeAddr{}
	attempts := make(chan *EdgeAddr, 3)

	var serveCalls int
	serveQUICConnection = func(*QUICConnection, context.Context, StreamHandler) error {
		serveCalls++
		switch serveCalls {
		case 1, 2:
			return &RetryableError{Err: errors.New("retry"), Delay: 20 * time.Millisecond}
		default:
			serviceInstance.cancel()
			return context.Canceled
		}
	}
	newQUICConnection = func(ctx context.Context, edgeAddr *EdgeAddr, connIndex uint8, credentials Credentials, connectorID uuid.UUID, datagramVersion string, features []string, numPreviousAttempts uint8, gracePeriod time.Duration, tunnelDialer N.Dialer, onConnected func(), log logger.ContextLogger) (*QUICConnection, error) {
		attempts <- edgeAddr
		return &QUICConnection{}, nil
	}

	serviceInstance.done.Add(1)
	done := make(chan struct{})
	started := time.Now()
	go func() {
		serviceInstance.superviseConnection(0, []*EdgeAddr{edge1, edge2})
		close(done)
	}()

	var sequence []*EdgeAddr
	for expected := range 3 {
		select {
		case edgeAddr := <-attempts:
			sequence = append(sequence, edgeAddr)
			if expected == 1 && time.Since(started) > 500*time.Millisecond {
				t.Fatalf("expected retryable delay override to retry quickly, elapsed=%v", time.Since(started))
			}
		case <-time.After(time.Second):
			t.Fatalf("expected connection attempt %d", expected+1)
		}
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected supervision loop to stop after cancellation")
	}

	if len(sequence) != 3 || sequence[0] != edge1 || sequence[1] != edge2 || sequence[2] != edge1 {
		t.Fatalf("unexpected edge rotation sequence %#v", sequence)
	}
	if retries := serviceInstance.connectionState(0).retries; retries != 2 {
		t.Fatalf("expected two recorded retries, got %d", retries)
	}
}
