package cloudflared

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
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

func TestRecordConnectionFailureAutoFallbackAfterRetryBudget(t *testing.T) {
	t.Parallel()

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = ""
	serviceInstance.initializeConnectionState(0)

	for retry := uint8(1); retry < defaultProtocolRetry; retry++ {
		count, switchedProtocol, switched := serviceInstance.recordConnectionFailure(0, fmt.Errorf("quic failed %d", retry))
		if switched {
			t.Fatalf("unexpected early fallback to %q at retry %d", switchedProtocol, retry)
		}
		if count != retry {
			t.Fatalf("unexpected retry count %d at step %d", count, retry)
		}
		if state := serviceInstance.connectionState(0); state.protocol != protocolQUIC || state.retries != retry {
			t.Fatalf("unexpected state before fallback %#v", state)
		}
	}

	count, switchedProtocol, switched := serviceInstance.recordConnectionFailure(0, errors.New("quic failed"))
	if !switched || switchedProtocol != protocolHTTP2 {
		t.Fatalf("expected fallback to HTTP/2, got switched=%v protocol=%q", switched, switchedProtocol)
	}
	if count != defaultProtocolRetry {
		t.Fatalf("unexpected retry count at fallback %d", count)
	}
	if state := serviceInstance.connectionState(0); state.protocol != protocolHTTP2 || state.retries != 0 {
		t.Fatalf("unexpected state after fallback %#v", state)
	}
}

func TestRecordConnectionFailureFallsBackOnBrokenQUIC(t *testing.T) {
	t.Parallel()

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = ""
	serviceInstance.initializeConnectionState(0)

	count, switchedProtocol, switched := serviceInstance.recordConnectionFailure(0, &quic.IdleTimeoutError{})
	if !switched || switchedProtocol != protocolHTTP2 {
		t.Fatalf("expected immediate fallback on broken QUIC, got switched=%v protocol=%q", switched, switchedProtocol)
	}
	if count != 1 {
		t.Fatalf("unexpected retry count for broken QUIC fallback %d", count)
	}
}

func TestSecondConnectionInitialProtocolUsesSelectorCurrent(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = ""
	serviceInstance.notifyConnected(0, "http2")
	serviceInstance.initializeConnectionState(1)

	if state := serviceInstance.connectionState(1); state.protocol != protocolQUIC {
		t.Fatalf("expected second connection to start from selector current protocol, got %#v", state)
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
	if state.protocol != protocolQUIC {
		t.Fatalf("expected protocol to return to selector current value, got %q", state.protocol)
	}
}

func TestRecordConnectionFailureExplicitQUICHasNoFallback(t *testing.T) {
	t.Parallel()

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.protocol = protocolQUIC
	serviceInstance.initializeConnectionState(0)

	for range defaultProtocolRetry + 2 {
		_, switchedProtocol, switched := serviceInstance.recordConnectionFailure(0, errors.New("quic failed"))
		if switched {
			t.Fatalf("unexpected fallback to %q for explicit QUIC transport", switchedProtocol)
		}
	}

	if state := serviceInstance.connectionState(0); state.protocol != protocolQUIC || state.retries != defaultProtocolRetry {
		t.Fatalf("unexpected explicit QUIC state %#v", state)
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
