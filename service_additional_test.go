package cloudflared

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

type closeCounter struct {
	count int
}

func (c *closeCounter) Close() error {
	c.count++
	return nil
}

func TestServiceStartCapsHAConnectionsAndStopsCleanly(t *testing.T) {
	originalDiscoverEdge := discoverEdge
	originalNewQUICConnection := newQUICConnection
	originalServeQUICConnection := serveQUICConnection
	defer func() {
		discoverEdge = originalDiscoverEdge
		newQUICConnection = originalNewQUICConnection
		serveQUICConnection = originalServeQUICConnection
	}()

	discoverEdge = func(ctx context.Context, region string, controlDialer N.Dialer) ([][]*EdgeAddr, error) {
		return [][]*EdgeAddr{{
			{TCP: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7844}, UDP: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7844}, IPVersion: 4},
			{TCP: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 7844}, UDP: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 7844}, IPVersion: 4},
		}}, nil
	}
	var capturedCallbacks []func()
	newQUICConnection = func(
		ctx context.Context,
		edgeAddr *EdgeAddr,
		connIndex uint8,
		credentials Credentials,
		connectorID uuid.UUID,
		datagramVersion string,
		features []string,
		numPreviousAttempts uint8,
		gracePeriod time.Duration,
		tunnelDialer N.Dialer,
		onConnected func(),
		log logger.ContextLogger,
	) (*QUICConnection, error) {
		capturedCallbacks = append(capturedCallbacks, onConnected)
		return &QUICConnection{}, nil
	}
	serveQUICConnection = func(connection *QUICConnection, ctx context.Context, handler StreamHandler) error {
		if len(capturedCallbacks) > 0 {
			callback := capturedCallbacks[len(capturedCallbacks)-1]
			if callback != nil {
				callback()
			}
		}
		<-ctx.Done()
		return ctx.Err()
	}

	serviceInstance := newTestService(t, testToken(t), protocolQUIC, 4)
	err := serviceInstance.Start()
	if err != nil {
		t.Fatal(err)
	}
	if serviceInstance.haConnections != 2 {
		t.Fatalf("expected HA connections to be capped to 2, got %d", serviceInstance.haConnections)
	}
	err = serviceInstance.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestServiceStartReturnsErrorWhenNoEdgesDiscovered(t *testing.T) {
	originalDiscoverEdge := discoverEdge
	defer func() {
		discoverEdge = originalDiscoverEdge
	}()
	discoverEdge = func(ctx context.Context, region string, controlDialer N.Dialer) ([][]*EdgeAddr, error) {
		return nil, nil
	}

	serviceInstance := newTestService(t, testToken(t), protocolQUIC, 1)
	err := serviceInstance.Start()
	if err == nil || err.Error() != "no edge addresses available" {
		t.Fatalf("unexpected start error %v", err)
	}
}

func TestServiceCloseClosesTrackedConnections(t *testing.T) {
	t.Parallel()

	serviceInstance := newLimitedService(t, 0)
	first := &closeCounter{}
	second := &closeCounter{}
	serviceInstance.connections = []io.Closer{first, second}
	err := serviceInstance.Close()
	if err != nil {
		t.Fatal(err)
	}
	if first.count != 1 || second.count != 1 {
		t.Fatalf("expected tracked connections to be closed once, got %d and %d", first.count, second.count)
	}
}

func TestConnectionRetryDecisionCases(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		err       error
		retry     bool
		cancelAll bool
	}{
		{err: nil, retry: false, cancelAll: false},
		{err: ErrNonRemoteManagedTunnelUnsupported, retry: false, cancelAll: true},
		{err: &permanentRegistrationError{Err: errors.New("no retry")}, retry: false, cancelAll: false},
		{err: errors.New("retry"), retry: true, cancelAll: false},
	}
	for _, testCase := range testCases {
		retry, cancelAll := connectionRetryDecision(testCase.err)
		if retry != testCase.retry || cancelAll != testCase.cancelAll {
			t.Fatalf("unexpected decision for %v: retry=%v cancelAll=%v", testCase.err, retry, cancelAll)
		}
	}
}

func TestServiceHelpers(t *testing.T) {
	t.Parallel()

	if index := initialEdgeAddrIndex(3, 2); index != 1 {
		t.Fatalf("unexpected initial edge index %d", index)
	}
	if index := rotateEdgeAddrIndex(1, 3); index != 2 {
		t.Fatalf("unexpected rotated edge index %d", index)
	}
	if got := effectiveHAConnections(4, 2); got != 2 {
		t.Fatalf("unexpected effective HA %d", got)
	}

	regions := [][]*EdgeAddr{
		{{UDP: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:1"))}},
		{{UDP: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:2"))}},
	}
	if flattened := flattenRegions(regions); len(flattened) != 2 {
		t.Fatalf("unexpected flattened regions %#v", flattened)
	}

	backoff := backoffDuration(20)
	if backoff < backoffMaxTime/2 || backoff > backoffMaxTime {
		t.Fatalf("unexpected bounded backoff %v", backoff)
	}
}

func TestContextWithNewIDRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := contextWithNewID(context.Background())
	id, loaded := ContextIDFrom(ctx)
	if !loaded || id.ID == 0 || id.CreatedAt.IsZero() {
		t.Fatalf("expected context id, got %#v loaded=%v", id, loaded)
	}
}
