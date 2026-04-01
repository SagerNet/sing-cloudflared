package cloudflared

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-cloudflared/tunnelrpc"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

type blockingRPCStream struct {
	closed chan struct{}
}

func newBlockingRPCStream() *blockingRPCStream {
	return &blockingRPCStream{closed: make(chan struct{})}
}

func (s *blockingRPCStream) Read(_ []byte) (int, error) {
	<-s.closed
	return 0, io.EOF
}

func (s *blockingRPCStream) Write(p []byte) (int, error) {
	return len(p), nil
}

func (s *blockingRPCStream) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

type blockingPacketDialHandler struct {
	testHandler
	entered chan struct{}
	release chan struct{}
}

func (h *blockingPacketDialHandler) DialPacket(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	select {
	case <-h.entered:
	default:
		close(h.entered)
	}

	select {
	case <-h.release:
		return newBlockingPacketConn(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func newRPCService(t *testing.T, handler Handler) *Service {
	t.Helper()

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.handler = handler
	return serviceInstance
}

func newRPCClientPair(t *testing.T, ctx context.Context) (tunnelrpc.CloudflaredServer, io.Closer, io.Closer, net.Conn, net.Conn) {
	t.Helper()

	serverSide, clientSide := net.Pipe()
	transport := safeTransport(clientSide)
	clientConn := newRPCClientConn(transport)
	client := tunnelrpc.CloudflaredServer{Client: clientConn.Bootstrap(ctx)}
	return client, clientConn, transport, serverSide, clientSide
}

func TestServeRPCStreamRespectsContextDeadline(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 0)
	stream := newBlockingRPCStream()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		ServeRPCStream(ctx, stream, serviceInstance, NewDatagramV2Muxer(serviceInstance, &captureDatagramSender{}, serviceInstance.logger), serviceInstance.logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected ServeRPCStream to exit after context deadline")
	}
}

func TestServeV3RPCStreamRespectsContextDeadline(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 0)
	stream := newBlockingRPCStream()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		ServeV3RPCStream(ctx, stream, serviceInstance, serviceInstance.logger)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected ServeV3RPCStream to exit after context deadline")
	}
}

func TestV2RPCAckAllowsConcurrentDispatch(t *testing.T) {
	t.Parallel()
	handler := &blockingPacketDialHandler{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	serviceInstance := newRPCService(t, handler)
	muxer := NewDatagramV2Muxer(serviceInstance, &captureDatagramSender{}, serviceInstance.logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, clientConn, transport, serverSide, clientSide := newRPCClientPair(t, ctx)
	defer clientConn.Close()
	defer transport.Close()
	defer clientSide.Close()

	done := make(chan struct{})
	go func() {
		ServeRPCStream(ctx, serverSide, serviceInstance, muxer, serviceInstance.logger)
		close(done)
	}()

	registerPromise := client.RegisterUdpSession(ctx, func(p tunnelrpc.SessionManager_registerUdpSession_Params) error {
		sessionID := uuid.New()
		if err := p.SetSessionId(sessionID[:]); err != nil {
			return err
		}
		if err := p.SetDstIp([]byte{127, 0, 0, 1}); err != nil {
			return err
		}
		p.SetDstPort(53)
		p.SetCloseAfterIdleHint(int64(time.Second))
		return p.SetTraceContext("")
	})

	select {
	case <-handler.entered:
	case <-time.After(time.Second):
		t.Fatal("expected register RPC to enter the blocking dial")
	}

	updateCtx, updateCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer updateCancel()
	updatePromise := client.UpdateConfiguration(updateCtx, func(p tunnelrpc.ConfigurationManager_updateConfiguration_Params) error {
		p.SetVersion(1)
		return p.SetConfig([]byte(`{"ingress":[{"service":"http_status:503"}]}`))
	})
	if _, err := updatePromise.Result().Struct(); err != nil {
		t.Fatalf("expected concurrent update RPC to succeed, got %v", err)
	}

	close(handler.release)
	if _, err := registerPromise.Result().Struct(); err != nil {
		t.Fatalf("expected register RPC to complete, got %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected ServeRPCStream to exit")
	}
}

func TestV3RPCAckAllowsConcurrentDispatch(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, clientConn, transport, serverSide, clientSide := newRPCClientPair(t, ctx)
	defer clientConn.Close()
	defer transport.Close()
	defer clientSide.Close()

	done := make(chan struct{})
	go func() {
		ServeV3RPCStream(ctx, serverSide, serviceInstance, serviceInstance.logger)
		close(done)
	}()

	serviceInstance.configManager.access.Lock()
	updatePromise := client.UpdateConfiguration(ctx, func(p tunnelrpc.ConfigurationManager_updateConfiguration_Params) error {
		p.SetVersion(1)
		return p.SetConfig([]byte(`{"ingress":[{"service":"http_status:503"}]}`))
	})

	time.Sleep(20 * time.Millisecond)

	registerCtx, registerCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer registerCancel()
	registerPromise := client.RegisterUdpSession(registerCtx, func(p tunnelrpc.SessionManager_registerUdpSession_Params) error {
		sessionID := uuid.New()
		if err := p.SetSessionId(sessionID[:]); err != nil {
			return err
		}
		if err := p.SetDstIp([]byte{127, 0, 0, 1}); err != nil {
			return err
		}
		p.SetDstPort(53)
		p.SetCloseAfterIdleHint(int64(time.Second))
		return p.SetTraceContext("")
	})

	registerResult, err := registerPromise.Result().Struct()
	if err != nil {
		t.Fatalf("expected concurrent v3 register RPC to succeed, got %v", err)
	}
	resultErr, err := registerResult.Err()
	if err != nil {
		t.Fatal(err)
	}
	if resultErr != errUnsupportedDatagramV3UDPRegistration.Error() {
		t.Fatalf("unexpected registration error %q", resultErr)
	}

	serviceInstance.configManager.access.Unlock()
	if _, err := updatePromise.Result().Struct(); err != nil {
		t.Fatalf("expected update RPC to complete, got %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected ServeV3RPCStream to exit")
	}
}
