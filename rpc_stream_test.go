package cloudflared

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-cloudflared/internal/tunnelrpc"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

type blockingPacketDialHandler struct {
	N.Dialer
	entered chan struct{}
	release chan struct{}
}

func (h *blockingPacketDialHandler) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	select {
	case <-h.entered:
	default:
		close(h.entered)
	}

	select {
	case <-h.release:
		return bufio.NewNetPacketConn(newBlockingPacketConn()), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func newRPCService(t *testing.T, handler N.Dialer) *Service {
	t.Helper()

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.connectionDialer = handler
	return serviceInstance
}

func newRPCClientPair(t *testing.T, ctx context.Context) (tunnelrpc.CloudflaredServer, io.Closer, io.Closer, net.Conn, net.Conn) {
	t.Helper()

	serverSide, clientSide := net.Pipe()
	rpcTransport := safeTransport(clientSide)
	clientConn := newRPCClientConn(rpcTransport)
	client := tunnelrpc.CloudflaredServer{Client: clientConn.Bootstrap(ctx)}
	return client, clientConn, rpcTransport, serverSide, clientSide
}

func TestServeRPCStreamRespectsContextDeadline(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 0)
	stream := newBlockingRPCStream()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		ServeRPCStream(ctx, stream, serviceInstance.configApplier(), NewDatagramV2Muxer(serviceInstance.muxerContext(), &captureDatagramSender{}, serviceInstance.logger), serviceInstance.logger)
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
		ServeV3RPCStream(ctx, stream, serviceInstance.configApplier(), serviceInstance.logger)
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
	muxer := NewDatagramV2Muxer(serviceInstance.muxerContext(), &captureDatagramSender{}, serviceInstance.logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, clientConn, rpcTransport, serverSide, clientSide := newRPCClientPair(t, ctx)
	defer clientConn.Close()
	defer rpcTransport.Close()
	defer clientSide.Close()

	done := make(chan struct{})
	go func() {
		ServeRPCStream(ctx, serverSide, serviceInstance.configApplier(), muxer, serviceInstance.logger)
		close(done)
	}()

	registerPromise := client.RegisterUdpSession(ctx, func(p tunnelrpc.SessionManager_registerUdpSession_Params) error {
		sessionID := uuid.New()
		err := p.SetSessionId(sessionID[:])
		if err != nil {
			return err
		}
		err = p.SetDstIp([]byte{127, 0, 0, 1})
		if err != nil {
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
	_, err := updatePromise.Result().Struct()
	if err != nil {
		t.Fatalf("expected concurrent update RPC to succeed, got %v", err)
	}

	close(handler.release)
	_, err = registerPromise.Result().Struct()
	if err != nil {
		t.Fatalf("expected register RPC to complete, got %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected ServeRPCStream to exit")
	}
}
