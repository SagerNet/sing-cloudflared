package cloudflared

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/sagernet/sing-cloudflared/internal/config"
	"github.com/sagernet/sing-cloudflared/internal/datagram"
	"github.com/sagernet/sing-cloudflared/internal/protocol"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/google/uuid"
)

type captureConnectMetadataWriter struct {
	err      error
	metadata []protocol.Metadata
}

func (w *captureConnectMetadataWriter) WriteResponse(responseError error, metadata []protocol.Metadata) error {
	w.err = responseError
	w.metadata = append([]protocol.Metadata(nil), metadata...)
	return nil
}

func newLimitedService(t *testing.T, limit uint64) *Service {
	t.Helper()
	configManager, err := config.NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	configJSON := fmt.Sprintf(`{"ingress":[{"service":"http_status:503"}],"warp-routing":{"maxActiveFlows":%d}}`, limit)
	configManager.Apply(1, []byte(configJSON))
	return &Service{
		ctx:               ctx,
		cancel:            cancel,
		logger:            logger.NOP(),
		configManager:     configManager,
		flowLimiter:       &datagram.FlowLimiter{},
		datagramV3Manager: datagram.NewDatagramV3SessionManager(),
		connectionStates:  make([]connectionState, 1),
		directTransports:  make(map[string]*http.Transport),
	}
}

func TestHandleTCPStreamRespectsMaxActiveFlows(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 1)
	if !serviceInstance.flowLimiter.Acquire(1) {
		t.Fatal("failed to pre-acquire limiter")
	}

	stream, peer := net.Pipe()
	defer stream.Close()
	defer peer.Close()
	respWriter := &fakeConnectResponseWriter{}
	serviceInstance.handleTCPStream(context.Background(), stream, respWriter, M.ParseSocksaddr("127.0.0.1:80"))
	if respWriter.err == nil {
		t.Fatal("expected too many active flows error")
	}
}

func TestFlowLimiterReleaseCases(t *testing.T) {
	t.Parallel()

	limiter := &datagram.FlowLimiter{}
	if !limiter.Acquire(1) {
		t.Fatal("expected initial acquire to succeed")
	}
	limiter.Release(1)
	if !limiter.Acquire(1) {
		t.Fatal("expected acquire to succeed after release")
	}
	limiter.Release(1)
	limiter.Release(1)
	if !limiter.Acquire(1) {
		t.Fatal("expected extra release not to underflow limiter state")
	}

	unlimited := &datagram.FlowLimiter{}
	if !unlimited.Acquire(0) {
		t.Fatal("expected unlimited acquire to succeed")
	}
	unlimited.Release(0)
	if !unlimited.Acquire(0) {
		t.Fatal("expected unlimited acquire to remain unaffected after release")
	}
}

func TestHandleTCPStreamRateLimitMetadata(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 1)
	if !serviceInstance.flowLimiter.Acquire(1) {
		t.Fatal("failed to pre-acquire limiter")
	}

	stream, peer := net.Pipe()
	defer stream.Close()
	defer peer.Close()

	respWriter := &captureConnectMetadataWriter{}
	serviceInstance.handleTCPStream(context.Background(), stream, respWriter, M.ParseSocksaddr("127.0.0.1:80"))
	if respWriter.err == nil {
		t.Fatal("expected too many active flows error")
	}
	if !protocol.HasFlowConnectRateLimited(respWriter.metadata) {
		t.Fatal("expected flow rate limit metadata")
	}
}

func TestDatagramV2RegisterSessionRespectsMaxActiveFlows(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 1)
	if !serviceInstance.flowLimiter.Acquire(1) {
		t.Fatal("failed to pre-acquire limiter")
	}
	muxer := datagram.NewDatagramV2Muxer(serviceInstance.muxerContext(), &captureDatagramSender{}, serviceInstance.logger)
	err := muxer.RegisterSession(context.Background(), uuidTest(1), net.IPv4(1, 1, 1, 1), 53, 0)
	if err == nil {
		t.Fatal("expected too many active flows error")
	}
}

func uuidTest(last byte) uuid.UUID {
	var value uuid.UUID
	value[15] = last
	return value
}
