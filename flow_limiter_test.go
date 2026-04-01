package cloudflared

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/google/uuid"
)

type captureConnectMetadataWriter struct {
	err      error
	metadata []Metadata
}

func (w *captureConnectMetadataWriter) WriteResponse(responseError error, metadata []Metadata) error {
	w.err = responseError
	w.metadata = append([]Metadata(nil), metadata...)
	return nil
}

func newLimitedService(t *testing.T, limit uint64) *Service {
	t.Helper()
	configManager, err := NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	config := configManager.Snapshot()
	config.WarpRouting.MaxActiveFlows = limit
	configManager.activeConfig = config
	return &Service{
		ctx:                 ctx,
		cancel:              cancel,
		logger:              logger.NOP(),
		configManager:       configManager,
		flowLimiter:         &FlowLimiter{},
		datagramV3Manager:   NewDatagramV3SessionManager(),
		connectionStates:    make([]connectionState, 1),
		successfulProtocols: make(map[string]struct{}),
		directTransports:    make(map[string]*http.Transport),
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

	limiter := &FlowLimiter{}
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

	unlimited := &FlowLimiter{}
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
	if !hasFlowConnectRateLimited(respWriter.metadata) {
		t.Fatal("expected flow rate limit metadata")
	}
}

func TestHTTP2ResponseWriterFlowRateLimitedMeta(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	writer := &http2ResponseWriter{
		writer:  recorder,
		flusher: recorder,
	}

	err := writer.WriteResponse(context.DeadlineExceeded, flowConnectRateLimitedMetadata())
	if err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("expected %d, got %d", http.StatusBadGateway, recorder.Code)
	}
	if meta := recorder.Header().Get(h2HeaderResponseMeta); meta != h2ResponseMetaCloudflaredLimited {
		t.Fatalf("unexpected response meta: %q", meta)
	}
}

func TestDatagramV2RegisterSessionRespectsMaxActiveFlows(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 1)
	if !serviceInstance.flowLimiter.Acquire(1) {
		t.Fatal("failed to pre-acquire limiter")
	}
	muxer := NewDatagramV2Muxer(serviceInstance, &captureDatagramSender{}, serviceInstance.logger)
	err := muxer.RegisterSession(context.Background(), uuidTest(1), net.IPv4(1, 1, 1, 1), 53, 0)
	if err == nil {
		t.Fatal("expected too many active flows error")
	}
}

func TestDatagramV3RegistrationTooManyActiveFlows(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 1)
	if !serviceInstance.flowLimiter.Acquire(1) {
		t.Fatal("failed to pre-acquire limiter")
	}
	sender := &captureDatagramSender{}
	muxer := NewDatagramV3Muxer(serviceInstance, sender, serviceInstance.logger)

	requestID := RequestID{}
	requestID[15] = 1
	payload := make([]byte, 1+1+2+2+16+4)
	payload[0] = 0
	binary.BigEndian.PutUint16(payload[1:3], 53)
	binary.BigEndian.PutUint16(payload[3:5], 30)
	copy(payload[5:21], requestID[:])
	copy(payload[21:25], []byte{1, 1, 1, 1})

	muxer.handleRegistration(context.Background(), payload)
	if len(sender.sent) != 1 {
		t.Fatalf("expected one registration response, got %d", len(sender.sent))
	}
	if sender.sent[0][0] != byte(DatagramV3TypeRegistrationResponse) || sender.sent[0][1] != v3ResponseTooManyActiveFlows {
		t.Fatalf("unexpected v3 response: %v", sender.sent[0])
	}
}

func uuidTest(last byte) uuid.UUID {
	var value uuid.UUID
	value[15] = last
	return value
}
