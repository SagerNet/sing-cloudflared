package cloudflared

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-cloudflared/tunnelrpc"
	"github.com/sagernet/sing/common/logger"

	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"
)

type datagramVersionSender struct {
	captureDatagramSender
	version string
}

func (s *datagramVersionSender) DatagramVersion() string {
	return s.version
}

func decodeConnectResponseForTest(t *testing.T, payload []byte) *ConnectResponse {
	t.Helper()

	if len(payload) < len(dataStreamSignature)+len(protocolVersion) {
		t.Fatalf("payload too short: %x", payload)
	}
	if !bytes.Equal(payload[:len(dataStreamSignature)], dataStreamSignature[:]) {
		t.Fatalf("unexpected signature %x", payload[:len(dataStreamSignature)])
	}

	message, err := capnp.NewDecoder(bytes.NewReader(payload[len(dataStreamSignature)+len(protocolVersion):])).Decode()
	if err != nil {
		t.Fatal(err)
	}
	root, err := tunnelrpc.ReadRootConnectResponse(message)
	if err != nil {
		t.Fatal(err)
	}
	var response ConnectResponse
	if err := pogs.Extract(&response, tunnelrpc.ConnectResponse_TypeID, root.Struct); err != nil {
		t.Fatal(err)
	}
	return &response
}

func TestHandleDataStreamWritesStatusConnectResponse(t *testing.T) {
	t.Parallel()

	serviceInstance := newSpecialService(t)
	serviceInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{{
			Service: ResolvedService{Kind: ResolvedServiceStatus, StatusCode: http.StatusNoContent},
		}},
	}
	stream := &captureReadWriteCloser{}
	request := &ConnectRequest{
		Type: ConnectionTypeHTTP,
		Dest: "http://example.com/status",
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: "example.com"},
		},
	}

	serviceInstance.HandleDataStream(context.Background(), stream, request, 0)
	response := decodeConnectResponseForTest(t, stream.body)
	if response.Error != "" {
		t.Fatalf("unexpected connect response error %q", response.Error)
	}
	if response.Metadata[0].Key != metadataHTTPStatus || response.Metadata[0].Val != "204" {
		t.Fatalf("unexpected response metadata %#v", response.Metadata)
	}
}

func TestHandleDataStreamWritesUnknownConnectionTypeError(t *testing.T) {
	t.Parallel()

	serviceInstance := newSpecialService(t)
	stream := &captureReadWriteCloser{}
	request := &ConnectRequest{
		Type: ConnectionType(99),
		Dest: "ignored",
	}

	serviceInstance.HandleDataStream(context.Background(), stream, request, 0)
	response := decodeConnectResponseForTest(t, stream.body)
	if response.Error != "unknown connection type: unknown" {
		t.Fatalf("unexpected connect response error %q", response.Error)
	}
	if len(response.Metadata) != 0 {
		t.Fatalf("unexpected response metadata %#v", response.Metadata)
	}
}

func TestHandleRPCStreamWithSenderSelectsDatagramVersion(t *testing.T) {
	t.Parallel()

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.logger = logger.NOP()
	serviceInstance.datagramV2Muxers = make(map[DatagramSender]*DatagramV2Muxer)
	serviceInstance.datagramV3Muxers = make(map[DatagramSender]*DatagramV3Muxer)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	serviceInstance.HandleRPCStreamWithSender(ctx, newBlockingRPCStream(), 0, &datagramVersionSender{version: defaultDatagramVersion})
	if len(serviceInstance.datagramV2Muxers) != 1 {
		t.Fatalf("expected V2 RPC stream to create muxer, got %#v", serviceInstance.datagramV2Muxers)
	}

	ctxV3, cancelV3 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelV3()
	serviceInstance.HandleRPCStreamWithSender(ctxV3, newBlockingRPCStream(), 0, &datagramVersionSender{version: datagramVersionV3})
	if len(serviceInstance.datagramV3Muxers) != 0 {
		t.Fatalf("expected V3 RPC stream not to create V2/V3 muxers directly, got %#v", serviceInstance.datagramV3Muxers)
	}
}

func TestHandleDatagramCreatesMuxersAndRemoveDatagramMuxer(t *testing.T) {
	t.Parallel()

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.datagramV2Muxers = make(map[DatagramSender]*DatagramV2Muxer)
	serviceInstance.datagramV3Muxers = make(map[DatagramSender]*DatagramV3Muxer)
	v2Sender := &datagramVersionSender{version: defaultDatagramVersion}
	v3Sender := &datagramVersionSender{version: datagramVersionV3}

	serviceInstance.HandleDatagram(context.Background(), []byte{}, v2Sender)
	serviceInstance.HandleDatagram(context.Background(), []byte{byte(DatagramV3TypeRegistrationResponse)}, v3Sender)
	if len(serviceInstance.datagramV2Muxers) != 1 || len(serviceInstance.datagramV3Muxers) != 1 {
		t.Fatalf("unexpected muxer counts v2=%d v3=%d", len(serviceInstance.datagramV2Muxers), len(serviceInstance.datagramV3Muxers))
	}

	serviceInstance.RemoveDatagramMuxer(v2Sender)
	serviceInstance.RemoveDatagramMuxer(v3Sender)
	if len(serviceInstance.datagramV2Muxers) != 0 || len(serviceInstance.datagramV3Muxers) != 0 {
		t.Fatalf("expected muxers to be removed, got v2=%d v3=%d", len(serviceInstance.datagramV2Muxers), len(serviceInstance.datagramV3Muxers))
	}
}

func TestDatagramVersionForSenderAndStreamConn(t *testing.T) {
	t.Parallel()

	if got := datagramVersionForSender(&captureDatagramSender{}); got != defaultDatagramVersion {
		t.Fatalf("unexpected default datagram version %q", got)
	}
	if got := datagramVersionForSender(&datagramVersionSender{version: datagramVersionV3}); got != datagramVersionV3 {
		t.Fatalf("unexpected explicit datagram version %q", got)
	}

	conn := newStreamConn(&captureReadWriteCloser{})
	if conn.LocalAddr() != nil || conn.RemoteAddr() != nil {
		t.Fatal("expected nil stream conn addresses")
	}
	if err := conn.SetDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestHandleRPCStreamAndQuicResponseWriter(t *testing.T) {
	t.Parallel()

	serviceInstance := newLimitedService(t, 0)
	serviceInstance.logger = logger.NOP()
	serviceInstance.HandleRPCStream(context.Background(), newBlockingRPCStream(), 0)

	stream := &captureReadWriteCloser{}
	writer := &quicResponseWriter{stream: stream}
	if err := writer.WriteResponse(io.EOF, nil); err != nil {
		t.Fatal(err)
	}
	response := decodeConnectResponseForTest(t, stream.body)
	if response.Error != io.EOF.Error() {
		t.Fatalf("unexpected quic response error %q", response.Error)
	}
}
