package cloudflared

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-cloudflared/tunnelrpc"

	"github.com/google/uuid"
	capnp "zombiezen.com/go/capnproto2"
)

func newRegisterUDPSessionCall(t *testing.T, traceContext string) (tunnelrpc.SessionManager_registerUdpSession, func() (tunnelrpc.RegisterUdpSessionResponse, error)) {
	return newRegisterUDPSessionCallWithDstIP(t, []byte{127, 0, 0, 1}, traceContext)
}

func newRegisterUDPSessionCallWithDstIP(t *testing.T, dstIP []byte, traceContext string) (tunnelrpc.SessionManager_registerUdpSession, func() (tunnelrpc.RegisterUdpSessionResponse, error)) {
	t.Helper()

	_, paramsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	params, err := tunnelrpc.NewSessionManager_registerUdpSession_Params(paramsSeg)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	if err := params.SetSessionId(sessionID[:]); err != nil {
		t.Fatal(err)
	}
	if err := params.SetDstIp(dstIP); err != nil {
		t.Fatal(err)
	}
	params.SetDstPort(53)
	params.SetCloseAfterIdleHint(int64(30))
	if err := params.SetTraceContext(traceContext); err != nil {
		t.Fatal(err)
	}

	_, resultsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	results, err := tunnelrpc.NewSessionManager_registerUdpSession_Results(resultsSeg)
	if err != nil {
		t.Fatal(err)
	}

	call := tunnelrpc.SessionManager_registerUdpSession{
		Ctx:     context.Background(),
		Params:  params,
		Results: results,
	}
	return call, results.Result
}

func newUnregisterUDPSessionCall(t *testing.T) tunnelrpc.SessionManager_unregisterUdpSession {
	t.Helper()

	_, paramsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	params, err := tunnelrpc.NewSessionManager_unregisterUdpSession_Params(paramsSeg)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	if err := params.SetSessionId(sessionID[:]); err != nil {
		t.Fatal(err)
	}
	if err := params.SetMessage("close"); err != nil {
		t.Fatal(err)
	}

	_, resultsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	results, err := tunnelrpc.NewSessionManager_unregisterUdpSession_Results(resultsSeg)
	if err != nil {
		t.Fatal(err)
	}

	return tunnelrpc.SessionManager_unregisterUdpSession{
		Ctx:     context.Background(),
		Params:  params,
		Results: results,
	}
}

func newUnregisterUDPSessionCallForSession(t *testing.T, sessionID uuid.UUID, message string) tunnelrpc.SessionManager_unregisterUdpSession {
	t.Helper()

	_, paramsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	params, err := tunnelrpc.NewSessionManager_unregisterUdpSession_Params(paramsSeg)
	if err != nil {
		t.Fatal(err)
	}
	if err := params.SetSessionId(sessionID[:]); err != nil {
		t.Fatal(err)
	}
	if err := params.SetMessage(message); err != nil {
		t.Fatal(err)
	}

	_, resultsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	results, err := tunnelrpc.NewSessionManager_unregisterUdpSession_Results(resultsSeg)
	if err != nil {
		t.Fatal(err)
	}

	return tunnelrpc.SessionManager_unregisterUdpSession{
		Ctx:     context.Background(),
		Params:  params,
		Results: results,
	}
}

func TestV3RPCRegisterUDPSessionReturnsUnsupportedResult(t *testing.T) {
	t.Parallel()
	server := &cloudflaredV3Server{
		service: &Service{},
	}
	call, readResult := newRegisterUDPSessionCall(t, "trace-context")
	if err := server.RegisterUdpSession(call); err != nil {
		t.Fatal(err)
	}

	result, err := readResult()
	if err != nil {
		t.Fatal(err)
	}
	resultErr, err := result.Err()
	if err != nil {
		t.Fatal(err)
	}
	if resultErr != errUnsupportedDatagramV3UDPRegistration.Error() {
		t.Fatalf("unexpected registration error %q", resultErr)
	}
	spans, err := result.Spans()
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 0 {
		t.Fatalf("expected empty spans, got %x", spans)
	}
}

func TestV3RPCUnregisterUDPSessionReturnsUnsupportedError(t *testing.T) {
	t.Parallel()
	server := &cloudflaredV3Server{
		service: &Service{},
	}
	err := server.UnregisterUdpSession(newUnregisterUDPSessionCall(t))
	if err == nil {
		t.Fatal("expected unsupported unregister error")
	}
	if err.Error() != errUnsupportedDatagramV3UDPUnregistration.Error() {
		t.Fatalf("unexpected unregister error %v", err)
	}
}

func TestV2RPCUnregisterUDPSessionPropagatesMessage(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.handler = &packetDialingHandler{packetConn: newBlockingPacketConn()}
	muxer := NewDatagramV2Muxer(serviceInstance, &captureDatagramSender{}, serviceInstance.logger)

	sessionID := uuid.New()
	if err := muxer.RegisterSession(context.Background(), sessionID, net.IPv4(127, 0, 0, 1), 53, time.Second); err != nil {
		t.Fatal(err)
	}
	muxer.sessionAccess.RLock()
	session := muxer.sessions[sessionID]
	muxer.sessionAccess.RUnlock()
	if session == nil {
		t.Fatal("expected registered session")
	}

	server := &cloudflaredServer{
		service: serviceInstance,
		muxer:   muxer,
		ctx:     context.Background(),
		logger:  serviceInstance.logger,
	}
	if err := server.UnregisterUdpSession(newUnregisterUDPSessionCallForSession(t, sessionID, "edge close")); err != nil {
		t.Fatal(err)
	}
	if reason := session.closeReason(); reason != "edge close" {
		t.Fatalf("expected close reason propagated from edge, got %q", reason)
	}
}

func TestV2RPCRegisterUDPSessionRejectsMissingDestinationIP(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.handler = &packetDialingHandler{packetConn: newBlockingPacketConn()}
	server := &cloudflaredServer{
		service: serviceInstance,
		muxer:   NewDatagramV2Muxer(serviceInstance, &captureDatagramSender{}, serviceInstance.logger),
		ctx:     context.Background(),
		logger:  serviceInstance.logger,
	}
	call, readResult := newRegisterUDPSessionCallWithDstIP(t, nil, "")

	if err := server.RegisterUdpSession(call); err != nil {
		t.Fatal(err)
	}

	result, err := readResult()
	if err != nil {
		t.Fatal(err)
	}
	resultErr, err := result.Err()
	if err != nil {
		t.Fatal(err)
	}
	if resultErr != "missing destination IP" {
		t.Fatalf("unexpected result error %q", resultErr)
	}
}
