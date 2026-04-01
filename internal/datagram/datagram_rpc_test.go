package datagram

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-cloudflared/internal/protocol"
	"github.com/sagernet/sing-cloudflared/internal/tunnelrpc"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

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
	err = params.SetSessionId(sessionID[:])
	if err != nil {
		t.Fatal(err)
	}
	err = params.SetDstIp(dstIP)
	if err != nil {
		t.Fatal(err)
	}
	params.SetDstPort(53)
	params.SetCloseAfterIdleHint(int64(30))
	err = params.SetTraceContext(traceContext)
	if err != nil {
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
	err = params.SetSessionId(sessionID[:])
	if err != nil {
		t.Fatal(err)
	}
	err = params.SetMessage("close")
	if err != nil {
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
	err = params.SetSessionId(sessionID[:])
	if err != nil {
		t.Fatal(err)
	}
	err = params.SetMessage(message)
	if err != nil {
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
	server := &CloudflaredV3Server{}
	call, readResult := newRegisterUDPSessionCall(t, "trace-context")
	err := server.RegisterUdpSession(call)
	if err != nil {
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
	if resultErr != ErrUnsupportedDatagramV3UDPRegistration.Error() {
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
	server := &CloudflaredV3Server{}
	err := server.UnregisterUdpSession(newUnregisterUDPSessionCall(t))
	if err == nil {
		t.Fatal("expected unsupported unregister error")
	}
	if err.Error() != ErrUnsupportedDatagramV3UDPUnregistration.Error() {
		t.Fatalf("unexpected unregister error %v", err)
	}
}

type blockingPacketConn struct {
	closed chan struct{}
}

func newBlockingPacketConn() *blockingPacketConn {
	return &blockingPacketConn{closed: make(chan struct{})}
}

func (c *blockingPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	<-c.closed
	return M.Socksaddr{}, io.EOF
}

func (c *blockingPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *blockingPacketConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *blockingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *blockingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestV2RPCUnregisterUDPSessionPropagatesMessage(t *testing.T) {
	t.Parallel()
	muxerCtx := testMuxerContext(t, 0)
	muxerCtx.DialPacket = func(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
		return newBlockingPacketConn(), nil
	}
	muxer := NewDatagramV2Muxer(muxerCtx, &captureDatagramSender{}, logger.NOP())

	sessionID := uuid.New()
	err := muxer.RegisterSession(context.Background(), sessionID, net.IPv4(127, 0, 0, 1), 53, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	muxer.sessionAccess.RLock()
	session := muxer.sessions[sessionID]
	muxer.sessionAccess.RUnlock()
	if session == nil {
		t.Fatal("expected registered session")
	}

	server := &CloudflaredServer{
		muxer:  muxer,
		ctx:    context.Background(),
		logger: logger.NOP(),
	}
	err = server.UnregisterUdpSession(newUnregisterUDPSessionCallForSession(t, sessionID, "edge close"))
	if err != nil {
		t.Fatal(err)
	}
	if reason := session.closeReason(); reason != "edge close" {
		t.Fatalf("expected close reason propagated from edge, got %q", reason)
	}
}

func TestV2RPCRegisterUDPSessionRejectsMissingDestinationIP(t *testing.T) {
	t.Parallel()
	muxerCtx := testMuxerContext(t, 0)
	muxerCtx.DialPacket = func(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
		return newBlockingPacketConn(), nil
	}
	server := &CloudflaredServer{
		muxer:  NewDatagramV2Muxer(muxerCtx, &captureDatagramSender{}, logger.NOP()),
		ctx:    context.Background(),
		logger: logger.NOP(),
	}
	call, readResult := newRegisterUDPSessionCallWithDstIP(t, nil, "")

	err := server.RegisterUdpSession(call)
	if err != nil {
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

// Ensure unused imports are consumed.
var _ protocol.RequestID
