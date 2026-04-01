package cloudflared

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type bufferQUICStream struct {
	reader           *bytes.Reader
	writes           bytes.Buffer
	cancelReadCount  int
	cancelWriteCount int
	closeCount       int
}

func newBufferQUICStream(payload []byte) *bufferQUICStream {
	return &bufferQUICStream{reader: bytes.NewReader(payload)}
}

func (s *bufferQUICStream) Read(p []byte) (int, error)  { return s.reader.Read(p) }
func (s *bufferQUICStream) Write(p []byte) (int, error) { return s.writes.Write(p) }
func (s *bufferQUICStream) Close() error {
	s.closeCount++
	return nil
}
func (s *bufferQUICStream) CancelRead(quic.StreamErrorCode) { s.cancelReadCount++ }
func (s *bufferQUICStream) CancelWrite(quic.StreamErrorCode) {
	s.cancelWriteCount++
}
func (s *bufferQUICStream) SetWriteDeadline(time.Time) error { return nil }

type scriptedQUICConn struct {
	openStreams   chan quicStreamHandle
	acceptStreams chan quicStreamHandle
	datagrams     chan []byte
	closeReasons  chan string

	openErr    error
	acceptErr  error
	receiveErr error
	localAddr  net.Addr
	sent       [][]byte
}

func newScriptedQUICConn() *scriptedQUICConn {
	return &scriptedQUICConn{
		openStreams:   make(chan quicStreamHandle, 4),
		acceptStreams: make(chan quicStreamHandle, 4),
		datagrams:     make(chan []byte, 4),
		closeReasons:  make(chan string, 2),
		localAddr:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
	}
}

func (c *scriptedQUICConn) OpenStream() (quicStreamHandle, error) {
	select {
	case stream := <-c.openStreams:
		return stream, nil
	default:
		if c.openErr != nil {
			return nil, c.openErr
		}
		return nil, errors.New("no open stream queued")
	}
}

func (c *scriptedQUICConn) AcceptStream(ctx context.Context) (quicStreamHandle, error) {
	select {
	case stream := <-c.acceptStreams:
		return stream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		if c.acceptErr != nil {
			return nil, c.acceptErr
		}
		select {
		case stream := <-c.acceptStreams:
			return stream, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (c *scriptedQUICConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case datagram := <-c.datagrams:
		return datagram, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		if c.receiveErr != nil {
			return nil, c.receiveErr
		}
		select {
		case datagram := <-c.datagrams:
			return datagram, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (c *scriptedQUICConn) SendDatagram(data []byte) error {
	copied := append([]byte(nil), data...)
	c.sent = append(c.sent, copied)
	return nil
}

func (c *scriptedQUICConn) LocalAddr() net.Addr { return c.localAddr }

func (c *scriptedQUICConn) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	c.closeReasons <- reason
	return nil
}

type recordingStreamHandler struct {
	dataRequests chan *ConnectRequest
	rpcStreams   chan struct{}
	datagrams    chan []byte
}

func (h *recordingStreamHandler) HandleDataStream(ctx context.Context, stream io.ReadWriteCloser, request *ConnectRequest, connIndex uint8) {
	h.dataRequests <- request
}

func (h *recordingStreamHandler) HandleRPCStream(ctx context.Context, stream io.ReadWriteCloser, connIndex uint8) {}

func (h *recordingStreamHandler) HandleRPCStreamWithSender(ctx context.Context, stream io.ReadWriteCloser, connIndex uint8, sender DatagramSender) {
	h.rpcStreams <- struct{}{}
}

func (h *recordingStreamHandler) HandleDatagram(ctx context.Context, datagram []byte, sender DatagramSender) {
	h.datagrams <- append([]byte(nil), datagram...)
}

type nonUDPListenDialer struct {
	packetConn net.PacketConn
}

func (d *nonUDPListenDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unused")
}

func (d *nonUDPListenDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.packetConn, nil
}

type dummyPacketConn struct{}

func (dummyPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) { return 0, nil, io.EOF }
func (dummyPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error)  { return len(p), nil }
func (dummyPacketConn) Close() error                                         { return nil }
func (dummyPacketConn) LocalAddr() net.Addr                                  { return &net.IPAddr{} }
func (dummyPacketConn) SetDeadline(time.Time) error                          { return nil }
func (dummyPacketConn) SetReadDeadline(time.Time) error                      { return nil }
func (dummyPacketConn) SetWriteDeadline(time.Time) error                     { return nil }

func TestQUICServeDispatchesStreamsAndDatagrams(t *testing.T) {
	originalFactory := newRegistrationClient
	defer func() {
		newRegistrationClient = originalFactory
	}()

	registrationClient := newCaptureRegistrationClient()
	registrationClient.result = &RegistrationResult{
		ConnectionID:            uuid.New(),
		Location:                "SIN",
		TunnelIsRemotelyManaged: true,
	}
	newRegistrationClient = func(ctx context.Context, stream io.ReadWriteCloser) registrationRPCClient {
		return registrationClient
	}

	conn := newScriptedQUICConn()
	controlStream := newBufferQUICStream(nil)
	dataStream := newBufferQUICStream(encodeConnectRequestForTest(t, &ConnectRequest{
		Dest: "http://example.com/test",
		Type: ConnectionTypeHTTP,
	}))
	rpcStream := newBufferQUICStream(rpcStreamSignature[:])
	conn.openStreams <- controlStream
	conn.acceptStreams <- dataStream
	conn.acceptStreams <- rpcStream
	conn.datagrams <- []byte("payload")

	connected := make(chan struct{}, 1)
	connection := &QUICConnection{
		conn:         conn,
		logger:       logger.NOP(),
		credentials:  Credentials{TunnelID: uuid.New()},
		connectorID:  uuid.New(),
		features:     []string{"serialized_headers"},
		connIndex:    2,
		gracePeriod:  10 * time.Millisecond,
		onConnected: func() {
			connected <- struct{}{}
		},
	}
	handler := &recordingStreamHandler{
		dataRequests: make(chan *ConnectRequest, 1),
		rpcStreams:   make(chan struct{}, 1),
		datagrams:    make(chan []byte, 1),
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- connection.Serve(ctx, handler)
	}()

	select {
	case <-connected:
	case <-time.After(time.Second):
		t.Fatal("expected onConnected callback")
	}
	select {
	case request := <-handler.dataRequests:
		if request.Dest != "http://example.com/test" || request.Type != ConnectionTypeHTTP {
			t.Fatalf("unexpected connect request %#v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("expected data stream dispatch")
	}
	select {
	case <-handler.rpcStreams:
	case <-time.After(time.Second):
		t.Fatal("expected rpc stream dispatch")
	}
	select {
	case datagram := <-handler.datagrams:
		if string(datagram) != "payload" {
			t.Fatalf("unexpected datagram %q", datagram)
		}
	case <-time.After(time.Second):
		t.Fatal("expected datagram dispatch")
	}

	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected serve error %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected Serve to exit after cancellation")
	}
	select {
	case <-registrationClient.unregisterCalled:
	case <-time.After(time.Second):
		t.Fatal("expected unregister during graceful shutdown")
	}
	select {
	case reason := <-conn.closeReasons:
		if reason != "graceful shutdown" {
			t.Fatalf("unexpected close reason %q", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("expected connection close")
	}
}

func TestQUICServeReturnsAcceptErrorAndForceCloses(t *testing.T) {
	originalFactory := newRegistrationClient
	defer func() {
		newRegistrationClient = originalFactory
	}()

	registrationClient := newCaptureRegistrationClient()
	registrationClient.result = &RegistrationResult{
		ConnectionID:            uuid.New(),
		TunnelIsRemotelyManaged: true,
	}
	newRegistrationClient = func(ctx context.Context, stream io.ReadWriteCloser) registrationRPCClient {
		return registrationClient
	}

	conn := newScriptedQUICConn()
	conn.openStreams <- newBufferQUICStream(nil)
	conn.acceptErr = errors.New("accept failed")

	connection := &QUICConnection{
		conn:        conn,
		logger:      logger.NOP(),
		credentials: Credentials{TunnelID: uuid.New()},
		connectorID: uuid.New(),
	}

	err := connection.Serve(context.Background(), &recordingStreamHandler{
		dataRequests: make(chan *ConnectRequest, 1),
		rpcStreams:   make(chan struct{}, 1),
		datagrams:    make(chan []byte, 1),
	})
	if err == nil || err.Error() != "accept stream: accept failed" {
		t.Fatalf("unexpected serve error %v", err)
	}
	select {
	case reason := <-conn.closeReasons:
		if reason != "connection closed" {
			t.Fatalf("unexpected close reason %q", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("expected force close")
	}
}

func TestQUICOpenRPCStreamWritesSignature(t *testing.T) {
	t.Parallel()

	conn := newScriptedQUICConn()
	stream := newBufferQUICStream(nil)
	conn.openStreams <- stream
	connection := &QUICConnection{conn: conn}

	rwc, err := connection.OpenRPCStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer rwc.Close()
	if !bytes.Equal(stream.writes.Bytes(), rpcStreamSignature[:]) {
		t.Fatalf("unexpected rpc stream signature %x", stream.writes.Bytes())
	}
}

func TestQUICHelpers(t *testing.T) {
	t.Parallel()

	if got := quicInitialPacketSize(4); got != 1232 {
		t.Fatalf("unexpected IPv4 packet size %d", got)
	}
	if got := quicInitialPacketSize(6); got != 1252 {
		t.Fatalf("unexpected IPv6 packet size %d", got)
	}

	_, err := createUDPConnForConnIndex(context.Background(), &EdgeAddr{
		UDP: &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53},
	}, &nonUDPListenDialer{packetConn: dummyPacketConn{}})
	if err == nil || err.Error() != "unexpected packet conn type" {
		t.Fatalf("unexpected createUDPConnForConnIndex error %v", err)
	}
}
