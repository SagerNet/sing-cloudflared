package cloudflared

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/quic-go"

	"github.com/google/uuid"
)

type stubNetConn struct {
	closed chan struct{}
}

func newStubNetConn() *stubNetConn {
	return &stubNetConn{closed: make(chan struct{})}
}

func (c *stubNetConn) Read(_ []byte) (int, error)       { <-c.closed; return 0, io.EOF }
func (c *stubNetConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *stubNetConn) Close() error                     { closeOnce(c.closed); return nil }
func (c *stubNetConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *stubNetConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *stubNetConn) SetDeadline(time.Time) error      { return nil }
func (c *stubNetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubNetConn) SetWriteDeadline(time.Time) error { return nil }

type stubQUICConn struct {
	closed chan string
}

func newStubQUICConn() *stubQUICConn {
	return &stubQUICConn{closed: make(chan string, 1)}
}

func (c *stubQUICConn) OpenStream() (*quic.Stream, error) { return nil, errors.New("unused") }
func (c *stubQUICConn) AcceptStream(context.Context) (*quic.Stream, error) {
	return nil, errors.New("unused")
}

func (c *stubQUICConn) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errors.New("unused")
}
func (c *stubQUICConn) SendDatagram([]byte) error { return nil }
func (c *stubQUICConn) LocalAddr() net.Addr       { return &net.UDPAddr{} }
func (c *stubQUICConn) CloseWithError(_ quic.ApplicationErrorCode, reason string) error {
	select {
	case c.closed <- reason:
	default:
	}
	return nil
}

type mockRegistrationClient struct {
	unregisterCalled chan struct{}
	closed           chan struct{}
}

func newMockRegistrationClient() *mockRegistrationClient {
	return &mockRegistrationClient{
		unregisterCalled: make(chan struct{}, 1),
		closed:           make(chan struct{}, 1),
	}
}

func (c *mockRegistrationClient) RegisterConnection(context.Context, TunnelAuth, uuid.UUID, uint8, *RegistrationConnectionOptions) (*RegistrationResult, error) {
	return &RegistrationResult{}, nil
}

func (c *mockRegistrationClient) Unregister(context.Context) error {
	select {
	case c.unregisterCalled <- struct{}{}:
	default:
	}
	return nil
}

func (c *mockRegistrationClient) Close() error {
	select {
	case c.closed <- struct{}{}:
	default:
	}
	return nil
}

func closeOnce(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func TestHTTP2GracefulShutdownWaitsForActiveRequests(t *testing.T) {
	t.Parallel()
	conn := newStubNetConn()
	registrationClient := newMockRegistrationClient()
	connection := &HTTP2Connection{
		conn:               conn,
		gracePeriod:        200 * time.Millisecond,
		registrationClient: registrationClient,
		registrationResult: &RegistrationResult{},
		serveCancel:        func() {},
	}
	connection.activeRequests.Add(1)

	done := make(chan struct{})
	go func() {
		connection.gracefulShutdown()
		close(done)
	}()

	select {
	case <-registrationClient.unregisterCalled:
	case <-time.After(time.Second):
		t.Fatal("expected unregister call")
	}

	select {
	case <-conn.closed:
		t.Fatal("connection closed before active requests completed")
	case <-time.After(50 * time.Millisecond):
	}

	connection.activeRequests.Done()

	select {
	case <-conn.closed:
	case <-time.After(time.Second):
		t.Fatal("expected connection close after active requests finished")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected graceful shutdown to finish")
	}
}

func TestHTTP2GracefulShutdownTimesOut(t *testing.T) {
	t.Parallel()
	conn := newStubNetConn()
	registrationClient := newMockRegistrationClient()
	connection := &HTTP2Connection{
		conn:               conn,
		gracePeriod:        50 * time.Millisecond,
		registrationClient: registrationClient,
		registrationResult: &RegistrationResult{},
		serveCancel:        func() {},
	}
	connection.activeRequests.Add(1)

	done := make(chan struct{})
	go func() {
		connection.gracefulShutdown()
		close(done)
	}()

	select {
	case <-conn.closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected connection close after grace timeout")
	}

	connection.activeRequests.Done()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected graceful shutdown to finish after request completion")
	}
}

func TestQUICGracefulShutdownWaitsForDrainWindow(t *testing.T) {
	t.Parallel()
	conn := newStubQUICConn()
	registrationClient := newMockRegistrationClient()
	serveCancelCalled := make(chan struct{}, 1)
	connection := &QUICConnection{
		conn:               conn,
		gracePeriod:        80 * time.Millisecond,
		registrationClient: registrationClient,
		registrationResult: &RegistrationResult{},
		serveCancel: func() {
			select {
			case serveCancelCalled <- struct{}{}:
			default:
			}
		},
	}

	done := make(chan struct{})
	go func() {
		connection.gracefulShutdown()
		close(done)
	}()

	select {
	case <-registrationClient.unregisterCalled:
	case <-time.After(time.Second):
		t.Fatal("expected unregister call")
	}

	select {
	case <-conn.closed:
		t.Fatal("connection closed before grace window elapsed")
	case <-time.After(20 * time.Millisecond):
	}

	select {
	case reason := <-conn.closed:
		if reason != "graceful shutdown" {
			t.Fatalf("unexpected close reason: %q", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("expected graceful close")
	}

	select {
	case <-serveCancelCalled:
	case <-time.After(time.Second):
		t.Fatal("expected serve cancel to be called")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected graceful shutdown to finish")
	}
}

func TestQUICGracefulShutdownStopsWaitingWhenServeContextEnds(t *testing.T) {
	t.Parallel()
	conn := newStubQUICConn()
	registrationClient := newMockRegistrationClient()
	serveCtx, cancelServe := context.WithCancel(context.Background())
	connection := &QUICConnection{
		conn:               conn,
		gracePeriod:        time.Second,
		registrationClient: registrationClient,
		registrationResult: &RegistrationResult{},
		serveCtx:           serveCtx,
		serveCancel:        func() {},
	}

	done := make(chan struct{})
	go func() {
		connection.gracefulShutdown()
		close(done)
	}()

	select {
	case <-registrationClient.unregisterCalled:
	case <-time.After(time.Second):
		t.Fatal("expected unregister call")
	}

	cancelServe()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected graceful shutdown to stop waiting once serve context ends")
	}
}
