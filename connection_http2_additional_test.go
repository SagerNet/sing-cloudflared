package cloudflared

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sagernet/sing/common/logger"
	"golang.org/x/net/http2"
)

type fixedAddrConn struct {
	closed chan struct{}
	local  net.Addr
}

func newFixedAddrConn(addr net.Addr) *fixedAddrConn {
	return &fixedAddrConn{
		closed: make(chan struct{}),
		local:  addr,
	}
}

func (c *fixedAddrConn) Read(_ []byte) (int, error)       { <-c.closed; return 0, io.EOF }
func (c *fixedAddrConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fixedAddrConn) Close() error                     { closeOnce(c.closed); return nil }
func (c *fixedAddrConn) LocalAddr() net.Addr              { return c.local }
func (c *fixedAddrConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *fixedAddrConn) SetDeadline(time.Time) error      { return nil }
func (c *fixedAddrConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fixedAddrConn) SetWriteDeadline(time.Time) error { return nil }

type flushCaptureWriter struct {
	header     http.Header
	statusCode int
	body       bytes.Buffer
	flushes    int
}

func (w *flushCaptureWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *flushCaptureWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func (w *flushCaptureWriter) Write(p []byte) (int, error) {
	return w.body.Write(p)
}

func (w *flushCaptureWriter) Flush() {
	w.flushes++
}

type captureRegistrationClient struct {
	result           *RegistrationResult
	registerErr      error
	unregisterErr    error
	registerCalled   chan struct{}
	unregisterCalled chan struct{}
	closed           chan struct{}

	auth      TunnelAuth
	tunnelID  uuid.UUID
	connIndex uint8
	options   *RegistrationConnectionOptions
}

func newCaptureRegistrationClient() *captureRegistrationClient {
	return &captureRegistrationClient{
		registerCalled:   make(chan struct{}, 1),
		unregisterCalled: make(chan struct{}, 1),
		closed:           make(chan struct{}, 1),
	}
}

func (c *captureRegistrationClient) RegisterConnection(ctx context.Context, auth TunnelAuth, tunnelID uuid.UUID, connIndex uint8, options *RegistrationConnectionOptions) (*RegistrationResult, error) {
	c.auth = auth
	c.tunnelID = tunnelID
	c.connIndex = connIndex
	c.options = options
	c.registerCalled <- struct{}{}
	if c.registerErr != nil {
		return nil, c.registerErr
	}
	return c.result, nil
}

func (c *captureRegistrationClient) Unregister(ctx context.Context) error {
	c.unregisterCalled <- struct{}{}
	return c.unregisterErr
}

func (c *captureRegistrationClient) Close() error {
	c.closed <- struct{}{}
	return nil
}

func startInMemoryHTTP2Connection(t *testing.T, service *Service) (*HTTP2Connection, *http2.ClientConn, context.CancelFunc, <-chan error) {
	t.Helper()

	serverSide, clientSide := net.Pipe()
	connection := &HTTP2Connection{
		conn:    serverSide,
		server:  &http2.Server{},
		logger:  logger.NOP(),
		service: service,
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- connection.Serve(ctx)
	}()

	clientConn, err := (&http2.Transport{}).NewClientConn(clientSide)
	if err != nil {
		cancel()
		_ = clientSide.Close()
		_ = serverSide.Close()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		cancel()
		_ = clientConn.Close()
		_ = clientSide.Close()
		_ = serverSide.Close()
	})
	return connection, clientConn, cancel, errCh
}

func TestHandleControlStreamRegistersAndNotifies(t *testing.T) {
	originalFactory := newRegistrationClient
	defer func() {
		newRegistrationClient = originalFactory
	}()

	serviceInstance := newTestService(t, testToken(t), protocolHTTP2, 1)
	connection := &HTTP2Connection{
		conn:         newFixedAddrConn(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}),
		logger:       logger.NOP(),
		service:      serviceInstance,
		credentials:  serviceInstance.credentials,
		connectorID:  uuid.New(),
		features:     []string{"serialized_headers"},
		connIndex:    0,
		gracePeriod:  10 * time.Millisecond,
	}

	registrationClient := newCaptureRegistrationClient()
	registrationClient.result = &RegistrationResult{
		ConnectionID:            uuid.New(),
		Location:                "NRT",
		TunnelIsRemotelyManaged: true,
	}
	newRegistrationClient = func(ctx context.Context, stream io.ReadWriteCloser) registrationRPCClient {
		return registrationClient
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodGet, "https://example.com", bytes.NewReader(nil)).WithContext(ctx)
	writer := &flushCaptureWriter{}

	done := make(chan struct{})
	go func() {
		connection.handleControlStream(ctx, request, writer)
		close(done)
	}()

	select {
	case <-registrationClient.registerCalled:
	case <-time.After(time.Second):
		t.Fatal("expected register call")
	}
	if writer.statusCode != http.StatusOK || writer.flushes != 1 {
		t.Fatalf("unexpected control stream response status=%d flushes=%d", writer.statusCode, writer.flushes)
	}
	if registrationClient.connIndex != 0 || registrationClient.tunnelID != serviceInstance.credentials.TunnelID {
		t.Fatalf("unexpected registration inputs conn=%d tunnel=%s", registrationClient.connIndex, registrationClient.tunnelID)
	}
	if registrationClient.options == nil || !registrationClient.options.OriginLocalIP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("unexpected origin local IP %#v", registrationClient.options)
	}

	select {
	case connected := <-serviceInstance.connectedNotify:
		if connected != 0 {
			t.Fatalf("unexpected connected index %d", connected)
		}
	case <-time.After(time.Second):
		t.Fatal("expected connected notification")
	}
	if connection.registrationResult == nil || connection.registrationResult.Location != "NRT" {
		t.Fatalf("unexpected registration result %#v", connection.registrationResult)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected control stream handler to exit on context cancellation")
	}
}

func TestHandleControlStreamRegistrationFailureForcesClose(t *testing.T) {
	originalFactory := newRegistrationClient
	defer func() {
		newRegistrationClient = originalFactory
	}()

	conn := newFixedAddrConn(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	connection := &HTTP2Connection{
		conn:        conn,
		logger:      logger.NOP(),
		credentials: Credentials{TunnelID: uuid.New()},
		connectorID: uuid.New(),
	}

	registrationClient := newCaptureRegistrationClient()
	registrationClient.registerErr = errors.New("register failed")
	newRegistrationClient = func(ctx context.Context, stream io.ReadWriteCloser) registrationRPCClient {
		return registrationClient
	}

	request := httptest.NewRequest(http.MethodGet, "https://example.com", bytes.NewReader(nil))
	writer := &flushCaptureWriter{}
	connection.handleControlStream(context.Background(), request, writer)

	select {
	case <-conn.closed:
	case <-time.After(time.Second):
		t.Fatal("expected connection close after failed registration")
	}
	select {
	case <-registrationClient.closed:
	case <-time.After(time.Second):
		t.Fatal("expected registration client close after failed registration")
	}
	if connection.controlStreamErr == nil || connection.controlStreamErr.Error() != "register failed" {
		t.Fatalf("unexpected control stream error %v", connection.controlStreamErr)
	}
}

func TestHTTP2ServeAppliesConfigurationAndExitsOnCancel(t *testing.T) {
	t.Parallel()

	serviceInstance := newSpecialService(t)
	_, clientConn, cancel, errCh := startInMemoryHTTP2Connection(t, serviceInstance)

	request, err := http.NewRequest(http.MethodPut, "http://example.com/config", bytes.NewBufferString(`{"version":2,"config":{"ingress":[{"service":"http_status:503"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(h2HeaderUpgrade, h2UpgradeConfiguration)

	response, err := clientConn.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", response.StatusCode)
	}
	if !bytes.Contains(body, []byte(`"lastAppliedVersion":2`)) {
		t.Fatalf("unexpected config update body %s", body)
	}
	if serviceInstance.configManager.CurrentVersion() != 2 {
		t.Fatalf("unexpected config version %d", serviceInstance.configManager.CurrentVersion())
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
}

func TestHTTP2ServeProxiesHTTPRequests(t *testing.T) {
	t.Parallel()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ping" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("origin-ok"))
	}))
	defer origin.Close()

	serviceInstance := newSpecialService(t)
	serviceInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{{
			Service: mustResolvedService(t, origin.URL),
		}},
	}
	_, clientConn, cancel, errCh := startInMemoryHTTP2Connection(t, serviceInstance)

	request, err := http.NewRequest(http.MethodGet, "http://example.com/ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := clientConn.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected status %d", response.StatusCode)
	}
	if string(body) != "origin-ok" {
		t.Fatalf("unexpected response body %q", body)
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
}

func TestHTTP2ServeRoutesWebsocketAndTCPBranches(t *testing.T) {
	t.Parallel()

	t.Run("websocket status service", func(t *testing.T) {
		serviceInstance := newSpecialService(t)
		serviceInstance.configManager.activeConfig = RuntimeConfig{
			Ingress: []compiledIngressRule{{
				Service: ResolvedService{Kind: ResolvedServiceStatus, StatusCode: http.StatusNoContent},
			}},
		}
		_, clientConn, cancel, errCh := startInMemoryHTTP2Connection(t, serviceInstance)

		request, err := http.NewRequest(http.MethodGet, "http://example.com/ws", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(h2HeaderUpgrade, h2UpgradeWebsocket)
		response, err := clientConn.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("unexpected websocket status %d", response.StatusCode)
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
	})

	t.Run("tcp rate limited", func(t *testing.T) {
		serviceInstance := newLimitedService(t, 1)
		if !serviceInstance.flowLimiter.Acquire(1) {
			t.Fatal("failed to pre-acquire flow limiter")
		}
		_, clientConn, cancel, errCh := startInMemoryHTTP2Connection(t, serviceInstance)

		request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:1", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(h2HeaderTCPSrc, "tcp")
		response, err := clientConn.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusBadGateway {
			t.Fatalf("unexpected tcp status %d", response.StatusCode)
		}
		if response.Header.Get(h2HeaderResponseMeta) != h2ResponseMetaCloudflaredLimited {
			t.Fatalf("unexpected response meta %q", response.Header.Get(h2HeaderResponseMeta))
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
	})
}
