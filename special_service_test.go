package cloudflared

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"
)

type fakeConnectResponseWriter struct {
	status  int
	headers http.Header
	err     error
	done    chan struct{}
}

func (w *fakeConnectResponseWriter) WriteResponse(responseError error, metadata []Metadata) error {
	w.err = responseError
	w.headers = make(http.Header)
	for _, entry := range metadata {
		switch {
		case entry.Key == metadataHTTPStatus:
			status, _ := strconv.Atoi(entry.Val)
			w.status = status
		case len(entry.Key) > len(metadataHTTPHeader)+1 && entry.Key[:len(metadataHTTPHeader)+1] == metadataHTTPHeader+":":
			w.headers.Add(entry.Key[len(metadataHTTPHeader)+1:], entry.Val)
		}
	}
	if w.done != nil {
		close(w.done)
		w.done = nil
	}
	return nil
}

func newSpecialService(t *testing.T) *Service {
	return newSpecialServiceWithHandler(t, &testHandler{})
}

func newSpecialServiceWithHandler(t *testing.T, handler Handler) *Service {
	t.Helper()
	configManager, err := NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	return &Service{
		handler:       handler,
		logger:        logger.NOP(),
		configManager: configManager,
		flowLimiter:   &FlowLimiter{},
	}
}

type countingHandler struct {
	testHandler
	count atomic.Int32
}

func (h *countingHandler) DialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	h.count.Add(1)
	return h.testHandler.DialTCP(ctx, destination)
}

func startEchoListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
	return listener
}

func newSocksProxyService(t *testing.T, rules []IPRule) ResolvedService {
	t.Helper()
	service, err := parseResolvedService("socks-proxy", OriginRequestConfig{IPRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newSocksProxyConnectRequest() *ConnectRequest {
	return &ConnectRequest{
		Type: ConnectionTypeWebsocket,
		Metadata: []Metadata{
			{Key: metadataHTTPHeader + ":Sec-WebSocket-Key", Val: "dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}
}

func startSocksProxyStream(t *testing.T, serviceInstance *Service, service ResolvedService) (net.Conn, <-chan struct{}) {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	respWriter := &fakeConnectResponseWriter{done: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		serviceInstance.handleSocksProxyStream(context.Background(), serverSide, respWriter, newSocksProxyConnectRequest(), service)
	}()
	select {
	case <-respWriter.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for socks-proxy connect response")
	}
	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 response, got %d", respWriter.status)
	}
	return clientSide, done
}

func writeSocksAuth(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := wsutil.WriteClientMessage(conn, ws.OpBinary, []byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	data, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string([]byte{5, 0}) {
		t.Fatalf("unexpected auth response: %v", data)
	}
}

func writeSocksConnectIPv4(t *testing.T, conn net.Conn, address string) []byte {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	requestBytes := []byte{5, 1, 0, 1}
	requestBytes = append(requestBytes, net.ParseIP(host).To4()...)
	requestBytes = append(requestBytes, byte(port>>8), byte(port))
	if err := wsutil.WriteClientMessage(conn, ws.OpBinary, requestBytes); err != nil {
		t.Fatal(err)
	}
	data, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestServeSocksProxyRejectsMissingNoAuth(t *testing.T) {
	t.Parallel()
	serviceInstance := newSpecialService(t)
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- serviceInstance.serveSocksProxy(context.Background(), serverSide, nil)
	}()

	if _, err := clientSide.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(clientSide, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string([]byte{5, 255}) {
		t.Fatalf("unexpected auth rejection response: %v", response)
	}
	if err := <-errCh; err == nil {
		t.Fatal("expected socks auth rejection error")
	}
}

func TestSocksReplyForDialError(t *testing.T) {
	t.Parallel()
	if reply := socksReplyForDialError(io.EOF); reply != socksReplyHostUnreachable {
		t.Fatalf("expected host unreachable for generic error, got %d", reply)
	}
	if reply := socksReplyForDialError(errors.New("connection refused")); reply != 5 {
		t.Fatalf("expected connection refused reply, got %d", reply)
	}
	if reply := socksReplyForDialError(errors.New("network is unreachable")); reply != 3 {
		t.Fatalf("expected network unreachable reply, got %d", reply)
	}
}

func TestHandleBastionStream(t *testing.T) {
	t.Parallel()
	listener := startEchoListener(t)
	defer listener.Close()

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	serviceInstance := newSpecialService(t)
	request := &ConnectRequest{
		Type: ConnectionTypeWebsocket,
		Metadata: []Metadata{
			{Key: metadataHTTPHeader + ":Sec-WebSocket-Key", Val: "dGhlIHNhbXBsZSBub25jZQ=="},
			{Key: metadataHTTPHeader + ":Cf-Access-Jump-Destination", Val: listener.Addr().String()},
		},
	}
	respWriter := &fakeConnectResponseWriter{done: make(chan struct{})}

	done := make(chan struct{})
	go func() {
		defer close(done)
		serviceInstance.handleBastionStream(context.Background(), serverSide, respWriter, request, ResolvedService{})
	}()

	select {
	case <-respWriter.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bastion connect response")
	}
	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 response, got %d", respWriter.status)
	}
	if respWriter.headers.Get("Sec-WebSocket-Accept") == "" {
		t.Fatal("expected websocket accept header")
	}

	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	data, opCode, err := wsutil.ReadServerData(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if opCode != ws.OpBinary {
		t.Fatalf("expected binary frame, got %v", opCode)
	}
	if string(data) != "hello" {
		t.Fatalf("expected echoed payload, got %q", string(data))
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bastion stream did not exit")
	}
}

func TestHandleSocksProxyStream(t *testing.T) {
	t.Parallel()
	listener := startEchoListener(t)
	defer listener.Close()

	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	service := newSocksProxyService(t, []IPRule{{
		Prefix: "127.0.0.0/8",
		Ports:  []int{port},
		Allow:  true,
	}})

	clientSide, done := startSocksProxyStream(t, newSpecialService(t), service)
	defer clientSide.Close()

	writeSocksAuth(t, clientSide)
	data := writeSocksConnectIPv4(t, clientSide, listener.Addr().String())
	if len(data) != 10 || data[1] != 0 {
		t.Fatalf("unexpected connect response: %v", data)
	}

	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	data, _, err := wsutil.ReadServerData(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected echoed payload, got %q", string(data))
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("socks-proxy stream did not exit")
	}
}

func TestHandleSocksProxyStreamDenyRule(t *testing.T) {
	t.Parallel()
	listener := startEchoListener(t)
	defer listener.Close()

	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	service := newSocksProxyService(t, []IPRule{{
		Prefix: "127.0.0.0/8",
		Ports:  []int{port},
		Allow:  false,
	}})
	handler := &countingHandler{}
	clientSide, done := startSocksProxyStream(t, newSpecialServiceWithHandler(t, handler), service)
	defer clientSide.Close()

	writeSocksAuth(t, clientSide)
	data := writeSocksConnectIPv4(t, clientSide, listener.Addr().String())
	if len(data) != 10 || data[1] != socksReplyRuleFailure {
		t.Fatalf("unexpected deny response: %v", data)
	}
	if handler.count.Load() != 0 {
		t.Fatalf("expected no handler dial, got %d", handler.count.Load())
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("socks-proxy stream did not exit")
	}
}

func TestHandleSocksProxyStreamPortMismatchDefaultDeny(t *testing.T) {
	t.Parallel()
	listener := startEchoListener(t)
	defer listener.Close()

	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	service := newSocksProxyService(t, []IPRule{{
		Prefix: "127.0.0.0/8",
		Ports:  []int{port + 1},
		Allow:  true,
	}})
	handler := &countingHandler{}
	clientSide, done := startSocksProxyStream(t, newSpecialServiceWithHandler(t, handler), service)
	defer clientSide.Close()

	writeSocksAuth(t, clientSide)
	data := writeSocksConnectIPv4(t, clientSide, listener.Addr().String())
	if len(data) != 10 || data[1] != socksReplyRuleFailure {
		t.Fatalf("unexpected port mismatch response: %v", data)
	}
	if handler.count.Load() != 0 {
		t.Fatalf("expected no handler dial, got %d", handler.count.Load())
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("socks-proxy stream did not exit")
	}
}

func TestHandleSocksProxyStreamEmptyRulesDefaultDeny(t *testing.T) {
	t.Parallel()
	listener := startEchoListener(t)
	defer listener.Close()

	handler := &countingHandler{}
	clientSide, done := startSocksProxyStream(t, newSpecialServiceWithHandler(t, handler), newSocksProxyService(t, nil))
	defer clientSide.Close()

	writeSocksAuth(t, clientSide)
	data := writeSocksConnectIPv4(t, clientSide, listener.Addr().String())
	if len(data) != 10 || data[1] != socksReplyRuleFailure {
		t.Fatalf("unexpected empty-rule response: %v", data)
	}
	if handler.count.Load() != 0 {
		t.Fatalf("expected no handler dial, got %d", handler.count.Load())
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("socks-proxy stream did not exit")
	}
}

func TestHandleStreamService(t *testing.T) {
	t.Parallel()
	listener := startEchoListener(t)
	defer listener.Close()

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	serviceInstance := newSpecialService(t)
	request := &ConnectRequest{
		Type: ConnectionTypeWebsocket,
		Metadata: []Metadata{
			{Key: metadataHTTPHeader + ":Sec-WebSocket-Key", Val: "dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}
	respWriter := &fakeConnectResponseWriter{done: make(chan struct{})}

	done := make(chan struct{})
	go func() {
		defer close(done)
		serviceInstance.handleStreamService(context.Background(), serverSide, respWriter, request, ResolvedService{
			Kind:          ResolvedServiceStream,
			Destination:   M.ParseSocksaddr(listener.Addr().String()),
			StreamHasPort: true,
		})
	}()

	select {
	case <-respWriter.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stream service connect response")
	}
	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 response, got %d", respWriter.status)
	}

	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	data, opCode, err := wsutil.ReadServerData(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if opCode != ws.OpBinary {
		t.Fatalf("expected binary frame, got %v", opCode)
	}
	if string(data) != "hello" {
		t.Fatalf("expected echoed payload, got %q", string(data))
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream service did not exit")
	}
}

func TestHandleStreamServiceGenericSchemeWithoutPort(t *testing.T) {
	t.Parallel()
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	handler := &countingHandler{}
	serviceInstance := newSpecialServiceWithHandler(t, handler)
	request := &ConnectRequest{
		Type: ConnectionTypeWebsocket,
		Metadata: []Metadata{
			{Key: metadataHTTPHeader + ":Sec-WebSocket-Key", Val: "dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}
	respWriter := &fakeConnectResponseWriter{done: make(chan struct{})}

	serviceInstance.handleStreamService(context.Background(), serverSide, respWriter, request, ResolvedService{
		Kind:          ResolvedServiceStream,
		Service:       "ftp://127.0.0.1",
		Destination:   M.ParseSocksaddrHostPort("127.0.0.1", 0),
		StreamHasPort: false,
		BaseURL: &url.URL{
			Scheme: "ftp",
			Host:   "127.0.0.1",
		},
	})

	if respWriter.err == nil {
		t.Fatal("expected missing port error")
	}
	if respWriter.err.Error() != "address 127.0.0.1: missing port in address" {
		t.Fatalf("unexpected error: %v", respWriter.err)
	}
	if respWriter.status == http.StatusSwitchingProtocols {
		t.Fatalf("expected non-upgrade response on error, got %d", respWriter.status)
	}
	if handler.count.Load() != 0 {
		t.Fatalf("expected handler not to be used, got %d", handler.count.Load())
	}
}

// Unused import guards
var (
	_ N.PacketConn
	_ = ws.StateServerSide
)
