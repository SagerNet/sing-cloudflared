package cloudflared

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"
	"golang.org/x/net/http2"
)

type notifyingCaptureStream struct {
	notifyOnce sync.Once
	notify     chan struct{}

	access sync.Mutex
	body   bytes.Buffer
}

func newNotifyingCaptureStream() *notifyingCaptureStream {
	return &notifyingCaptureStream{notify: make(chan struct{})}
}

func (s *notifyingCaptureStream) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (s *notifyingCaptureStream) Write(p []byte) (int, error) {
	s.access.Lock()
	defer s.access.Unlock()

	n, err := s.body.Write(p)
	if n > 0 {
		s.notifyOnce.Do(func() {
			close(s.notify)
		})
	}
	return n, err
}

func (s *notifyingCaptureStream) Close() error {
	return nil
}

func (s *notifyingCaptureStream) String() string {
	s.access.Lock()
	defer s.access.Unlock()
	return s.body.String()
}

func configForSingleOrigin(originURL string) []byte {
	return []byte(fmt.Sprintf(`{"ingress":[{"service":"%s"}]}`, originURL))
}

func newConnectRequestForOrigin(destination string, connectionType ConnectionType, extraMetadata ...Metadata) *ConnectRequest {
	request := &ConnectRequest{
		Dest: destination,
		Type: connectionType,
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: "example.com"},
		},
	}
	request.Metadata = append(request.Metadata, extraMetadata...)
	return request
}

func startRouterRoundTrip(t *testing.T, serviceInstance *Service, request *ConnectRequest, resolved ResolvedService, stream io.ReadWriteCloser, respWriter ConnectResponseWriter) (func(), <-chan struct{}) {
	t.Helper()

	transport, cleanup, err := serviceInstance.newRouterOriginTransport(context.Background(), resolved.Destination, resolved.OriginRequest, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		serviceInstance.roundTripHTTP(context.Background(), stream, respWriter, request, resolved, transport)
	}()

	return func() {
		cleanup()
	}, done
}

func TestApplyConfigAffectsNewRequestsWithoutInterruptingActiveHTTPResponse(t *testing.T) {
	t.Parallel()

	firstChunkWritten := make(chan struct{})
	releaseOldOrigin := make(chan struct{})
	oldOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected flusher")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("old-1"))
		flusher.Flush()
		close(firstChunkWritten)
		<-releaseOldOrigin
		_, _ = w.Write([]byte("old-2"))
	}))
	defer oldOrigin.Close()

	newOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("new-body"))
	}))
	defer newOrigin.Close()

	serviceInstance := newTestService(t, testToken(t), protocolHTTP2, 1)
	result := serviceInstance.ApplyConfig(1, configForSingleOrigin(oldOrigin.URL))
	if result.Err != nil {
		t.Fatal(result.Err)
	}

	oldResolved, oldURL, err := serviceInstance.resolveHTTPService("http://example.com/stream")
	if err != nil {
		t.Fatal(err)
	}
	oldStream := newNotifyingCaptureStream()
	oldRespWriter := &fakeConnectResponseWriter{}
	oldCleanup, oldDone := startRouterRoundTrip(t, serviceInstance, newConnectRequestForOrigin(oldURL, ConnectionTypeHTTP), oldResolved, oldStream, oldRespWriter)
	defer oldCleanup()

	select {
	case <-firstChunkWritten:
	case <-time.After(time.Second):
		t.Fatal("expected first old-origin chunk")
	}
	select {
	case <-oldStream.notify:
	case <-time.After(time.Second):
		t.Fatal("expected old response body to start streaming")
	}

	result = serviceInstance.ApplyConfig(2, configForSingleOrigin(newOrigin.URL))
	if result.Err != nil {
		t.Fatal(result.Err)
	}

	newResolved, newURL, err := serviceInstance.resolveHTTPService("http://example.com/stream")
	if err != nil {
		t.Fatal(err)
	}
	newStream := newNotifyingCaptureStream()
	newRespWriter := &fakeConnectResponseWriter{}
	newCleanup, newDone := startRouterRoundTrip(t, serviceInstance, newConnectRequestForOrigin(newURL, ConnectionTypeHTTP), newResolved, newStream, newRespWriter)
	defer newCleanup()

	select {
	case <-newDone:
	case <-time.After(time.Second):
		t.Fatal("expected updated request to finish")
	}
	if got := newStream.String(); got != "new-body" {
		t.Fatalf("unexpected new response body %q", got)
	}
	if newRespWriter.status != http.StatusOK {
		t.Fatalf("unexpected new response status %d", newRespWriter.status)
	}

	close(releaseOldOrigin)
	select {
	case <-oldDone:
	case <-time.After(time.Second):
		t.Fatal("expected original streaming request to finish")
	}
	if got := oldStream.String(); got != "old-1old-2" {
		t.Fatalf("unexpected old response body %q", got)
	}
	if oldRespWriter.status != http.StatusOK {
		t.Fatalf("unexpected old response status %d", oldRespWriter.status)
	}
}

func TestApplyConfigAffectsNewRequestsWithoutInterruptingActiveWebsocketStream(t *testing.T) {
	t.Parallel()

	oldOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			payload, opCode, err := wsutil.ReadClientData(conn)
			if err != nil {
				return
			}
			if err := wsutil.WriteServerMessage(conn, opCode, append([]byte("old:"), payload...)); err != nil {
				return
			}
		}
	}))
	defer oldOrigin.Close()

	newOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("new-http"))
	}))
	defer newOrigin.Close()

	serviceInstance := newTestService(t, testToken(t), protocolHTTP2, 1)
	result := serviceInstance.ApplyConfig(1, configForSingleOrigin(oldOrigin.URL))
	if result.Err != nil {
		t.Fatal(result.Err)
	}

	oldResolved, oldURL, err := serviceInstance.resolveHTTPService("http://example.com/ws")
	if err != nil {
		t.Fatal(err)
	}

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	oldRespWriter := &fakeConnectResponseWriter{done: make(chan struct{})}
	oldCleanup, oldDone := startRouterRoundTrip(
		t,
		serviceInstance,
		newConnectRequestForOrigin(oldURL, ConnectionTypeWebsocket, Metadata{
			Key: metadataHTTPHeader + ":Sec-WebSocket-Key",
			Val: "dGhlIHNhbXBsZSBub25jZQ==",
		}),
		oldResolved,
		serverSide,
		oldRespWriter,
	)
	defer oldCleanup()

	select {
	case <-oldRespWriter.done:
	case <-time.After(time.Second):
		t.Fatal("expected websocket connect response")
	}
	if oldRespWriter.status != http.StatusSwitchingProtocols {
		t.Fatalf("unexpected websocket response status %d", oldRespWriter.status)
	}

	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte("one")); err != nil {
		t.Fatal(err)
	}
	payload, opCode, err := wsutil.ReadServerData(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if opCode != ws.OpBinary || string(payload) != "old:one" {
		t.Fatalf("unexpected first websocket payload %q op=%v", payload, opCode)
	}

	result = serviceInstance.ApplyConfig(2, configForSingleOrigin(newOrigin.URL))
	if result.Err != nil {
		t.Fatal(result.Err)
	}

	newResolved, newURL, err := serviceInstance.resolveHTTPService("http://example.com/ws")
	if err != nil {
		t.Fatal(err)
	}
	newStream := newNotifyingCaptureStream()
	newRespWriter := &fakeConnectResponseWriter{}
	newCleanup, newDone := startRouterRoundTrip(t, serviceInstance, newConnectRequestForOrigin(newURL, ConnectionTypeHTTP), newResolved, newStream, newRespWriter)
	defer newCleanup()

	select {
	case <-newDone:
	case <-time.After(time.Second):
		t.Fatal("expected updated request to finish")
	}
	if got := newStream.String(); got != "new-http" {
		t.Fatalf("unexpected updated response body %q", got)
	}

	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte("two")); err != nil {
		t.Fatal(err)
	}
	payload, opCode, err = wsutil.ReadServerData(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if opCode != ws.OpBinary || string(payload) != "old:two" {
		t.Fatalf("unexpected second websocket payload %q op=%v", payload, opCode)
	}

	_ = clientSide.Close()
	select {
	case <-oldDone:
	case <-time.After(time.Second):
		t.Fatal("expected original websocket stream to exit")
	}
}

func TestHTTP2ServeReturnsErrorWhenEdgeClosesBeforeRegistration(t *testing.T) {
	t.Parallel()

	serverSide, clientSide := net.Pipe()
	connection := &HTTP2Connection{
		conn:    serverSide,
		server:  &http2.Server{},
		logger:  logger.NOP(),
		service: newSpecialService(t),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- connection.Serve(context.Background())
	}()

	_ = clientSide.Close()

	select {
	case err := <-errCh:
		if err == nil || err.Error() != "edge connection closed before registration" {
			t.Fatalf("unexpected serve error %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected Serve to return after edge close")
	}
}
