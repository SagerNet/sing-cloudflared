package cloudflared

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"
)

type http2RegressionWSRespWriter struct {
	*httptest.ResponseRecorder
	readPipe  *io.PipeReader
	writePipe *io.PipeWriter
	closed    bool
	panicked  bool
}

func newHTTP2RegressionWSRespWriter() *http2RegressionWSRespWriter {
	readPipe, writePipe := io.Pipe()
	return &http2RegressionWSRespWriter{
		ResponseRecorder: httptest.NewRecorder(),
		readPipe:         readPipe,
		writePipe:        writePipe,
	}
}

type noWriteReader struct {
	io.Reader
}

func (noWriteReader) Write(_ []byte) (int, error) {
	return 0, errors.New("writer not implemented")
}

func (w *http2RegressionWSRespWriter) RespBody() io.ReadWriter {
	return noWriteReader{w.readPipe}
}

func (w *http2RegressionWSRespWriter) Write(p []byte) (int, error) {
	if w.closed {
		w.panicked = true
		return 0, errors.New("http2RegressionWSRespWriter panicked")
	}
	return w.writePipe.Write(p)
}

func (w *http2RegressionWSRespWriter) close() {
	w.closed = true
}

func TestHTTP2WebsocketDoesNotWriteAfterHandlerReturns(t *testing.T) {
	t.Parallel()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			if err := wsutil.WriteServerMessage(conn, opCode, payload); err != nil {
				return
			}
		}
	}))
	defer origin.Close()

	serviceInstance := newSpecialService(t)
	serviceInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{{
			Service: mustResolvedService(t, origin.URL),
		}},
	}
	connection := &HTTP2Connection{
		logger:  logger.NOP(),
		service: serviceInstance,
	}

	for range 20 {
		ctx, cancel := context.WithCancel(context.Background())
		respWriter := newHTTP2RegressionWSRespWriter()
		readPipe, writePipe := io.Pipe()
		respBody := respWriter.RespBody()

		request := httptest.NewRequest(http.MethodGet, "http://example.com/ws/flaky", readPipe).WithContext(ctx)
		request.Header.Set(h2HeaderUpgrade, h2UpgradeWebsocket)
		request.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

		done := make(chan struct{})
		go func() {
			defer close(done)
			connection.ServeHTTP(respWriter, request)
			respWriter.close()
		}()

		if err := wsutil.WriteClientMessage(writePipe, ws.OpBinary, []byte("hello")); err != nil {
			t.Fatal(err)
		}

		firstFrameCh := make(chan error, 1)
		drainDone := make(chan struct{})
		go func() {
			defer close(drainDone)

			payload, opCode, err := wsutil.ReadServerData(respBody)
			if err != nil {
				firstFrameCh <- err
				return
			}
			if opCode != ws.OpBinary || string(payload) != "hello" {
				firstFrameCh <- errors.New("unexpected echoed websocket payload")
				return
			}
			firstFrameCh <- nil

			for {
				if _, _, err := wsutil.ReadServerData(respBody); err != nil {
					return
				}
			}
		}()

		select {
		case err := <-firstFrameCh:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("expected websocket echo before cancellation")
		}

		spamDone := make(chan struct{})
		go func() {
			defer close(spamDone)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_ = wsutil.WriteClientMessage(writePipe, ws.OpBinary, []byte("loop"))
			}
		}()

		time.Sleep(50 * time.Millisecond)
		cancel()
		_ = readPipe.Close()
		_ = writePipe.Close()
		_ = respWriter.readPipe.Close()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("expected websocket handler to return after cancellation")
		}

		select {
		case <-spamDone:
		case <-time.After(time.Second):
			t.Fatal("expected websocket writer goroutine to stop")
		}
		select {
		case <-drainDone:
		case <-time.After(time.Second):
			t.Fatal("expected websocket reader goroutine to stop")
		}

		time.Sleep(20 * time.Millisecond)
		if respWriter.Code != http.StatusOK {
			t.Fatalf("unexpected websocket response code %d", respWriter.Code)
		}
		if respWriter.panicked {
			t.Fatal("unexpected write attempt after websocket handler returned")
		}
	}
}
