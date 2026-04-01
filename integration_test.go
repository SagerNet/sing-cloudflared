package cloudflared

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"
)

func startLiveTestService(t *testing.T, env *liveTestEnvironment, protocol string, haConnections int) *Service {
	t.Helper()

	serviceInstance := newTestService(t, env.token, protocol, haConnections)
	if err := serviceInstance.Start(); err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, env.baseURL, 2*time.Minute)
	return serviceInstance
}

func startLiveConfiguredService(t *testing.T, env *liveTestEnvironment, options ServiceOptions) *Service {
	t.Helper()

	if options.Token == "" {
		options.Token = env.token
	}
	if options.ConnectionDialer == nil {
		options.ConnectionDialer = N.SystemDialer
	}
	serviceInstance, err := NewService(options)
	if err != nil {
		t.Fatal("NewService: ", err)
	}
	t.Cleanup(func() {
		_ = serviceInstance.Close()
	})

	if err := serviceInstance.Start(); err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, env.baseURL, 2*time.Minute)
	return serviceInstance
}

func requireFirstTrackedConnection(t *testing.T, serviceInstance *Service) io.Closer {
	t.Helper()

	serviceInstance.connectionAccess.Lock()
	defer serviceInstance.connectionAccess.Unlock()
	if len(serviceInstance.connections) == 0 {
		t.Fatal("expected at least one tracked connection")
	}
	return serviceInstance.connections[0]
}

func TestLiveQUICIntegration(t *testing.T) {
	env := requireLiveTestEnvironment(t)
	startLiveTestService(t, env, "quic", 1)

	resp, err := http.Get(env.HTTPURL("/ping"))
	if err != nil {
		t.Fatal("GET /ping: ", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatal("expected 200, got ", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("read body: ", err)
	}
	if string(body) != `{"ok":true}` {
		t.Error("unexpected body: ", string(body))
	}
}

func TestLiveHTTP2Integration(t *testing.T) {
	env := requireLiveTestEnvironment(t)
	startLiveTestService(t, env, "http2", 1)

	resp, err := http.Get(env.HTTPURL("/ping"))
	if err != nil {
		t.Fatal("GET /ping: ", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatal("expected 200, got ", resp.StatusCode)
	}
}

func TestLiveAutoProtocolIntegration(t *testing.T) {
	env := requireLiveTestEnvironment(t)
	serviceInstance := startLiveConfiguredService(t, env, ServiceOptions{
		Protocol:      "auto",
		HAConnections: 1,
	})

	if _, ok := requireFirstTrackedConnection(t, serviceInstance).(*QUICConnection); !ok {
		t.Fatalf("expected auto protocol to establish QUIC connection, got %T", requireFirstTrackedConnection(t, serviceInstance))
	}

	resp, err := http.Get(env.HTTPURL("/ping"))
	if err != nil {
		t.Fatal("GET /ping: ", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("expected 200, got ", resp.StatusCode)
	}
}

func TestLivePostQuantumIntegration(t *testing.T) {
	env := requireLiveTestEnvironment(t)
	serviceInstance := startLiveConfiguredService(t, env, ServiceOptions{
		Protocol:      "auto",
		PostQuantum:   true,
		HAConnections: 1,
	})

	if _, ok := requireFirstTrackedConnection(t, serviceInstance).(*QUICConnection); !ok {
		t.Fatalf("expected post-quantum mode to use QUIC, got %T", requireFirstTrackedConnection(t, serviceInstance))
	}
	_, features := serviceInstance.currentConnectionFeatures()
	if !strings.Contains(strings.Join(features, ","), featurePostQuantum) {
		t.Fatalf("expected post-quantum feature in %v", features)
	}

	resp, err := http.Get(env.HTTPURL("/ping"))
	if err != nil {
		t.Fatal("GET /ping: ", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("expected 200, got ", resp.StatusCode)
	}
}

func TestLiveMultipleHAConnections(t *testing.T) {
	env := requireLiveTestEnvironment(t)
	serviceInstance := startLiveTestService(t, env, "quic", 2)

	time.Sleep(3 * time.Second)

	serviceInstance.connectionAccess.Lock()
	connCount := len(serviceInstance.connections)
	serviceInstance.connectionAccess.Unlock()
	if connCount < 2 {
		t.Errorf("expected at least 2 connections, got %d", connCount)
	}

	resp, err := http.Get(env.HTTPURL("/ping"))
	if err != nil {
		t.Fatal("GET /ping: ", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("expected 200, got ", resp.StatusCode)
	}
}

func TestLiveHTTPResponseCorrectness(t *testing.T) {
	env := requireLiveTestEnvironment(t)
	startLiveTestService(t, env, "quic", 1)

	t.Run("StatusCode", func(t *testing.T) {
		resp, err := http.Get(env.HTTPURL("/status/201"))
		if err != nil {
			t.Fatal("GET /status/201: ", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 201 {
			t.Error("expected 201, got ", resp.StatusCode)
		}
	})

	t.Run("CustomHeader", func(t *testing.T) {
		resp, err := http.Get(env.HTTPURL("/status/200"))
		if err != nil {
			t.Fatal("GET /status/200: ", err)
		}
		resp.Body.Close()
		customHeader := resp.Header.Get("X-Custom")
		if customHeader != "test-value" {
			t.Error("expected X-Custom=test-value, got ", customHeader)
		}
	})

	t.Run("PostEcho", func(t *testing.T) {
		resp, err := http.Post(env.HTTPURL("/echo"), "text/plain", strings.NewReader("payload"))
		if err != nil {
			t.Fatal("POST /echo: ", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatal("expected 200, got ", resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal("read body: ", err)
		}
		if string(body) != "payload" {
			t.Error("unexpected body: ", string(body))
		}
	})

	t.Run("RequestHeaders", func(t *testing.T) {
		request, err := http.NewRequest(http.MethodGet, env.HTTPURL("/headers"), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Test-Header", "test-value")

		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal("GET /headers: ", err)
		}
		defer resp.Body.Close()

		var originRequest testOriginRequest
		if err := json.NewDecoder(resp.Body).Decode(&originRequest); err != nil {
			t.Fatal(err)
		}
		if originRequest.Headers.Get("X-Test-Header") != "test-value" {
			t.Fatalf("expected X-Test-Header to reach origin, got %q", originRequest.Headers.Get("X-Test-Header"))
		}
		if originRequest.Host == "" {
			t.Fatal("expected origin request host to be populated")
		}
	})
}

func TestLiveWebsocketIntegration(t *testing.T) {
	env := requireLiveTestEnvironment(t)
	startLiveTestService(t, env, "quic", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, _, _, err := ws.Dial(ctx, env.WebSocketURL("/ws"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := wsutil.WriteClientMessage(conn, ws.OpBinary, []byte("hello")); err != nil {
		t.Fatal(err)
	}

	data, opCode, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatal(err)
	}
	if opCode != ws.OpBinary {
		t.Fatalf("expected binary frame, got %v", opCode)
	}
	if string(data) != "hello" {
		t.Fatalf("expected echoed payload, got %q", data)
	}
}

func TestLiveStreamingIntegration(t *testing.T) {
	env := requireLiveTestEnvironment(t)
	startLiveTestService(t, env, "quic", 1)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(env.HTTPURL("/sse?count=4&interval_ms=100"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if contentType := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/event-stream") {
		t.Fatalf("expected SSE content type, got %q", contentType)
	}

	reader := bufio.NewReader(resp.Body)
	for index := 1; index <= 4; index++ {
		event := readNextSSEEvent(t, reader)
		if event != strconv.Itoa(index) {
			t.Fatalf("expected SSE event %d, got %q", index, event)
		}
	}
}

func TestLiveGracefulClose(t *testing.T) {
	env := requireLiveTestEnvironment(t)

	serviceInstance := newTestService(t, env.token, "quic", 1)
	serviceInstance.gracePeriod = 2 * time.Second
	err := serviceInstance.Start()
	if err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, env.baseURL, 2*time.Minute)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(env.HTTPURL("/sse?count=50&interval_ms=200"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	if firstEvent := readNextSSEEvent(t, reader); firstEvent != "1" {
		t.Fatalf("expected first SSE event to be 1, got %q", firstEvent)
	}

	closeStarted := time.Now()
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- serviceInstance.Close()
	}()

	eventsAfterClose := 0
	for eventsAfterClose < 3 {
		event, err := readNextSSEEventValue(reader)
		if err != nil {
			break
		}
		if event != "" {
			eventsAfterClose++
		}
	}

	err = <-closeDone
	if err != nil {
		t.Fatal("Close: ", err)
	}

	closeDuration := time.Since(closeStarted)
	if closeDuration < time.Second {
		t.Fatalf("expected graceful shutdown to wait for in-flight stream, got %s", closeDuration)
	}
	if closeDuration > 8*time.Second {
		t.Fatalf("expected graceful shutdown to complete within 8s, got %s", closeDuration)
	}
	if eventsAfterClose == 0 {
		t.Fatal("expected at least one SSE event after Close was triggered")
	}

	if serviceInstance.ctx.Err() == nil {
		t.Error("expected context to be cancelled after Close")
	}

	serviceInstance.connectionAccess.Lock()
	remaining := serviceInstance.connections
	serviceInstance.connectionAccess.Unlock()
	if remaining != nil {
		t.Error("expected connections to be nil after Close, got ", len(remaining))
	}
}

func readNextSSEEvent(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	event, err := readNextSSEEventValue(reader)
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func readNextSSEEventValue(reader *bufio.Reader) (string, error) {
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data: ") {
			return strings.TrimPrefix(line, "data: "), nil
		}
	}
}
