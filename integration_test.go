package cloudflared

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestQUICIntegration(t *testing.T) {
	t.Parallel()
	token, testURL := requireEnvVars(t)
	startOriginServer(t)

	serviceInstance := newTestService(t, token, "quic", 1)
	err := serviceInstance.Start()
	if err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, testURL, 30*time.Second)

	resp, err := http.Get(testURL + "/ping")
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

func TestHTTP2Integration(t *testing.T) {
	t.Parallel()
	token, testURL := requireEnvVars(t)
	startOriginServer(t)

	serviceInstance := newTestService(t, token, "http2", 1)
	err := serviceInstance.Start()
	if err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, testURL, 30*time.Second)

	resp, err := http.Get(testURL + "/ping")
	if err != nil {
		t.Fatal("GET /ping: ", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatal("expected 200, got ", resp.StatusCode)
	}
}

func TestMultipleHAConnections(t *testing.T) {
	t.Parallel()
	token, testURL := requireEnvVars(t)
	startOriginServer(t)

	serviceInstance := newTestService(t, token, "quic", 2)
	err := serviceInstance.Start()
	if err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, testURL, 30*time.Second)

	time.Sleep(3 * time.Second)

	serviceInstance.connectionAccess.Lock()
	connCount := len(serviceInstance.connections)
	serviceInstance.connectionAccess.Unlock()
	if connCount < 2 {
		t.Errorf("expected at least 2 connections, got %d", connCount)
	}

	resp, err := http.Get(testURL + "/ping")
	if err != nil {
		t.Fatal("GET /ping: ", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("expected 200, got ", resp.StatusCode)
	}
}

func TestHTTPResponseCorrectness(t *testing.T) {
	t.Parallel()
	token, testURL := requireEnvVars(t)
	startOriginServer(t)

	serviceInstance := newTestService(t, token, "quic", 1)
	err := serviceInstance.Start()
	if err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, testURL, 30*time.Second)

	t.Run("StatusCode", func(t *testing.T) {
		t.Parallel()
		resp, err := http.Get(testURL + "/status/201")
		if err != nil {
			t.Fatal("GET /status/201: ", err)
		}
		resp.Body.Close()
		if resp.StatusCode != 201 {
			t.Error("expected 201, got ", resp.StatusCode)
		}
	})

	t.Run("CustomHeader", func(t *testing.T) {
		t.Parallel()
		resp, err := http.Get(testURL + "/status/200")
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
		t.Parallel()
		resp, err := http.Post(testURL+"/echo", "text/plain", strings.NewReader("payload"))
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
}

func TestGracefulClose(t *testing.T) {
	t.Parallel()
	token, testURL := requireEnvVars(t)
	startOriginServer(t)

	serviceInstance := newTestService(t, token, "quic", 1)
	err := serviceInstance.Start()
	if err != nil {
		t.Fatal("Start: ", err)
	}

	waitForTunnel(t, testURL, 30*time.Second)

	err = serviceInstance.Close()
	if err != nil {
		t.Fatal("Close: ", err)
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
