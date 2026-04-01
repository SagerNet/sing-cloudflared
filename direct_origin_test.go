package cloudflared

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func TestNewDirectOriginTransportUnix(t *testing.T) {
	t.Parallel()
	socketPath := fmt.Sprintf("/tmp/cf-origin-%d.sock", time.Now().UnixNano())
	if runtime.GOOS == "windows" {
		socketPath = filepath.Join(os.TempDir(), fmt.Sprintf("cf-origin-%d.sock", time.Now().UnixNano()))
	}
	_ = os.Remove(socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go serveTestHTTPOverListener(listener, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("unix-ok"))
	})

	serviceInstance := &Service{
		directTransports: make(map[string]*http.Transport),
	}
	transport, cleanup, err := serviceInstance.newDirectOriginTransport(ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: socketPath,
		BaseURL: &url.URL{
			Scheme: "http",
			Host:   "localhost",
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	client := &http.Client{Transport: transport}
	resp, err := client.Get("http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "unix-ok" {
		t.Fatalf("unexpected response body: %q", string(body))
	}
}

func serveTestHTTPOverListener(listener net.Listener, handler func(http.ResponseWriter, *http.Request)) {
	server := &http.Server{Handler: http.HandlerFunc(handler)}
	_ = server.Serve(listener)
}

func TestDirectOriginTransportCacheReusesMatchingTransports(t *testing.T) {
	t.Parallel()
	serviceInstance := &Service{
		directTransports: make(map[string]*http.Transport),
	}
	service := ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: "/tmp/test.sock",
		BaseURL:  &url.URL{Scheme: "http", Host: "localhost"},
	}

	transport1, _, err := serviceInstance.newDirectOriginTransport(service, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	transport2, _, err := serviceInstance.newDirectOriginTransport(service, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if transport1 != transport2 {
		t.Fatal("expected matching direct-origin transports to be reused")
	}

	transport3, _, err := serviceInstance.newDirectOriginTransport(service, "other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if transport3 == transport1 {
		t.Fatal("expected different cache keys to produce different transports")
	}
}

func TestApplyConfigClearsDirectOriginTransportCache(t *testing.T) {
	t.Parallel()
	configManager, err := NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	serviceInstance := &Service{
		logger:           logger.NOP(),
		configManager:    configManager,
		directTransports: make(map[string]*http.Transport),
	}
	service := ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: "/tmp/test.sock",
		BaseURL:  &url.URL{Scheme: "http", Host: "localhost"},
	}

	transport1, _, err := serviceInstance.newDirectOriginTransport(service, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	result := serviceInstance.ApplyConfig(1, []byte(`{"ingress":[{"service":"http_status:503"}]}`))
	if result.Err != nil {
		t.Fatal(result.Err)
	}

	transport2, _, err := serviceInstance.newDirectOriginTransport(service, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if transport1 == transport2 {
		t.Fatal("expected ApplyConfig to clear direct-origin transport cache")
	}
}
