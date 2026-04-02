package cloudflared

import (
	"testing"

	"github.com/sagernet/sing-cloudflared/internal/config"
	"github.com/sagernet/sing/common/logger"
)

func newTestIngressService(t *testing.T) *Service {
	t.Helper()
	configManager, err := config.NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	return &Service{
		logger:        logger.NOP(),
		configManager: configManager,
	}
}

func TestApplyConfig(t *testing.T) {
	t.Parallel()
	serviceInstance := newTestIngressService(t)

	config1 := []byte(`{"ingress":[{"hostname":"a.com","service":"http://localhost:80"},{"hostname":"b.com","service":"http://localhost:81"},{"service":"http_status:404"}]}`)
	result := serviceInstance.ApplyConfig(1, config1)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if result.LastAppliedVersion != 1 {
		t.Fatalf("expected version 1, got %d", result.LastAppliedVersion)
	}

	service, loaded := serviceInstance.configManager.Resolve("a.com", "/")
	if !loaded || service.Service != "http://localhost:80" {
		t.Fatalf("expected a.com to resolve to localhost:80, got %#v, loaded=%v", service, loaded)
	}

	result = serviceInstance.ApplyConfig(1, []byte(`{"ingress":[{"service":"http_status:503"}]}`))
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if result.LastAppliedVersion != 1 {
		t.Fatalf("same version should keep current version, got %d", result.LastAppliedVersion)
	}

	service, loaded = serviceInstance.configManager.Resolve("b.com", "/")
	if !loaded || service.Service != "http://localhost:81" {
		t.Fatalf("expected old rules to remain, got %#v, loaded=%v", service, loaded)
	}

	result = serviceInstance.ApplyConfig(2, []byte(`{"ingress":[{"service":"http_status:503"}]}`))
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if result.LastAppliedVersion != 2 {
		t.Fatalf("expected version 2, got %d", result.LastAppliedVersion)
	}

	service, loaded = serviceInstance.configManager.Resolve("anything.com", "/")
	if !loaded || service.StatusCode != 503 {
		t.Fatalf("expected catch-all status 503, got %#v, loaded=%v", service, loaded)
	}
}

func TestApplyConfigInvalidJSON(t *testing.T) {
	t.Parallel()
	serviceInstance := newTestIngressService(t)
	result := serviceInstance.ApplyConfig(1, []byte("not json"))
	if result.Err == nil {
		t.Fatal("expected parse error")
	}
	if result.LastAppliedVersion != -1 {
		t.Fatalf("expected version to stay -1, got %d", result.LastAppliedVersion)
	}
}

func TestDefaultConfigIsCatchAll503(t *testing.T) {
	t.Parallel()
	serviceInstance := newTestIngressService(t)

	service, loaded := serviceInstance.configManager.Resolve("any.example.com", "/")
	if !loaded {
		t.Fatal("expected default config to resolve catch-all rule")
	}
	if service.StatusCode != 503 {
		t.Fatalf("expected catch-all 503, got %#v", service)
	}
}

func TestResolveExactAndWildcard(t *testing.T) {
	t.Parallel()
	serviceInstance := newTestIngressService(t)
	configJSON := `{"ingress":[{"hostname":"test.example.com","service":"http://localhost:8080"},{"hostname":"*.example.com","service":"http://localhost:9090"},{"service":"http_status:404"}]}`
	result := serviceInstance.ApplyConfig(1, []byte(configJSON))
	if result.Err != nil {
		t.Fatal(result.Err)
	}

	service, loaded := serviceInstance.configManager.Resolve("test.example.com", "/")
	if !loaded || service.Service != "http://localhost:8080" {
		t.Fatalf("expected exact match, got %#v, loaded=%v", service, loaded)
	}

	service, loaded = serviceInstance.configManager.Resolve("sub.example.com", "/")
	if !loaded || service.Service != "http://localhost:9090" {
		t.Fatalf("expected wildcard match, got %#v, loaded=%v", service, loaded)
	}

	service, loaded = serviceInstance.configManager.Resolve("unknown.test", "/")
	if !loaded || service.StatusCode != 404 {
		t.Fatalf("expected catch-all 404, got %#v, loaded=%v", service, loaded)
	}
}

func TestResolveHTTPService(t *testing.T) {
	t.Parallel()
	serviceInstance := newTestIngressService(t)
	configJSON := `{"ingress":[{"hostname":"foo.com","service":"http://127.0.0.1:8083"},{"service":"http_status:404"}]}`
	serviceInstance.ApplyConfig(1, []byte(configJSON))

	service, requestURL, err := serviceInstance.resolveHTTPService("https://foo.com/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	if service.Destination.String() != "127.0.0.1:8083" {
		t.Fatalf("expected destination 127.0.0.1:8083, got %s", service.Destination)
	}
	if requestURL != "http://127.0.0.1:8083/path?q=1" {
		t.Fatalf("expected rewritten URL, got %s", requestURL)
	}
}

func TestResolveHTTPServiceStatus(t *testing.T) {
	t.Parallel()
	serviceInstance := newTestIngressService(t)
	serviceInstance.ApplyConfig(1, []byte(`{"ingress":[{"service":"http_status:404"}]}`))

	service, requestURL, err := serviceInstance.resolveHTTPService("https://any.com/path")
	if err != nil {
		t.Fatal(err)
	}
	if service.StatusCode != 404 {
		t.Fatalf("expected status 404, got %#v", service)
	}
	if requestURL != "https://any.com/path" {
		t.Fatalf("status service should keep request URL, got %s", requestURL)
	}
}

func TestResolveHTTPServiceWebSocketOrigin(t *testing.T) {
	t.Parallel()
	serviceInstance := newTestIngressService(t)
	configJSON := `{"ingress":[{"hostname":"foo.com","service":"ws://127.0.0.1:8083"},{"service":"http_status:404"}]}`
	serviceInstance.ApplyConfig(1, []byte(configJSON))

	_, requestURL, err := serviceInstance.resolveHTTPService("https://foo.com/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	if requestURL != "http://127.0.0.1:8083/path?q=1" {
		t.Fatalf("expected websocket origin to be canonicalized, got %s", requestURL)
	}
}
