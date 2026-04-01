package cloudflared

import (
	"testing"

	"github.com/sagernet/sing/common/logger"
)

func newTestIngressService(t *testing.T) *Service {
	t.Helper()
	configManager, err := NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	return &Service{
		logger:        logger.NOP(),
		configManager: configManager,
	}
}

func mustResolvedService(t *testing.T, rawService string) ResolvedService {
	t.Helper()
	service, err := parseResolvedService(rawService, defaultOriginRequestConfig())
	if err != nil {
		t.Fatal(err)
	}
	return service
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
	serviceInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{
			{Hostname: "test.example.com", Service: mustResolvedService(t, "http://localhost:8080")},
			{Hostname: "*.example.com", Service: mustResolvedService(t, "http://localhost:9090")},
			{Service: mustResolvedService(t, "http_status:404")},
		},
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
	serviceInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{
			{Hostname: "foo.com", Service: mustResolvedService(t, "http://127.0.0.1:8083")},
			{Service: mustResolvedService(t, "http_status:404")},
		},
	}

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
	serviceInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{
			{Service: mustResolvedService(t, "http_status:404")},
		},
	}

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

func TestParseResolvedServiceCanonicalizesWebSocketOrigin(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		rawService string
		wantScheme string
	}{
		{rawService: "ws://127.0.0.1:8080", wantScheme: "http"},
		{rawService: "wss://127.0.0.1:8443", wantScheme: "https"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.rawService, func(t *testing.T) {
			t.Parallel()
			service, err := parseResolvedService(testCase.rawService, defaultOriginRequestConfig())
			if err != nil {
				t.Fatal(err)
			}
			if service.BaseURL == nil {
				t.Fatal("expected base URL")
			}
			if service.BaseURL.Scheme != testCase.wantScheme {
				t.Fatalf("expected scheme %q, got %q", testCase.wantScheme, service.BaseURL.Scheme)
			}
			if service.Service != testCase.rawService {
				t.Fatalf("expected raw service to stay %q, got %q", testCase.rawService, service.Service)
			}
		})
	}
}

func TestParseResolvedServiceGenericStreamSchemeWithoutPort(t *testing.T) {
	t.Parallel()
	service, err := parseResolvedService("ftp://127.0.0.1", defaultOriginRequestConfig())
	if err != nil {
		t.Fatal(err)
	}
	if service.Kind != ResolvedServiceStream {
		t.Fatalf("expected stream service, got %v", service.Kind)
	}
	if service.Destination.AddrString() != "127.0.0.1" {
		t.Fatalf("expected destination host 127.0.0.1, got %s", service.Destination.AddrString())
	}
	if service.Destination.Port != 0 {
		t.Fatalf("expected destination port 0, got %d", service.Destination.Port)
	}
	if service.StreamHasPort {
		t.Fatal("expected generic stream service without port to report missing port")
	}
}

func TestParseResolvedServiceGenericStreamSchemeWithPort(t *testing.T) {
	t.Parallel()
	service, err := parseResolvedService("ftp://127.0.0.1:21", defaultOriginRequestConfig())
	if err != nil {
		t.Fatal(err)
	}
	if service.Kind != ResolvedServiceStream {
		t.Fatalf("expected stream service, got %v", service.Kind)
	}
	if service.Destination.String() != "127.0.0.1:21" {
		t.Fatalf("expected destination 127.0.0.1:21, got %s", service.Destination)
	}
	if !service.StreamHasPort {
		t.Fatal("expected generic stream service with explicit port to be dialable")
	}
}

func TestParseResolvedServiceSSHDefaultPort(t *testing.T) {
	t.Parallel()
	service, err := parseResolvedService("ssh://127.0.0.1", defaultOriginRequestConfig())
	if err != nil {
		t.Fatal(err)
	}
	if service.Destination.String() != "127.0.0.1:22" {
		t.Fatalf("expected destination 127.0.0.1:22, got %s", service.Destination)
	}
	if !service.StreamHasPort {
		t.Fatal("expected ssh stream service to apply default port")
	}
}

func TestParseResolvedServiceTCPDefaultPort(t *testing.T) {
	t.Parallel()
	service, err := parseResolvedService("tcp://127.0.0.1", defaultOriginRequestConfig())
	if err != nil {
		t.Fatal(err)
	}
	if service.Destination.String() != "127.0.0.1:7864" {
		t.Fatalf("expected destination 127.0.0.1:7864, got %s", service.Destination)
	}
	if !service.StreamHasPort {
		t.Fatal("expected tcp stream service to apply default port")
	}
}

func TestResolveHTTPServiceWebSocketOrigin(t *testing.T) {
	t.Parallel()
	serviceInstance := newTestIngressService(t)
	serviceInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{
			{Hostname: "foo.com", Service: mustResolvedService(t, "ws://127.0.0.1:8083")},
			{Service: mustResolvedService(t, "http_status:404")},
		},
	}

	_, requestURL, err := serviceInstance.resolveHTTPService("https://foo.com/path?q=1")
	if err != nil {
		t.Fatal(err)
	}
	if requestURL != "http://127.0.0.1:8083/path?q=1" {
		t.Fatalf("expected websocket origin to be canonicalized, got %s", requestURL)
	}
}
