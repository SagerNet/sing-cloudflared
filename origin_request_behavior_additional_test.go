package cloudflared

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

func mustResolvedService(t *testing.T, rawService string) ResolvedService {
	t.Helper()
	service, err := parseResolvedService(rawService, defaultOriginRequestConfig())
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestRoundTripHTTPAppliesHostHeaderOverride(t *testing.T) {
	t.Parallel()

	const (
		originHost  = "origin.example.com"
		requestHost = "eyeball.example.com"
	)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != originHost {
			t.Fatalf("unexpected origin host %q", r.Host)
		}
		if got := r.Header.Get("X-Forwarded-Host"); got != requestHost {
			t.Fatalf("unexpected forwarded host %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("host-header-ok"))
	}))
	defer origin.Close()

	transport, isHTTPTransport := origin.Client().Transport.(*http.Transport)
	if !isHTTPTransport {
		t.Fatalf("unexpected transport type %T", origin.Client().Transport)
	}

	serviceInstance := &Service{
		logger: logger.NOP(),
	}
	stream := &captureReadWriteCloser{}
	respWriter := &fakeConnectResponseWriter{}
	request := &ConnectRequest{
		Dest: origin.URL,
		Type: ConnectionTypeHTTP,
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: requestHost},
		},
	}

	serviceInstance.roundTripHTTP(context.Background(), stream, respWriter, request, ResolvedService{
		OriginRequest: OriginRequestConfig{
			HTTPHostHeader: originHost,
		},
	}, transport)

	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusOK {
		t.Fatalf("unexpected status %d", respWriter.status)
	}
	if got := string(stream.body); got != "host-header-ok" {
		t.Fatalf("unexpected response body %q", got)
	}
}

func TestResolveHTTPServiceUsesIngressSchemeForRoundTrip(t *testing.T) {
	t.Parallel()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Fatal("expected TLS request to origin")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("https-origin-ok"))
	}))
	defer origin.Close()

	transport, isHTTPTransport := origin.Client().Transport.(*http.Transport)
	if !isHTTPTransport {
		t.Fatalf("unexpected transport type %T", origin.Client().Transport)
	}

	serviceInstance := newSpecialService(t)
	serviceInstance.configManager.Apply(1, []byte(`{"ingress":[{"service":"`+origin.URL+`"}]}`))

	resolved, originURL, err := serviceInstance.resolveHTTPService("http://example.com/secure?value=1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(originURL, "https://") {
		t.Fatalf("expected resolved origin URL to use ingress scheme, got %q", originURL)
	}

	stream := &captureReadWriteCloser{}
	respWriter := &fakeConnectResponseWriter{}
	request := &ConnectRequest{
		Dest: originURL,
		Type: ConnectionTypeHTTP,
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: "example.com"},
			{Key: metadataHTTPHeader + ":X-Forwarded-Proto", Val: "http"},
		},
	}

	serviceInstance.roundTripHTTP(context.Background(), stream, respWriter, request, resolved, transport)

	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusOK {
		t.Fatalf("unexpected status %d", respWriter.status)
	}
	if got := string(stream.body); got != "https-origin-ok" {
		t.Fatalf("unexpected response body %q", got)
	}
}
