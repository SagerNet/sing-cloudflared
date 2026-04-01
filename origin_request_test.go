package cloudflared

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestOriginTLSServerName(t *testing.T) {
	t.Parallel()
	t.Run("origin server name overrides host", func(t *testing.T) {
		t.Parallel()
		serverName := originTLSServerName(OriginRequestConfig{
			OriginServerName: "origin.example.com",
			MatchSNIToHost:   true,
		}, "request.example.com")
		if serverName != "origin.example.com" {
			t.Fatalf("expected origin.example.com, got %s", serverName)
		}
	})

	t.Run("match sni to host strips port", func(t *testing.T) {
		t.Parallel()
		serverName := originTLSServerName(OriginRequestConfig{
			MatchSNIToHost: true,
		}, "request.example.com:443")
		if serverName != "request.example.com" {
			t.Fatalf("expected request.example.com, got %s", serverName)
		}
	})

	t.Run("match sni to host uses http host header", func(t *testing.T) {
		t.Parallel()
		serverName := originTLSServerName(OriginRequestConfig{
			MatchSNIToHost: true,
		}, effectiveOriginHost(OriginRequestConfig{
			HTTPHostHeader: "origin.example.com",
			MatchSNIToHost: true,
		}, "request.example.com"))
		if serverName != "origin.example.com" {
			t.Fatalf("expected origin.example.com, got %s", serverName)
		}
	})

	t.Run("match sni to host strips port from http host header", func(t *testing.T) {
		t.Parallel()
		serverName := originTLSServerName(OriginRequestConfig{
			MatchSNIToHost: true,
		}, effectiveOriginHost(OriginRequestConfig{
			HTTPHostHeader: "origin.example.com:8443",
			MatchSNIToHost: true,
		}, "request.example.com"))
		if serverName != "origin.example.com" {
			t.Fatalf("expected origin.example.com, got %s", serverName)
		}
	})

	t.Run("disabled match keeps empty server name", func(t *testing.T) {
		t.Parallel()
		serverName := originTLSServerName(OriginRequestConfig{}, "request.example.com")
		if serverName != "" {
			t.Fatalf("expected empty server name, got %s", serverName)
		}
	})
}

func TestNewOriginTLSConfigErrorsOnMissingCAPool(t *testing.T) {
	t.Parallel()
	originalBaseLoader := loadOriginCABasePool
	loadOriginCABasePool = func() (*x509.CertPool, error) {
		return x509.NewCertPool(), nil
	}
	defer func() {
		loadOriginCABasePool = originalBaseLoader
	}()

	_, err := newOriginTLSConfig(OriginRequestConfig{
		CAPool: "/path/does/not/exist.pem",
	}, "request.example.com")
	if err == nil {
		t.Fatal("expected error for missing ca pool")
	}
}

func TestOriginTransportUsesProxyFromEnvironmentOnly(t *testing.T) {
	t.Parallel()
	originalProxyFromEnvironment := proxyFromEnvironment
	proxyFromEnvironment = func(request *http.Request) (*url.URL, error) {
		return url.Parse("http://proxy.example.com:8080")
	}
	defer func() {
		proxyFromEnvironment = originalProxyFromEnvironment
	}()

	serviceInstance := &Service{}
	transport, cleanup, err := serviceInstance.newDirectOriginTransport(ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: "/tmp/test.sock",
		OriginRequest: OriginRequestConfig{
			ProxyAddress: "127.0.0.1",
			ProxyPort:    8081,
			ProxyType:    "http",
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	proxyURL, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL == nil || proxyURL.String() != "http://proxy.example.com:8080" {
		t.Fatalf("expected environment proxy URL, got %#v", proxyURL)
	}
}

func TestNewDirectOriginTransportNoHappyEyeballs(t *testing.T) {
	t.Parallel()
	serviceInstance := &Service{}
	transport, cleanup, err := serviceInstance.newDirectOriginTransport(ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: "/tmp/test.sock",
		OriginRequest: OriginRequestConfig{
			NoHappyEyeballs: true,
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if transport.Proxy == nil {
		t.Fatal("expected proxy function to be configured from environment")
	}
	if transport.DialContext == nil {
		t.Fatal("expected custom direct dial context")
	}
}

func TestNewRouterOriginTransportPropagatesTLSConfigError(t *testing.T) {
	t.Parallel()
	originalBaseLoader := loadOriginCABasePool
	loadOriginCABasePool = func() (*x509.CertPool, error) {
		return x509.NewCertPool(), nil
	}
	defer func() {
		loadOriginCABasePool = originalBaseLoader
	}()

	serviceInstance := &Service{}
	_, _, err := serviceInstance.newRouterOriginTransport(context.Background(), M.Socksaddr{}, OriginRequestConfig{
		CAPool: "/path/does/not/exist.pem",
	}, "")
	if err == nil {
		t.Fatal("expected transport build error")
	}
}

func TestNormalizeOriginRequestSetsKeepAliveAndEmptyUserAgent(t *testing.T) {
	t.Parallel()
	request, err := http.NewRequest(http.MethodGet, "https://example.com/path", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	request = normalizeOriginRequest(ConnectionTypeHTTP, request, OriginRequestConfig{})
	if connection := request.Header.Get("Connection"); connection != "keep-alive" {
		t.Fatalf("expected keep-alive connection header, got %q", connection)
	}
	if values, exists := request.Header["User-Agent"]; !exists || len(values) != 1 || values[0] != "" {
		t.Fatalf("expected empty User-Agent header, got %#v", request.Header["User-Agent"])
	}
}

func TestNormalizeOriginRequestDisableChunkedEncoding(t *testing.T) {
	t.Parallel()
	request, err := http.NewRequest(http.MethodPost, "https://example.com/path", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	request.TransferEncoding = []string{"chunked"}
	request.Header.Set("Content-Length", "7")

	request = normalizeOriginRequest(ConnectionTypeHTTP, request, OriginRequestConfig{
		DisableChunkedEncoding: true,
	})
	if len(request.TransferEncoding) != 2 || request.TransferEncoding[0] != "gzip" || request.TransferEncoding[1] != "deflate" {
		t.Fatalf("unexpected transfer encoding: %#v", request.TransferEncoding)
	}
	if request.ContentLength != 7 {
		t.Fatalf("expected content length 7, got %d", request.ContentLength)
	}
}

func TestNormalizeOriginRequestWebsocket(t *testing.T) {
	t.Parallel()
	request, err := http.NewRequest(http.MethodGet, "https://example.com/path", io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}

	request = normalizeOriginRequest(ConnectionTypeWebsocket, request, OriginRequestConfig{})
	if connection := request.Header.Get("Connection"); connection != "Upgrade" {
		t.Fatalf("expected websocket connection header, got %q", connection)
	}
	if upgrade := request.Header.Get("Upgrade"); upgrade != "websocket" {
		t.Fatalf("expected websocket upgrade header, got %q", upgrade)
	}
	if version := request.Header.Get("Sec-Websocket-Version"); version != "13" {
		t.Fatalf("expected websocket version 13, got %q", version)
	}
	if request.ContentLength != 0 {
		t.Fatalf("expected websocket content length 0, got %d", request.ContentLength)
	}
	if request.Body != nil {
		t.Fatal("expected websocket body to be nil")
	}
}

func createTestCertificatePEM(t *testing.T, commonName string) ([]byte, *x509.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate
}

func writeTempPEM(t *testing.T, pemData []byte) string {
	t.Helper()
	path := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
