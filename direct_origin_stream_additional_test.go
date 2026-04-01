//go:build !windows

package cloudflared

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func unixSocketPathForTest(t *testing.T) string {
	t.Helper()

	path := filepath.Join(os.TempDir(), "cf-direct-origin-"+time.Now().Format("150405.000000000")+".sock")
	_ = os.Remove(path)
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func TestHandleHTTPServiceDirectOriginUnix(t *testing.T) {
	t.Parallel()

	originalProxy := proxyFromEnvironment
	proxyFromEnvironment = func(request *http.Request) (*url.URL, error) {
		return nil, nil
	}
	defer func() {
		proxyFromEnvironment = originalProxy
	}()

	listener, err := net.Listen("unix", unixSocketPathForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go serveTestHTTPOverListener(listener, func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if got := string(body); got != "ping" {
			t.Fatalf("unexpected body %q", got)
		}
		if r.URL.Path != "/direct" || r.URL.RawQuery != "value=1" {
			t.Fatalf("unexpected URL %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("unix-direct-ok"))
	})

	serviceInstance := &Service{
		logger:           logger.NOP(),
		directTransports: make(map[string]*http.Transport),
	}
	respWriter := &fakeConnectResponseWriter{}
	stream := newRequestResponseStream("ping")
	serviceInstance.handleHTTPService(context.Background(), stream, respWriter, &ConnectRequest{
		Type: ConnectionTypeHTTP,
		Dest: "http://localhost/direct?value=1",
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodPost},
			{Key: metadataHTTPHost, Val: "example.com"},
			{Key: metadataHTTPHeader + ":Content-Length", Val: "4"},
		},
	}, ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: listener.Addr().String(),
		BaseURL:  &url.URL{Scheme: "http", Host: "localhost"},
	})

	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusAccepted {
		t.Fatalf("unexpected status %d", respWriter.status)
	}
	if got := stream.writes.String(); got != "unix-direct-ok" {
		t.Fatalf("unexpected response body %q", got)
	}
}

func TestHandleHTTPServiceDirectOriginUnixTLS(t *testing.T) {
	originalProxy := proxyFromEnvironment
	proxyFromEnvironment = func(request *http.Request) (*url.URL, error) {
		return nil, nil
	}
	defer func() {
		proxyFromEnvironment = originalProxy
	}()

	caCertificate, caPrivateKey, caPEM := createTestCertificateAuthority(t, "test origin root")
	caPath := writeTempPEM(t, caPEM)
	listener, err := net.Listen("unix", unixSocketPathForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{createTestServerCertificate(t, caCertificate, caPrivateKey, "origin.example.com")},
	})

	go serveTestHTTPOverListener(tlsListener, func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Fatal("expected TLS request")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("unix-tls-ok"))
	})

	serviceInstance := &Service{
		logger:           logger.NOP(),
		directTransports: make(map[string]*http.Transport),
	}
	respWriter := &fakeConnectResponseWriter{}
	stream := newRequestResponseStream("")
	serviceInstance.handleHTTPService(context.Background(), stream, respWriter, &ConnectRequest{
		Type: ConnectionTypeHTTP,
		Dest: "https://localhost/secure",
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: "example.com"},
		},
	}, ResolvedService{
		Kind:     ResolvedServiceUnixTLS,
		UnixPath: listener.Addr().String(),
		BaseURL:  &url.URL{Scheme: "https", Host: "localhost"},
		OriginRequest: OriginRequestConfig{
			CAPool:           caPath,
			OriginServerName: "origin.example.com",
		},
	})

	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusOK {
		t.Fatalf("unexpected status %d", respWriter.status)
	}
	if got := stream.writes.String(); got != "unix-tls-ok" {
		t.Fatalf("unexpected response body %q", got)
	}
}
