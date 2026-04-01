package cloudflared

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

type trailerCaptureResponseWriter struct {
	status   int
	trailers http.Header
}

func (w *trailerCaptureResponseWriter) WriteResponse(responseError error, metadata []Metadata) error {
	for _, entry := range metadata {
		if entry.Key == metadataHTTPStatus {
			w.status = http.StatusOK
		}
	}
	return nil
}

func (w *trailerCaptureResponseWriter) AddTrailer(name, value string) {
	if w.trailers == nil {
		w.trailers = make(http.Header)
	}
	w.trailers.Add(name, value)
}

type captureReadWriteCloser struct {
	body []byte
}

func (c *captureReadWriteCloser) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *captureReadWriteCloser) Write(p []byte) (int, error) {
	c.body = append(c.body, p...)
	return len(p), nil
}

func (c *captureReadWriteCloser) Close() error {
	return nil
}

func TestRoundTripHTTPCopiesTrailers(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Trailer", "X-Test-Trailer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		w.Header().Set("X-Test-Trailer", "trailer-value")
	}))
	defer server.Close()

	transport, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", server.Client().Transport)
	}

	serviceInstance := &Service{
		logger: logger.NOP(),
	}
	stream := &captureReadWriteCloser{}
	respWriter := &trailerCaptureResponseWriter{}
	request := &ConnectRequest{
		Dest: server.URL,
		Type: ConnectionTypeHTTP,
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: "example.com"},
		},
	}

	serviceInstance.roundTripHTTP(context.Background(), stream, respWriter, request, ResolvedService{
		OriginRequest: defaultOriginRequestConfig(),
	}, transport)

	if got := respWriter.trailers.Get("X-Test-Trailer"); got != "trailer-value" {
		t.Fatalf("expected copied trailer, got %q", got)
	}
	if string(stream.body) != "ok" {
		t.Fatalf("unexpected response body %q", stream.body)
	}
}
