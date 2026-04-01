package cloudflared

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing/common/logger"
	"golang.org/x/net/http2"
)

type trackingReadCloser struct {
	reader io.Reader
	closed bool
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

type requestResponseStream struct {
	reader *bytes.Reader
	writes bytes.Buffer
	closed bool
}

func newRequestResponseStream(body string) *requestResponseStream {
	return &requestResponseStream{reader: bytes.NewReader([]byte(body))}
}

func (s *requestResponseStream) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *requestResponseStream) Write(p []byte) (int, error) {
	return s.writes.Write(p)
}

func (s *requestResponseStream) Close() error {
	s.closed = true
	return nil
}

func TestHTTP2StreamAndDataStreamHelpers(t *testing.T) {
	t.Parallel()

	reader := &trackingReadCloser{reader: bytes.NewBufferString("input")}
	output := &bytes.Buffer{}
	stream := newHTTP2Stream(reader, output)

	buffer := make([]byte, 5)
	n, err := stream.Read(buffer)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "input" {
		t.Fatalf("unexpected read data %q", buffer[:n])
	}
	if _, err := stream.Write([]byte("output")); err != nil {
		t.Fatal(err)
	}
	if output.String() != "output" {
		t.Fatalf("unexpected write data %q", output.String())
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if !reader.closed {
		t.Fatal("expected http2 stream close to close underlying reader")
	}

	dataReader := &trackingReadCloser{reader: bytes.NewBufferString("data")}
	dataWriter := &captureHTTP2Writer{}
	dataStream := &http2DataStream{
		reader:  dataReader,
		writer:  dataWriter,
		flusher: dataWriter,
		state:   &http2FlushState{shouldFlush: true},
		logger:  logger.NOP(),
	}
	readBuffer := make([]byte, 4)
	n, err = dataStream.Read(readBuffer)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(readBuffer[:n]) != "data" {
		t.Fatalf("unexpected data stream read %q", readBuffer[:n])
	}
	if err := dataStream.Close(); err != nil {
		t.Fatal(err)
	}
	if !dataReader.closed {
		t.Fatal("expected data stream close to close underlying reader")
	}
}

func TestHTTP2FlushWriterFlushesAndTrailers(t *testing.T) {
	t.Parallel()

	writer := &captureHTTP2Writer{}
	flushWriter := &http2FlushWriter{w: writer, flusher: writer}
	if _, err := flushWriter.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	if writer.flushCount != 1 || string(writer.body) != "body" {
		t.Fatalf("unexpected flush writer state %#v", writer)
	}

	responseWriter := &http2ResponseWriter{
		writer:     writer,
		flusher:    writer,
		flushState: &http2FlushState{},
	}
	responseWriter.AddTrailer("X-Skipped", "ignored")
	if writer.Header().Get(http2.TrailerPrefix+"X-Skipped") != "" {
		t.Fatal("unexpected trailer before headers are sent")
	}
	if err := responseWriter.WriteResponse(nil, encodeResponseHeaders(http.StatusOK, http.Header{})); err != nil {
		t.Fatal(err)
	}
	responseWriter.AddTrailer("X-Test-Trailer", "trailer-value")
	if got := writer.Header().Get(http2.TrailerPrefix + "X-Test-Trailer"); got != "trailer-value" {
		t.Fatalf("unexpected trailer value %q", got)
	}
}

func TestHTTP2ServeProxiesPOSTBodyAndTrailers(t *testing.T) {
	t.Parallel()

	serviceInstance := newSpecialService(t)
	serviceInstance.directTransports = make(map[string]*http.Transport)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(body); got != "ping" {
			t.Fatalf("unexpected origin body %q", got)
		}
		w.Header().Add("Trailer", "X-Origin-Trailer")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("origin-response"))
		w.Header().Set("X-Origin-Trailer", "trailer-value")
	}))
	defer origin.Close()

	serviceInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{{
			Service: mustResolvedService(t, origin.URL),
		}},
	}

	_, clientConn, _, errCh := startInMemoryHTTP2Connection(t, serviceInstance)
	streamRequest, err := http.NewRequest(http.MethodPost, "http://example.com/upload?via=h2", bytes.NewBufferString("ping"))
	if err != nil {
		t.Fatal(err)
	}

	response, err := clientConn.RoundTrip(streamRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("unexpected status %d", response.StatusCode)
	}
	if string(body) != "origin-response" {
		t.Fatalf("unexpected response body %q", body)
	}
	if got := response.Trailer.Get("X-Origin-Trailer"); got != "trailer-value" {
		t.Fatalf("unexpected trailer %q", got)
	}

	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("unexpected serve error %v", err)
		}
	default:
	}
}
