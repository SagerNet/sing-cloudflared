package transport

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/sagernet/sing-cloudflared/internal/protocol"
	"github.com/sagernet/sing/common/logger"
)

type captureHTTP2Writer struct {
	header     http.Header
	flushCount int
	statusCode int
	body       []byte
	panicWrite bool
}

func (w *captureHTTP2Writer) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *captureHTTP2Writer) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func (w *captureHTTP2Writer) Write(p []byte) (int, error) {
	if w.panicWrite {
		panic("write after close")
	}
	w.body = append(w.body, p...)
	return len(p), nil
}

func (w *captureHTTP2Writer) Flush() {
	w.flushCount++
}

func encodeResponseHeadersForTest(statusCode int, header http.Header) []protocol.Metadata {
	metadata := make([]protocol.Metadata, 0, len(header)+1)
	metadata = append(metadata, protocol.Metadata{
		Key: protocol.MetadataHTTPStatus,
		Val: strconv.Itoa(statusCode),
	})
	for name, values := range header {
		for _, value := range values {
			metadata = append(metadata, protocol.Metadata{
				Key: protocol.MetadataHTTPHeader + ":" + name,
				Val: value,
			})
		}
	}
	return metadata
}

func TestHTTP2NonStreamingResponseDoesNotFlush(t *testing.T) {
	t.Parallel()
	writer := &captureHTTP2Writer{}
	flushState := &HTTP2FlushState{}
	respWriter := &HTTP2ResponseWriter{
		writer:     writer,
		flusher:    writer,
		flushState: flushState,
	}

	err := respWriter.WriteResponse(nil, encodeResponseHeadersForTest(http.StatusOK, http.Header{
		"Content-Type":   []string{"application/json"},
		"Content-Length": []string{"2"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if writer.flushCount != 0 {
		t.Fatalf("expected no header flush for non-streaming response, got %d", writer.flushCount)
	}

	stream := &HTTP2DataStream{
		writer:  writer,
		flusher: writer,
		state:   flushState,
		logger:  logger.NOP(),
	}
	_, err = stream.Write([]byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	if writer.flushCount != 0 {
		t.Fatalf("expected no body flush for non-streaming response, got %d", writer.flushCount)
	}
}

func TestHTTP2StreamingResponsesFlush(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		header http.Header
	}{
		{
			name: "sse",
			header: http.Header{
				"Content-Type":   []string{"text/event-stream"},
				"Content-Length": []string{"1"},
			},
		},
		{
			name: "grpc",
			header: http.Header{
				"Content-Type":   []string{"application/grpc"},
				"Content-Length": []string{"1"},
			},
		},
		{
			name: "ndjson",
			header: http.Header{
				"Content-Type":   []string{"application/x-ndjson"},
				"Content-Length": []string{"1"},
			},
		},
		{
			name: "chunked",
			header: http.Header{
				"Content-Type":      []string{"application/json"},
				"Content-Length":    []string{"-1"},
				"Transfer-Encoding": []string{"chunked"},
			},
		},
		{
			name: "no-content-length",
			header: http.Header{
				"Content-Type": []string{"application/json"},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			writer := &captureHTTP2Writer{}
			flushState := &HTTP2FlushState{}
			respWriter := &HTTP2ResponseWriter{
				writer:     writer,
				flusher:    writer,
				flushState: flushState,
			}

			err := respWriter.WriteResponse(nil, encodeResponseHeadersForTest(http.StatusOK, testCase.header))
			if err != nil {
				t.Fatal(err)
			}
			if writer.flushCount == 0 {
				t.Fatal("expected header flush for streaming response")
			}

			stream := &HTTP2DataStream{
				writer:  writer,
				flusher: writer,
				state:   flushState,
				logger:  logger.NOP(),
			}
			_, err = stream.Write([]byte("chunk"))
			if err != nil {
				t.Fatal(err)
			}
			if writer.flushCount < 2 {
				t.Fatalf("expected body flush for streaming response, got %d flushes", writer.flushCount)
			}
		})
	}
}

func TestHTTP2DataStreamWriteRecoversPanic(t *testing.T) {
	t.Parallel()
	writer := &captureHTTP2Writer{panicWrite: true}
	stream := &HTTP2DataStream{
		writer:  writer,
		flusher: writer,
		state:   &HTTP2FlushState{shouldFlush: true},
		logger:  logger.NOP(),
	}

	_, err := stream.Write([]byte("panic"))
	if err != io.ErrClosedPipe {
		t.Fatalf("expected io.ErrClosedPipe, got %v", err)
	}
}

func TestHandleConfigurationUpdateDecodeFailureReturnsBadGateway(t *testing.T) {
	t.Parallel()
	writer := &captureHTTP2Writer{}
	connection := &HTTP2Connection{
		logger: logger.NOP(),
	}
	request, err := http.NewRequest(http.MethodPost, "https://example.com", bytes.NewBufferString("{"))
	if err != nil {
		t.Fatal(err)
	}

	connection.handleConfigurationUpdate(request, writer)

	if writer.statusCode != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, writer.statusCode)
	}
	meta := writer.Header().Get(protocol.H2HeaderResponseMeta)
	if !strings.Contains(meta, "cloudflared") {
		t.Fatalf("unexpected response meta: %q", meta)
	}
	if len(writer.body) != 0 {
		t.Fatalf("expected empty response body, got %q", string(writer.body))
	}
}
