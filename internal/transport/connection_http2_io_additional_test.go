package transport

import (
	"bytes"
	"io"
	"net/http"
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

func TestHTTP2StreamAndDataStreamHelpers(t *testing.T) {
	t.Parallel()

	reader := &trackingReadCloser{reader: bytes.NewBufferString("input")}
	output := &bytes.Buffer{}
	stream := NewHTTP2Stream(reader, output)

	buffer := make([]byte, 5)
	n, err := stream.Read(buffer)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "input" {
		t.Fatalf("unexpected read data %q", buffer[:n])
	}
	_, err = stream.Write([]byte("output"))
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != "output" {
		t.Fatalf("unexpected write data %q", output.String())
	}
	err = stream.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !reader.closed {
		t.Fatal("expected http2 stream close to close underlying reader")
	}

	dataReader := &trackingReadCloser{reader: bytes.NewBufferString("data")}
	dataWriter := &captureHTTP2Writer{}
	dataStream := &HTTP2DataStream{
		reader:  dataReader,
		writer:  dataWriter,
		flusher: dataWriter,
		state:   &HTTP2FlushState{shouldFlush: true},
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
	err = dataStream.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !dataReader.closed {
		t.Fatal("expected data stream close to close underlying reader")
	}
}

func TestHTTP2FlushWriterFlushesAndTrailers(t *testing.T) {
	t.Parallel()

	writer := &captureHTTP2Writer{}
	flushWriter := &HTTP2FlushWriter{w: writer, flusher: writer}
	_, err := flushWriter.Write([]byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if writer.flushCount != 1 || string(writer.body) != "body" {
		t.Fatalf("unexpected flush writer state %#v", writer)
	}

	responseWriter := &HTTP2ResponseWriter{
		writer:     writer,
		flusher:    writer,
		flushState: &HTTP2FlushState{},
	}
	responseWriter.AddTrailer("X-Skipped", "ignored")
	if writer.Header().Get(http2.TrailerPrefix+"X-Skipped") != "" {
		t.Fatal("unexpected trailer before headers are sent")
	}
	err = responseWriter.WriteResponse(nil, encodeResponseHeadersForTest(http.StatusOK, http.Header{}))
	if err != nil {
		t.Fatal(err)
	}
	responseWriter.AddTrailer("X-Test-Trailer", "trailer-value")
	if got := writer.Header().Get(http2.TrailerPrefix + "X-Test-Trailer"); got != "trailer-value" {
		t.Fatalf("unexpected trailer value %q", got)
	}
}
