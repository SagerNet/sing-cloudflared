package cloudflared

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/logger"
)

type mockReadWriteCloser struct {
	reader strings.Reader
	writes []byte
}

func (m *mockReadWriteCloser) Read(p []byte) (int, error) {
	return m.reader.Read(p)
}

func (m *mockReadWriteCloser) Write(p []byte) (int, error) {
	m.writes = append(m.writes, p...)
	return len(p), nil
}

func (m *mockReadWriteCloser) Close() error {
	return nil
}

func TestNOPCloserReadWriterCloseOnlyStopsReads(t *testing.T) {
	t.Parallel()
	inner := &mockReadWriteCloser{reader: *strings.NewReader("payload")}
	wrapper := &nopCloserReadWriter{ReadWriteCloser: inner}

	if err := wrapper.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := wrapper.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected read to fail after close")
	}

	if _, err := wrapper.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if string(inner.writes) != "response" {
		t.Fatalf("unexpected writes %q", inner.writes)
	}
}

func TestNOPCloserReadWriterTracksEOF(t *testing.T) {
	t.Parallel()
	inner := &mockReadWriteCloser{reader: *strings.NewReader("")}
	wrapper := &nopCloserReadWriter{ReadWriteCloser: inner}

	if _, err := wrapper.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
	if _, err := wrapper.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected cached EOF, got %v", err)
	}
}

type fakeQUICStream struct {
	reader           strings.Reader
	cancelWriteCount int
}

func (s *fakeQUICStream) Read(p []byte) (int, error)      { return s.reader.Read(p) }
func (s *fakeQUICStream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *fakeQUICStream) Close() error                    { return nil }
func (s *fakeQUICStream) CancelRead(quic.StreamErrorCode) {}
func (s *fakeQUICStream) CancelWrite(quic.StreamErrorCode) {
	s.cancelWriteCount++
}
func (s *fakeQUICStream) SetWriteDeadline(time.Time) error { return nil }

func TestHandleStreamCancelsWriteOnSignatureError(t *testing.T) {
	t.Parallel()
	stream := &fakeQUICStream{reader: *strings.NewReader("broken")}
	connection := &QUICConnection{logger: logger.NOP()}

	connection.handleStream(context.Background(), stream, nil)
	if stream.cancelWriteCount != 1 {
		t.Fatalf("expected CancelWrite on signature error, got %d", stream.cancelWriteCount)
	}
}

type nopStreamHandler struct{}

func (nopStreamHandler) HandleDataStream(context.Context, io.ReadWriteCloser, *ConnectRequest, uint8) {
}
func (nopStreamHandler) HandleRPCStream(context.Context, io.ReadWriteCloser, uint8) {}
func (nopStreamHandler) HandleRPCStreamWithSender(context.Context, io.ReadWriteCloser, uint8, DatagramSender) {
}
func (nopStreamHandler) HandleDatagram(context.Context, []byte, DatagramSender) {}

func TestHandleStreamCancelsWriteOnConnectRequestError(t *testing.T) {
	t.Parallel()
	stream := &fakeQUICStream{
		reader: *strings.NewReader(string(dataStreamSignature[:])),
	}
	connection := &QUICConnection{logger: logger.NOP()}

	connection.handleStream(context.Background(), stream, nopStreamHandler{})
	if stream.cancelWriteCount != 1 {
		t.Fatalf("expected CancelWrite on connect request error, got %d", stream.cancelWriteCount)
	}
}
