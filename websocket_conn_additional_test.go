package cloudflared

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"
)

func TestWebsocketConnReadSkipsTextFramesAndReturnsBinary(t *testing.T) {
	t.Parallel()

	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	conn := newWebsocketConn(serverSide, ws.StateServerSide)
	go func() {
		_ = wsutil.WriteClientText(clientSide, []byte("ignore"))
		_ = wsutil.WriteClientBinary(clientSide, []byte("payload"))
	}()

	buffer := make([]byte, 16)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "payload" {
		t.Fatalf("unexpected binary payload %q", buffer[:n])
	}
}

func TestWebsocketConnReadSupportsPartialBinaryFrames(t *testing.T) {
	t.Parallel()

	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	conn := newWebsocketConn(serverSide, ws.StateServerSide)
	go func() {
		_ = wsutil.WriteClientBinary(clientSide, []byte("abc"))
	}()

	first := make([]byte, 1)
	n, err := conn.Read(first)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || string(first[:n]) != "a" {
		t.Fatalf("unexpected first partial read %q", first[:n])
	}

	second := make([]byte, 8)
	n, err = conn.Read(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(second[:n]) != "bc" {
		t.Fatalf("unexpected second partial read %q", second[:n])
	}
}

func TestWebsocketConnReadReturnsEOFOnNormalClose(t *testing.T) {
	t.Parallel()

	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	conn := newWebsocketConn(serverSide, ws.StateServerSide)
	go func() {
		_, _ = io.Copy(io.Discard, clientSide)
	}()
	go func() {
		_ = wsutil.WriteClientMessage(clientSide, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, ""))
	}()

	buffer := make([]byte, 1)
	_, err := conn.Read(buffer)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected normal close to map to EOF, got %v", err)
	}
}

func TestWebsocketConnWriteEncodesBinaryFrame(t *testing.T) {
	t.Parallel()

	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	conn := newWebsocketConn(serverSide, ws.StateServerSide)
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("payload"))
		errCh <- err
	}()

	data, opCode, err := wsutil.ReadServerData(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if opCode != ws.OpBinary || string(data) != "payload" {
		t.Fatalf("unexpected server frame payload=%q opcode=%v", data, opCode)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestWrapWebsocketErrorAndRetryableCases(t *testing.T) {
	t.Parallel()

	if !isRetryableReadError(io.EOF) {
		t.Fatal("expected EOF to be retryable")
	}
	if !isRetryableReadError(wsutil.ErrNoFrameAdvance) {
		t.Fatal("expected no-frame-advance to be retryable")
	}
	if isRetryableReadError(io.ErrUnexpectedEOF) {
		t.Fatal("expected unexpected EOF not to be retryable")
	}

	if err := wrapWebsocketError(nil); err != nil {
		t.Fatalf("expected nil error to stay nil, got %v", err)
	}
	if err := wrapWebsocketError(wsutil.ClosedError{Code: ws.StatusNormalClosure}); !errors.Is(err, io.EOF) {
		t.Fatalf("expected normal closure to map to EOF, got %v", err)
	}
	if err := wrapWebsocketError(wsutil.ClosedError{Code: ws.StatusNoStatusRcvd}); !errors.Is(err, io.EOF) {
		t.Fatalf("expected no-status closure to map to EOF, got %v", err)
	}
	other := wrapWebsocketError(wsutil.ClosedError{Code: ws.StatusProtocolError})
	var closedErr wsutil.ClosedError
	if !errors.As(other, &closedErr) || closedErr.Code != ws.StatusProtocolError {
		t.Fatalf("expected protocol error to remain unchanged, got %v", other)
	}
}
