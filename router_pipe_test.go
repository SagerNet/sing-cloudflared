package cloudflared

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestHandleTCPStreamUsesDialTCP(t *testing.T) {
	t.Parallel()
	listener := startEchoListener(t)
	defer listener.Close()

	serviceInstance := newSpecialServiceWithHandler(t, &testHandler{})

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	respWriter := &fakeConnectResponseWriter{done: make(chan struct{})}
	responseDone := respWriter.done
	finished := make(chan struct{})
	go func() {
		serviceInstance.handleTCPStream(context.Background(), serverSide, respWriter, M.ParseSocksaddr(listener.Addr().String()))
		close(finished)
	}()

	select {
	case <-responseDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connect response")
	}
	if respWriter.err != nil {
		t.Fatal("unexpected response error: ", respWriter.err)
	}

	if err := clientSide.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("ping")
	if _, err := clientSide.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(clientSide, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string(payload) {
		t.Fatalf("unexpected echo payload: %q", string(response))
	}

	_ = clientSide.Close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TCP stream handler to exit")
	}
}

