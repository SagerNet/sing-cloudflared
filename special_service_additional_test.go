package cloudflared

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"
)

func TestStreamServiceHostnameAdditionalCases(t *testing.T) {
	t.Parallel()

	if got := streamServiceHostname(ResolvedService{
		BaseURL: &url.URL{Scheme: "tcp", Host: "base.example.com:1234"},
	}); got != "base.example.com" {
		t.Fatalf("unexpected hostname %q", got)
	}
	if got := streamServiceHostname(ResolvedService{
		Service: "tcp://service.example.com:1234",
	}); got != "service.example.com" {
		t.Fatalf("unexpected hostname from service %q", got)
	}
}

func TestResolveBastionDestinationAdditionalCases(t *testing.T) {
	t.Parallel()

	t.Run("missing header", func(t *testing.T) {
		_, err := resolveBastionDestination(&ConnectRequest{})
		if err == nil || err.Error() != "missing Cf-Access-Jump-Destination header" {
			t.Fatalf("unexpected error %v", err)
		}
	})

	t.Run("url with path", func(t *testing.T) {
		destination, err := resolveBastionDestination(&ConnectRequest{
			Metadata: []Metadata{{
				Key: metadataHTTPHeader + ":Cf-Access-Jump-Destination",
				Val: "ssh://jump.example.com:2222/path/to/target",
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if destination != "jump.example.com:2222" {
			t.Fatalf("unexpected bastion destination %q", destination)
		}
	})

	t.Run("raw host with path suffix", func(t *testing.T) {
		destination, err := resolveBastionDestination(&ConnectRequest{
			Metadata: []Metadata{{
				Key: metadataHTTPHeader + ":Cf-Access-Jump-Destination",
				Val: "jump.example.com:2022/ignored",
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if destination != "jump.example.com:2022" {
			t.Fatalf("unexpected bastion destination %q", destination)
		}
	})
}

func TestReadSocksDestinationDomainAndIPv6(t *testing.T) {
	t.Parallel()

	t.Run("domain", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		go func() {
			_, _ = client.Write([]byte{11})
			_, _ = client.Write([]byte("example.com"))
			_, _ = client.Write([]byte{0x01, 0xbb})
		}()

		destination, err := readSocksDestination(server, 3)
		if err != nil {
			t.Fatal(err)
		}
		if destination.String() != "example.com:443" {
			t.Fatalf("unexpected domain destination %s", destination)
		}
	})

	t.Run("ipv6", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		go func() {
			_, _ = client.Write([]byte(net.ParseIP("2001:db8::1").To16()))
			_, _ = client.Write([]byte{0x00, 0x35})
		}()

		destination, err := readSocksDestination(server, 4)
		if err != nil {
			t.Fatal(err)
		}
		if destination.String() != "[2001:db8::1]:53" {
			t.Fatalf("unexpected IPv6 destination %s", destination)
		}
	})
}

func TestReadSocksHandshakeErrorCases(t *testing.T) {
	t.Parallel()

	t.Run("unsupported version", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		go func() {
			_, _ = client.Write([]byte{0x04})
		}()

		_, err := readSocksHandshake(server)
		if err == nil || err.Error() != "unsupported SOCKS version: 4" {
			t.Fatalf("unexpected error %v", err)
		}
	})

	t.Run("missing no-auth method", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		replyCh := make(chan []byte, 1)
		go func() {
			_, _ = client.Write([]byte{0x05, 0x01, 0x02})
			reply := make([]byte, 2)
			_, _ = io.ReadFull(client, reply)
			replyCh <- reply
		}()

		_, err := readSocksHandshake(server)
		if err == nil || err.Error() != "unknown authentication type" {
			t.Fatalf("unexpected error %v", err)
		}
		reply := <-replyCh
		if string(reply) != string([]byte{0x05, 0xff}) {
			t.Fatalf("unexpected auth rejection %x", reply)
		}
	})

	t.Run("unsupported request version", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		authReplyCh := make(chan []byte, 1)
		go func() {
			_, _ = client.Write([]byte{0x05, 0x01, 0x00})
			reply := make([]byte, 2)
			_, _ = io.ReadFull(client, reply)
			authReplyCh <- reply
			_, _ = client.Write([]byte{0x04, 0x01, 0x00, 0x01})
		}()

		_, err := readSocksHandshake(server)
		if err == nil || err.Error() != "unsupported SOCKS request version: 4" {
			t.Fatalf("unexpected error %v", err)
		}
		reply := <-authReplyCh
		if string(reply) != string([]byte{0x05, 0x00}) {
			t.Fatalf("unexpected auth acceptance %x", reply)
		}
	})

	t.Run("unsupported command", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		replyCh := make(chan []byte, 1)
		go func() {
			_, _ = client.Write([]byte{0x05, 0x01, 0x00})
			authReply := make([]byte, 2)
			_, _ = io.ReadFull(client, authReply)
			_, _ = client.Write([]byte{0x05, 0x02, 0x00, 0x01})
			commandReply := make([]byte, 10)
			_, _ = io.ReadFull(client, commandReply)
			replyCh <- append(authReply, commandReply...)
		}()

		_, err := readSocksHandshake(server)
		if err == nil || err.Error() != "unsupported SOCKS command: 2" {
			t.Fatalf("unexpected error %v", err)
		}
		reply := <-replyCh
		if string(reply[:2]) != string([]byte{0x05, 0x00}) {
			t.Fatalf("unexpected auth acceptance %x", reply[:2])
		}
		if reply[3] != socksReplyCommandNotSupported {
			t.Fatalf("unexpected command rejection %x", reply[2:])
		}
	})

	t.Run("unsupported address type", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		go func() {
			_, _ = client.Write([]byte{0x05, 0x01, 0x00})
			reply := make([]byte, 2)
			_, _ = io.ReadFull(client, reply)
			_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x09})
		}()

		_, err := readSocksHandshake(server)
		if err == nil || err.Error() != "unsupported SOCKS address type: 9" {
			t.Fatalf("unexpected error %v", err)
		}
	})
}

func TestServeFixedSocksStreamBridgesTraffic(t *testing.T) {
	t.Parallel()

	serverSide, clientSide := net.Pipe()
	targetSide, originSide := net.Pipe()
	defer clientSide.Close()
	defer originSide.Close()

	done := make(chan error, 1)
	go func() {
		done <- serveFixedSocksStream(context.Background(), serverSide, targetSide)
	}()

	// Initial SOCKS5 greeting.
	_, _ = clientSide.Write([]byte{0x05, 0x01, 0x00})

	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(clientSide, methodReply); err != nil {
		t.Fatal(err)
	}
	if string(methodReply) != string([]byte{0x05, 0x00}) {
		t.Fatalf("unexpected auth reply %x", methodReply)
	}

	// CONNECT request for 127.0.0.1:53.
	_, _ = clientSide.Write([]byte{
		0x05, 0x01, 0x00, 0x01,
		127, 0, 0, 1,
		0x00, 0x35,
	})

	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(clientSide, connectReply); err != nil {
		t.Fatal(err)
	}
	if connectReply[1] != socksReplySuccess {
		t.Fatalf("unexpected connect reply %x", connectReply)
	}

	go func() {
		_, _ = originSide.Write([]byte("origin-data"))
	}()

	if _, err := clientSide.Write([]byte("client-data")); err != nil {
		t.Fatal(err)
	}

	fromClient := make([]byte, len("client-data"))
	if _, err := io.ReadFull(originSide, fromClient); err != nil {
		t.Fatal(err)
	}
	if string(fromClient) != "client-data" {
		t.Fatalf("unexpected payload to target %q", fromClient)
	}

	fromOrigin := make([]byte, len("origin-data"))
	if _, err := io.ReadFull(clientSide, fromOrigin); err != nil {
		t.Fatal(err)
	}
	if string(fromOrigin) != "origin-data" {
		t.Fatalf("unexpected payload to client %q", fromOrigin)
	}

	serverSide.Close()
	targetSide.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.EOF) && !E.IsClosedOrCanceled(err) {
			t.Fatalf("unexpected serveFixedSocksStream error %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected serveFixedSocksStream to exit")
	}
}

type dialErrorDialer struct {
	N.Dialer
	err error
}

func (d *dialErrorDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, d.err
}

type closingPipeDialer struct {
	N.Dialer
	delay time.Duration
}

func (d *closingPipeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		time.Sleep(d.delay)
		_ = server.Close()
	}()
	return client, nil
}

func TestServeSocksProxyWritesDialErrorReply(t *testing.T) {
	t.Parallel()

	policy, err := newIPRulePolicy([]IPRule{{
		Prefix: "127.0.0.0/8",
		Ports:  []int{53},
		Allow:  true,
	}})
	if err != nil {
		t.Fatal(err)
	}

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	serviceInstance := newSpecialServiceWithHandler(t, &dialErrorDialer{err: errors.New("connection refused by test")})
	errCh := make(chan error, 1)
	go func() {
		errCh <- serviceInstance.serveSocksProxy(context.Background(), server, policy)
	}()

	_, _ = client.Write([]byte{0x05, 0x01, 0x00})
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(client, authReply); err != nil {
		t.Fatal(err)
	}
	if string(authReply) != string([]byte{0x05, 0x00}) {
		t.Fatalf("unexpected auth reply %x", authReply)
	}

	_, _ = client.Write([]byte{
		0x05, 0x01, 0x00, 0x01,
		127, 0, 0, 1,
		0x00, 0x35,
	})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != socksReplyConnectionRefused {
		t.Fatalf("unexpected dial failure reply %x", reply)
	}

	select {
	case err := <-errCh:
		if err == nil || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("unexpected serveSocksProxy error %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expected serveSocksProxy to exit")
	}
}

func TestHandleStreamServiceReturnsWhenContextCanceledDuringClientSpam(t *testing.T) {
	t.Parallel()

	listener := startEchoListener(t)
	defer listener.Close()

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	serviceInstance := newSpecialService(t)
	respWriter := &fakeConnectResponseWriter{done: make(chan struct{})}
	request := &ConnectRequest{
		Type: ConnectionTypeWebsocket,
		Metadata: []Metadata{
			{Key: metadataHTTPHeader + ":Sec-WebSocket-Key", Val: "dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		serviceInstance.handleStreamService(ctx, serverSide, respWriter, request, ResolvedService{
			Kind:          ResolvedServiceStream,
			Destination:   M.ParseSocksaddr(listener.Addr().String()),
			StreamHasPort: true,
		})
	}()

	select {
	case <-respWriter.done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for stream service websocket upgrade")
	}
	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusSwitchingProtocols {
		t.Fatalf("unexpected websocket response status %d", respWriter.status)
	}
	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	data, opCode, err := wsutil.ReadServerData(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if opCode != ws.OpBinary || string(data) != "hello" {
		t.Fatalf("unexpected initial websocket echo op=%v data=%q", opCode, data)
	}

	spamDone := make(chan struct{})
	go func() {
		defer close(spamDone)
		for {
			if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte("spam")); err != nil {
				return
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	_ = clientSide.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected stream service to return after cancellation")
	}
	select {
	case <-spamDone:
	case <-time.After(time.Second):
		t.Fatal("expected client writer to observe closed websocket stream")
	}
}
