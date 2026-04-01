package cloudflared

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
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
