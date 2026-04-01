package cloudflared

import (
	"testing"

	"github.com/sagernet/sing-cloudflared/internal/protocol"
	"github.com/sagernet/sing-cloudflared/internal/transport"
)

func TestProtocolSelectorConstants(t *testing.T) {
	t.Parallel()

	if transport.ProtocolQUIC != "quic" {
		t.Fatalf("unexpected quic protocol %q", transport.ProtocolQUIC)
	}
	if transport.ProtocolHTTP2 != "http2" {
		t.Fatalf("unexpected http2 protocol %q", transport.ProtocolHTTP2)
	}
	if protocol.DefaultDatagramVersion != "v2" {
		t.Fatalf("unexpected default datagram version %q", protocol.DefaultDatagramVersion)
	}
	if protocol.DatagramVersionV3 != "v3" {
		t.Fatalf("unexpected v3 datagram version %q", protocol.DatagramVersionV3)
	}
}
