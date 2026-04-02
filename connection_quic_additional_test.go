package cloudflared

import (
	"context"
	"testing"

	"github.com/sagernet/sing-cloudflared/internal/protocol"
)

func TestDatagramVersionForSenderDefaultsToV2(t *testing.T) {
	t.Parallel()

	sender := &captureDatagramSender{}
	version := datagramVersionForSender(sender)
	if version != protocol.DefaultDatagramVersion {
		t.Fatalf("expected default datagram version %q, got %q", protocol.DefaultDatagramVersion, version)
	}
}

func TestDatagramVersionForSenderReportsV3(t *testing.T) {
	t.Parallel()

	sender := &captureDatagramSenderV3{}
	version := datagramVersionForSender(sender)
	if version != protocol.DatagramVersionV3 {
		t.Fatalf("expected datagram version %q, got %q", protocol.DatagramVersionV3, version)
	}
}

type captureDatagramSenderV3 struct {
	captureDatagramSender
}

func (c *captureDatagramSenderV3) DatagramVersion() string {
	return protocol.DatagramVersionV3
}

type captureDatagramSenderEmpty struct {
	captureDatagramSender
}

func (c *captureDatagramSenderEmpty) DatagramVersion() string {
	return ""
}

func TestDatagramVersionForSenderEmptyDefaultsToV2(t *testing.T) {
	t.Parallel()

	sender := &captureDatagramSenderEmpty{}
	version := datagramVersionForSender(sender)
	if version != protocol.DefaultDatagramVersion {
		t.Fatalf("expected default datagram version %q, got %q", protocol.DefaultDatagramVersion, version)
	}
}

func TestStreamHandlerAdapterDelegates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	serviceInstance := newTestService(t, testToken(t), "quic", 1)
	adapter := &streamHandlerAdapter{service: serviceInstance}
	adapter.HandleRPCStream(ctx, nil, 0)
}
