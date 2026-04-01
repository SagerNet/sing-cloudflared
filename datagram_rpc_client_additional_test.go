package cloudflared

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
)

type failingRPCStreamSender struct {
	captureDatagramSender
	err error
}

func (s *failingRPCStreamSender) OpenRPCStream(ctx context.Context) (io.ReadWriteCloser, error) {
	return nil, s.err
}

func TestNewV2SessionRPCClientRequiresRPCStreamSupport(t *testing.T) {
	t.Parallel()

	_, err := newV2SessionRPCClient(context.Background(), &captureDatagramSender{})
	if err == nil || err.Error() != "sender does not support rpc streams" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestUnregisterRemoteSessionPropagatesOpenRPCStreamError(t *testing.T) {
	t.Parallel()

	muxer := &DatagramV2Muxer{
		sender: &failingRPCStreamSender{err: errors.New("open rpc stream failed")},
	}
	err := muxer.unregisterRemoteSession(context.Background(), uuid.New(), "closed")
	if err == nil || err.Error() != "open rpc stream failed" {
		t.Fatalf("unexpected error %v", err)
	}
}
