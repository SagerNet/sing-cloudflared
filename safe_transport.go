package cloudflared

import (
	"context"
	"io"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/rpc"
)

const (
	safeTransportMaxRetries    = 3
	safeTransportRetryInterval = 500 * time.Millisecond
)

type safeReadWriteCloser struct {
	io.ReadWriteCloser
	retries int
}

func (s *safeReadWriteCloser) Read(p []byte) (int, error) {
	n, err := s.ReadWriteCloser.Read(p)
	if n == 0 && err != nil && isTemporaryError(err) {
		if s.retries >= safeTransportMaxRetries {
			return 0, E.Cause(err, "read capnproto transport after multiple temporary errors")
		}
		s.retries++
		time.Sleep(safeTransportRetryInterval)
		return n, err
	}
	if err == nil {
		s.retries = 0
	}
	return n, err
}

func isTemporaryError(err error) bool {
	type temporary interface{ Temporary() bool }
	t, ok := err.(temporary)
	return ok && t.Temporary()
}

func safeTransport(stream io.ReadWriteCloser) rpc.Transport {
	return rpc.StreamTransport(&safeReadWriteCloser{ReadWriteCloser: stream})
}

type noopCapnpLogger struct{}

func (noopCapnpLogger) Infof(ctx context.Context, format string, args ...interface{})  {}
func (noopCapnpLogger) Errorf(ctx context.Context, format string, args ...interface{}) {}

func newRPCClientConn(transport rpc.Transport, ctx context.Context) *rpc.Conn {
	return rpc.NewConn(transport, rpc.ConnLog(noopCapnpLogger{}))
}

func newRPCServerConn(transport rpc.Transport, client capnp.Client) *rpc.Conn {
	return rpc.NewConn(transport, rpc.MainInterface(client), rpc.ConnLog(noopCapnpLogger{}))
}
