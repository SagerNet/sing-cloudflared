package cloudflared

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-cloudflared/internal/datagram"
	"github.com/sagernet/sing-cloudflared/internal/protocol"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type recordingPacketConn struct {
	closed chan struct{}
	writes chan []byte
}

type blockingPacketConn struct {
	closed chan struct{}
}

type controlledReadPacketConn struct {
	closed     chan struct{}
	reads      chan []byte
	readErr    error
	closeCount atomic.Int32
}

func newRecordingPacketConn() *recordingPacketConn {
	return &recordingPacketConn{
		closed: make(chan struct{}),
		writes: make(chan []byte, 8),
	}
}

func newBlockingPacketConn() *blockingPacketConn {
	return &blockingPacketConn{closed: make(chan struct{})}
}

func newControlledReadPacketConn() *controlledReadPacketConn {
	return &controlledReadPacketConn{
		closed: make(chan struct{}),
		reads:  make(chan []byte, 4),
	}
}

func (c *recordingPacketConn) ReadPacket(_ *buf.Buffer) (M.Socksaddr, error) {
	<-c.closed
	return M.Socksaddr{}, io.EOF
}

func (c *recordingPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	data := append([]byte(nil), buffer.Bytes()...)
	buffer.Release()
	c.writes <- data
	return nil
}

func (c *recordingPacketConn) Close() error {
	closeOnce(c.closed)
	return nil
}

func (c *recordingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *blockingPacketConn) ReadPacket(_ *buf.Buffer) (M.Socksaddr, error) {
	<-c.closed
	return M.Socksaddr{}, io.EOF
}

func (c *blockingPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *blockingPacketConn) Close() error {
	closeOnce(c.closed)
	return nil
}

func (c *blockingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *blockingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *controlledReadPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if c.readErr != nil {
		return M.Socksaddr{}, c.readErr
	}

	select {
	case payload := <-c.reads:
		_, err := buffer.Write(payload)
		return M.Socksaddr{}, err
	case <-c.closed:
		return M.Socksaddr{}, io.EOF
	}
}

func (c *controlledReadPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *controlledReadPacketConn) Close() error {
	c.closeCount.Add(1)
	closeOnce(c.closed)
	return nil
}

func (c *controlledReadPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *controlledReadPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *controlledReadPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *controlledReadPacketConn) SetWriteDeadline(time.Time) error { return nil }

type packetDialingHandler struct {
	testHandler
	packetConn N.PacketConn
}

func (h *packetDialingHandler) DialPacket(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	return h.packetConn, nil
}

func waitForV3SessionRemoval(t *testing.T, manager *datagram.DatagramV3SessionManager, requestID protocol.RequestID) {
	t.Helper()

	deadline := time.After(2 * time.Second)
	for {
		if _, exists := manager.Get(requestID); !exists {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("expected V3 session %x to be removed", requestID)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestDatagramV2RegisterSession(t *testing.T) {
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.handler = &packetDialingHandler{packetConn: newBlockingPacketConn()}
	muxer := datagram.NewDatagramV2Muxer(serviceInstance.muxerContext(), &captureDatagramSender{}, serviceInstance.logger)
	sessionID := uuidTest(7)
	err := muxer.RegisterSession(context.Background(), sessionID, net.IPv4(127, 0, 0, 1), 53, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	muxer.Close()
}

func TestDatagramV3SessionContextCancellationRemovesSession(t *testing.T) {
	t.Parallel()

	packetConn := newBlockingPacketConn()
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.handler = &packetDialingHandler{packetConn: packetConn}

	requestID := protocol.RequestID{}
	requestID[15] = 14
	ctx, cancel := context.WithCancel(context.Background())
	_, _, err := serviceInstance.datagramV3Manager.Register(
		serviceInstance.muxerContext(),
		ctx,
		requestID,
		netip.MustParseAddrPort("127.0.0.1:53"),
		time.Second,
		&captureDatagramSender{},
	)
	if err != nil {
		t.Fatal(err)
	}

	cancel()
	waitForV3SessionRemoval(t, serviceInstance.datagramV3Manager, requestID)
}
