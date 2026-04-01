package cloudflared

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type captureDeadlinePacketConn struct {
	err       error
	deadlines []time.Time
}

func (c *captureDeadlinePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	buffer.Release()
	return M.Socksaddr{}, errors.New("unused")
}

func (c *captureDeadlinePacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return c.err
}

func (c *captureDeadlinePacketConn) Close() error                    { return nil }
func (c *captureDeadlinePacketConn) LocalAddr() net.Addr             { return &net.UDPAddr{} }
func (c *captureDeadlinePacketConn) SetDeadline(time.Time) error     { return nil }
func (c *captureDeadlinePacketConn) SetReadDeadline(time.Time) error { return nil }
func (c *captureDeadlinePacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, t)
	return nil
}

func TestDeadlinePacketConnWrapsWriteDeadline(t *testing.T) {
	t.Parallel()
	packetConn := &captureDeadlinePacketConn{}
	wrapped := &udpWriteDeadlinePacketConn{PacketConn: packetConn}

	if err := wrapped.WritePacket(buf.As([]byte("payload")), M.Socksaddr{}); err != nil {
		t.Fatal(err)
	}

	if len(packetConn.deadlines) != 2 {
		t.Fatalf("expected two deadline updates, got %d", len(packetConn.deadlines))
	}
	if packetConn.deadlines[0].IsZero() {
		t.Fatal("expected first deadline to set a timeout")
	}
	if !packetConn.deadlines[1].IsZero() {
		t.Fatal("expected second deadline to clear the timeout")
	}
}
