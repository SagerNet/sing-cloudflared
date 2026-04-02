package cloudflared

import (
	"context"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const originUDPWriteTimeout = 200 * time.Millisecond

type udpWriteDeadlinePacketConn struct {
	N.PacketConn
}

func (c *udpWriteDeadlinePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	_ = c.PacketConn.SetWriteDeadline(time.Now().Add(originUDPWriteTimeout))
	defer func() {
		_ = c.PacketConn.SetWriteDeadline(time.Time{})
	}()
	return c.PacketConn.WritePacket(buffer, destination)
}

func (s *Service) dialWarpPacketConnection(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	if s.handler == nil {
		return nil, E.New("handler not configured")
	}

	warpRouting := s.configManager.Snapshot().WarpRouting
	if warpRouting.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, warpRouting.ConnectTimeout)
		defer cancel()
	}

	packetConn, err := s.handler.DialPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return &udpWriteDeadlinePacketConn{PacketConn: packetConn}, nil
}
