package cloudflared

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Handler interface {
	DialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	DialPacket(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error)
}

type ICMPHandler interface {
	RouteICMPConnection(
		ctx context.Context,
		session ICMPRouteSession,
		routeContext ICMPRouteContext,
		timeout time.Duration,
	) (ICMPRouteDestination, error)
}

type ICMPRouteSession struct {
	Source      netip.Addr
	Destination netip.Addr
}

type ICMPRouteContext interface {
	WritePacket(packet *buf.Buffer, destination M.Socksaddr) error
}

type ICMPRouteDestination interface {
	WritePacket(packet *buf.Buffer) error
	Timeout() time.Duration
	Close() error
}
