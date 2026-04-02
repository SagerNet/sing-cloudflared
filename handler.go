package cloudflared

import (
	"context"
	"net"

	"github.com/sagernet/sing-cloudflared/internal/icmp"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Handler interface {
	DialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	DialPacket(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error)
}

type ICMPHandler = icmp.RouteHandler
type ICMPRouteSession = icmp.RouteSession
type ICMPRouteContext = icmp.RouteContext
type ICMPRouteDestination = icmp.RouteDestination
