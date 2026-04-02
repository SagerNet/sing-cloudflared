package icmp

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type RouteHandler interface {
	RouteICMPConnection(
		ctx context.Context,
		session RouteSession,
		routeContext RouteContext,
		timeout time.Duration,
	) (RouteDestination, error)
}

type RouteSession struct {
	Source      netip.Addr
	Destination netip.Addr
}

type RouteContext interface {
	WritePacket(packet *buf.Buffer, destination M.Socksaddr) error
}

type RouteDestination interface {
	WritePacket(packet *buf.Buffer) error
	Timeout() time.Duration
	Close() error
}
