package icmp

import (
	"context"
	"time"

	tun "github.com/sagernet/sing-tun"
)

type RouteHandler interface {
	RouteICMPConnection(
		ctx context.Context,
		session tun.DirectRouteSession,
		routeContext tun.DirectRouteContext,
		timeout time.Duration,
	) (tun.DirectRouteDestination, error)
}
