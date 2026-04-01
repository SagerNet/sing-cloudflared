package icmp

import (
	"context"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/ping"
	"github.com/sagernet/sing/common/logger"
)

type DirectHandler struct {
	logger logger.ContextLogger
}

func NewDirectHandler(logger logger.ContextLogger) *DirectHandler {
	return &DirectHandler{logger: logger}
}

func (h *DirectHandler) RouteICMPConnection(
	ctx context.Context,
	session tun.DirectRouteSession,
	routeContext tun.DirectRouteContext,
	timeout time.Duration,
) (tun.DirectRouteDestination, error) {
	return ping.ConnectDestination(ctx, h.logger, nil, session.Destination, routeContext, timeout)
}
