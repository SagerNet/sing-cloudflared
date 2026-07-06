package icmp

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/ping"
	"github.com/sagernet/sing/common/logger"
)

type DirectHandler struct {
	port *ping.Port
}

func NewDirectHandler(logger logger.ContextLogger) *DirectHandler {
	return &DirectHandler{port: ping.NewPort(context.Background(), logger, nil, 0)}
}

func (h *DirectHandler) RouteICMPFlow(source netip.Addr, destination netip.Addr) (tun.Port, error) {
	return h.port, nil
}
