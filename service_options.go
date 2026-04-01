package cloudflared

import (
	"context"
	"time"

	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type ServiceOptions struct {
	Logger          logger.ContextLogger
	Handler         Handler
	ICMPHandler     ICMPHandler
	NewContext      func(context.Context) context.Context
	Token           string
	HAConnections   int
	Protocol        string
	PostQuantum     bool
	ControlDialer   N.Dialer
	TunnelDialer    N.Dialer
	EdgeIPVersion   int
	DatagramVersion string
	GracePeriod     time.Duration
	Region          string
	ClientVersion   string
}
