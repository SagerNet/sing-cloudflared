package cloudflared

import (
	"context"
	"io"

	"github.com/sagernet/sing-cloudflared/tunnelrpc"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

var (
	errUnsupportedDatagramV3UDPRegistration   = E.New("datagram v3 does not support RegisterUdpSession RPC")
	errUnsupportedDatagramV3UDPUnregistration = E.New("datagram v3 does not support UnregisterUdpSession RPC")
)

type cloudflaredV3Server struct {
	service *Service
	logger  logger.ContextLogger
}

func (s *cloudflaredV3Server) RegisterUdpSession(call tunnelrpc.SessionManager_registerUdpSession) error {
	result, err := call.Results.NewResult()
	if err != nil {
		return err
	}
	err = result.SetErr(errUnsupportedDatagramV3UDPRegistration.Error())
	if err != nil {
		return err
	}
	return result.SetSpans([]byte{})
}

func (s *cloudflaredV3Server) UnregisterUdpSession(call tunnelrpc.SessionManager_unregisterUdpSession) error {
	return errUnsupportedDatagramV3UDPUnregistration
}

func (s *cloudflaredV3Server) UpdateConfiguration(call tunnelrpc.ConfigurationManager_updateConfiguration) error {
	return handleUpdateConfiguration(s.service, call)
}

func ServeV3RPCStream(ctx context.Context, stream io.ReadWriteCloser, service *Service, log logger.ContextLogger) {
	srv := &cloudflaredV3Server{
		service: service,
		logger:  log,
	}
	client := tunnelrpc.CloudflaredServer_ServerToClient(srv)
	serveRPCConn(ctx, stream, client.Client)
}
