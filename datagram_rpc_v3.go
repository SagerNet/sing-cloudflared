package cloudflared

import (
	"context"
	"errors"
	"io"

	"github.com/sagernet/sing-cloudflared/tunnelrpc"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"zombiezen.com/go/capnproto2/server"
)

var (
	errUnsupportedDatagramV3UDPRegistration   = errors.New("datagram v3 does not support RegisterUdpSession RPC")
	errUnsupportedDatagramV3UDPUnregistration = errors.New("datagram v3 does not support UnregisterUdpSession RPC")
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
	server.Ack(call.Options)
	version := call.Params.Version()
	configData, _ := call.Params.Config()
	updateResult := s.service.ApplyConfig(version, configData)
	result, err := call.Results.NewResult()
	if err != nil {
		return err
	}
	result.SetLatestAppliedVersion(updateResult.LastAppliedVersion)
	if updateResult.Err != nil {
		result.SetErr(updateResult.Err.Error())
	} else {
		result.SetErr("")
	}
	return nil
}

// ServeV3RPCStream serves configuration updates on v3 and rejects legacy UDP RPCs.
func ServeV3RPCStream(ctx context.Context, stream io.ReadWriteCloser, service *Service, log logger.ContextLogger) {
	srv := &cloudflaredV3Server{
		service: service,
		logger:  log,
	}
	client := tunnelrpc.CloudflaredServer_ServerToClient(srv)
	transport := safeTransport(stream)
	rpcConn := newRPCServerConn(transport, client.Client)
	rpcCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	select {
	case <-rpcConn.Done():
	case <-rpcCtx.Done():
	}
	E.Errors(
		rpcConn.Close(),
		transport.Close(),
	)
}
