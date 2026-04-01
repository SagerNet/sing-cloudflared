package cloudflared

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"time"

	"github.com/sagernet/sing-cloudflared/tunnelrpc"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/google/uuid"
	"zombiezen.com/go/capnproto2/pogs"
	"zombiezen.com/go/capnproto2/rpc"
)

const (
	rpcTimeout = 5 * time.Second
)

var clientVersion = "sing-cloudflared"

// RegistrationClient handles the Cap'n Proto RPC for tunnel registration.
type RegistrationClient struct {
	client    tunnelrpc.TunnelServer
	rpcConn   *rpc.Conn
	transport rpc.Transport
}

type registrationRPCClient interface {
	RegisterConnection(
		ctx context.Context,
		auth TunnelAuth,
		tunnelID uuid.UUID,
		connIndex uint8,
		options *RegistrationConnectionOptions,
	) (*RegistrationResult, error)
	Unregister(ctx context.Context) error
	Close() error
}

type permanentRegistrationError struct {
	Err error
}

func (e *permanentRegistrationError) Error() string {
	if e == nil || e.Err == nil {
		return "permanent registration error"
	}
	return e.Err.Error()
}

func (e *permanentRegistrationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func isPermanentRegistrationError(err error) bool {
	var permanentErr *permanentRegistrationError
	return errors.As(err, &permanentErr)
}

// NewRegistrationClient creates a Cap'n Proto RPC client over the given stream.
// The stream should be the first QUIC stream (control stream).
func NewRegistrationClient(ctx context.Context, stream io.ReadWriteCloser) *RegistrationClient {
	transport := safeTransport(stream)
	conn := newRPCClientConn(transport, ctx)
	return &RegistrationClient{
		client:    tunnelrpc.TunnelServer{Client: conn.Bootstrap(ctx)},
		rpcConn:   conn,
		transport: transport,
	}
}

// RegisterConnection registers this tunnel connection with the edge.
func (c *RegistrationClient) RegisterConnection(
	ctx context.Context,
	auth TunnelAuth,
	tunnelID uuid.UUID,
	connIndex uint8,
	options *RegistrationConnectionOptions,
) (*RegistrationResult, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	promise := c.client.RegisterConnection(ctx, func(p tunnelrpc.RegistrationServer_registerConnection_Params) error {
		// Marshal TunnelAuth
		tunnelAuth, err := p.NewAuth()
		if err != nil {
			return err
		}
		authPogs := &RegistrationTunnelAuth{
			AccountTag:   auth.AccountTag,
			TunnelSecret: auth.TunnelSecret,
		}
		err = pogs.Insert(tunnelrpc.TunnelAuth_TypeID, tunnelAuth.Struct, authPogs)
		if err != nil {
			return err
		}

		// Set tunnel ID
		err = p.SetTunnelId(tunnelID[:])
		if err != nil {
			return err
		}

		// Set connection index
		p.SetConnIndex(connIndex)

		// Marshal ConnectionOptions
		connOptions, err := p.NewOptions()
		if err != nil {
			return err
		}
		return pogs.Insert(tunnelrpc.ConnectionOptions_TypeID, connOptions.Struct, options)
	})

	response, err := promise.Result().Struct()
	if err != nil {
		return nil, E.Cause(err, "registration RPC")
	}

	result := response.Result()
	switch result.Which() {
	case tunnelrpc.ConnectionResponse_result_Which_error:
		resultError, err := result.Error()
		if err != nil {
			return nil, E.Cause(err, "read registration error")
		}
		cause, _ := resultError.Cause()
		registrationError := E.New(cause)
		if resultError.ShouldRetry() {
			return nil, &RetryableError{
				Err:   registrationError,
				Delay: time.Duration(resultError.RetryAfter()),
			}
		}
		return nil, &permanentRegistrationError{Err: registrationError}

	case tunnelrpc.ConnectionResponse_result_Which_connectionDetails:
		connDetails, err := result.ConnectionDetails()
		if err != nil {
			return nil, E.Cause(err, "read connection details")
		}
		uuidBytes, err := connDetails.Uuid()
		if err != nil {
			return nil, E.Cause(err, "read connection UUID")
		}
		connectionID, err := uuid.FromBytes(uuidBytes)
		if err != nil {
			return nil, E.Cause(err, "parse connection UUID")
		}
		location, _ := connDetails.LocationName()
		return &RegistrationResult{
			ConnectionID:            connectionID,
			Location:                location,
			TunnelIsRemotelyManaged: connDetails.TunnelIsRemotelyManaged(),
		}, nil

	default:
		return nil, E.New("unexpected registration response type")
	}
}

// Unregister sends the UnregisterConnection RPC.
func (c *RegistrationClient) Unregister(ctx context.Context) error {
	promise := c.client.UnregisterConnection(ctx, nil)
	_, err := promise.Struct()
	return err
}

// Close closes the RPC connection and transport.
func (c *RegistrationClient) Close() error {
	return E.Errors(
		c.rpcConn.Close(),
		c.transport.Close(),
	)
}

func validateRegistrationResult(result *RegistrationResult) error {
	if result == nil || result.TunnelIsRemotelyManaged {
		return nil
	}
	return ErrNonRemoteManagedTunnelUnsupported
}

// BuildConnectionOptions creates the ConnectionOptions to send during registration.
func BuildConnectionOptions(connectorID uuid.UUID, features []string, numPreviousAttempts uint8, originLocalIP net.IP) *RegistrationConnectionOptions {
	return &RegistrationConnectionOptions{
		Client: RegistrationClientInfo{
			ClientID: connectorID[:],
			Features: features,
			Version:  clientVersion,
			Arch:     runtime.GOOS + "_" + runtime.GOARCH,
		},
		ReplaceExisting:     false,
		CompressionQuality:  0,
		OriginLocalIP:       originLocalIP,
		NumPreviousAttempts: numPreviousAttempts,
	}
}

// DefaultFeatures returns the feature strings to advertise.
func DefaultFeatures(datagramVersion string) []string {
	features := []string{
		"serialized_headers",
		"support_datagram_v2",
		"support_quic_eof",
		"allow_remote_config",
	}
	if datagramVersion == "v3" {
		features = append(features, "support_datagram_v3_2")
	}
	return features
}
