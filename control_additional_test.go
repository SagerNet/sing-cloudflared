package cloudflared

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-cloudflared/internal/config"
	"github.com/sagernet/sing-cloudflared/internal/control"
	"github.com/sagernet/sing-cloudflared/internal/protocol"
	"github.com/sagernet/sing-cloudflared/internal/tunnelrpc"
	"github.com/sagernet/sing/common/logger"

	"github.com/google/uuid"
	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"
)

type registrationCall struct {
	auth      protocol.RegistrationTunnelAuth
	tunnelID  uuid.UUID
	connIndex uint8
	options   protocol.RegistrationConnectionOptions
}

type registrationTestServer struct {
	registerCalls chan registrationCall
	unregisterCh  chan struct{}

	result      *protocol.RegistrationResult
	retryAfter  time.Duration
	registerErr error
}

func (s *registrationTestServer) RegisterConnection(call tunnelrpc.RegistrationServer_registerConnection) error {
	authStruct, err := call.Params.Auth()
	if err != nil {
		return err
	}
	var auth protocol.RegistrationTunnelAuth
	err = pogs.Extract(&auth, tunnelrpc.TunnelAuth_TypeID, authStruct.Struct)
	if err != nil {
		return err
	}

	tunnelIDBytes, err := call.Params.TunnelId()
	if err != nil {
		return err
	}
	tunnelID, err := uuid.FromBytes(tunnelIDBytes)
	if err != nil {
		return err
	}

	optionsStruct, err := call.Params.Options()
	if err != nil {
		return err
	}
	var options protocol.RegistrationConnectionOptions
	err = pogs.Extract(&options, tunnelrpc.ConnectionOptions_TypeID, optionsStruct.Struct)
	if err != nil {
		return err
	}

	s.registerCalls <- registrationCall{
		auth:      auth,
		tunnelID:  tunnelID,
		connIndex: call.Params.ConnIndex(),
		options:   options,
	}

	response, err := call.Results.NewResult()
	if err != nil {
		return err
	}
	if s.registerErr != nil {
		resultErr, err := response.Result().NewError()
		if err != nil {
			return err
		}
		err = resultErr.SetCause(s.registerErr.Error())
		if err != nil {
			return err
		}
		resultErr.SetShouldRetry(s.retryAfter > 0)
		resultErr.SetRetryAfter(int64(s.retryAfter))
		return nil
	}

	connectionDetails, err := response.Result().NewConnectionDetails()
	if err != nil {
		return err
	}
	if s.result != nil {
		err = connectionDetails.SetUuid(s.result.ConnectionID[:])
		if err != nil {
			return err
		}
		err = connectionDetails.SetLocationName(s.result.Location)
		if err != nil {
			return err
		}
		connectionDetails.SetTunnelIsRemotelyManaged(s.result.TunnelIsRemotelyManaged)
	}
	return nil
}

func (s *registrationTestServer) UnregisterConnection(call tunnelrpc.RegistrationServer_unregisterConnection) error {
	s.unregisterCh <- struct{}{}
	return nil
}

func (s *registrationTestServer) UpdateLocalConfiguration(call tunnelrpc.RegistrationServer_updateLocalConfiguration) error {
	return nil
}

func newRegistrationRPCClient(t *testing.T, server tunnelrpc.RegistrationServer_Server) (control.RegistrationRPCClient, func()) {
	t.Helper()

	serverSide, clientSide := net.Pipe()
	serverTransport := control.SafeTransport(serverSide)
	serverConn := control.NewRPCServerConn(serverTransport, tunnelrpc.RegistrationServer_ServerToClient(server).Client)
	client := control.CreateRegistrationClient(context.Background(), clientSide)

	cleanup := func() {
		_ = client.Close()
		_ = serverConn.Close()
		_ = serverTransport.Close()
		_ = serverSide.Close()
	}
	return client, cleanup
}

func TestRegistrationClientRegisterConnectionSuccess(t *testing.T) {
	t.Parallel()

	expectedResult := &protocol.RegistrationResult{
		ConnectionID:            uuid.New(),
		Location:                "HKG",
		TunnelIsRemotelyManaged: true,
	}
	server := &registrationTestServer{
		registerCalls: make(chan registrationCall, 1),
		unregisterCh:  make(chan struct{}, 1),
		result:        expectedResult,
	}
	client, cleanup := newRegistrationRPCClient(t, server)
	defer cleanup()

	connectorID := uuid.New()
	tunnelID := uuid.New()
	options := control.BuildConnectionOptions(connectorID, []string{"serialized_headers", "support_datagram_v3_2"}, 2, net.IPv4(127, 0, 0, 1))
	result, err := client.RegisterConnection(context.Background(), protocol.TunnelAuth{
		AccountTag:   "account",
		TunnelSecret: []byte("secret"),
	}, tunnelID, 3, options)
	if err != nil {
		t.Fatal(err)
	}
	if *result != *expectedResult {
		t.Fatalf("unexpected registration result: %#v", result)
	}

	call := <-server.registerCalls
	if call.auth.AccountTag != "account" {
		t.Fatalf("unexpected account tag %q", call.auth.AccountTag)
	}
	if string(call.auth.TunnelSecret) != "secret" {
		t.Fatalf("unexpected secret %q", string(call.auth.TunnelSecret))
	}
	if call.tunnelID != tunnelID {
		t.Fatalf("unexpected tunnel id %s", call.tunnelID)
	}
	if call.connIndex != 3 {
		t.Fatalf("unexpected conn index %d", call.connIndex)
	}
	if !call.options.OriginLocalIP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("unexpected origin local ip %v", call.options.OriginLocalIP)
	}
	if got := call.options.Client.Version; got != control.ClientVersion {
		t.Fatalf("unexpected client version %q", got)
	}
	if got := call.options.Client.Arch; got != runtime.GOOS+"_"+runtime.GOARCH {
		t.Fatalf("unexpected client arch %q", got)
	}
	if uuid.UUID(call.options.Client.ClientID) != connectorID {
		t.Fatalf("unexpected connector id %x", call.options.Client.ClientID)
	}
	if len(call.options.Client.Features) != 2 {
		t.Fatalf("unexpected features %#v", call.options.Client.Features)
	}
}

func TestRegistrationClientRegisterConnectionRetryableError(t *testing.T) {
	t.Parallel()

	server := &registrationTestServer{
		registerCalls: make(chan registrationCall, 1),
		unregisterCh:  make(chan struct{}, 1),
		registerErr:   errors.New("retry later"),
		retryAfter:    3 * time.Second,
	}
	client, cleanup := newRegistrationRPCClient(t, server)
	defer cleanup()

	_, err := client.RegisterConnection(context.Background(), protocol.TunnelAuth{}, uuid.New(), 0, control.BuildConnectionOptions(uuid.New(), nil, 0, nil))
	retryErr, ok := err.(*protocol.RetryableError)
	if !ok {
		t.Fatalf("expected retryable error, got %T %v", err, err)
	}
	if retryErr.Error() != "retry later" {
		t.Fatalf("unexpected retry error %q", retryErr.Error())
	}
	if retryErr.Delay != 3*time.Second {
		t.Fatalf("unexpected retry delay %v", retryErr.Delay)
	}
	if !errors.Is(retryErr, retryErr.Err) {
		t.Fatal("expected retryable error to unwrap")
	}
}

func TestRegistrationClientRegisterConnectionPermanentError(t *testing.T) {
	t.Parallel()

	server := &registrationTestServer{
		registerCalls: make(chan registrationCall, 1),
		unregisterCh:  make(chan struct{}, 1),
		registerErr:   errors.New("no retry"),
	}
	client, cleanup := newRegistrationRPCClient(t, server)
	defer cleanup()

	_, err := client.RegisterConnection(context.Background(), protocol.TunnelAuth{}, uuid.New(), 0, control.BuildConnectionOptions(uuid.New(), nil, 0, nil))
	permanentErr, ok := err.(*control.PermanentRegistrationError)
	if !ok {
		t.Fatalf("expected permanent registration error, got %T %v", err, err)
	}
	if permanentErr.Error() != "no retry" {
		t.Fatalf("unexpected permanent error %q", permanentErr.Error())
	}
	if !errors.Is(permanentErr, permanentErr.Err) {
		t.Fatal("expected permanent registration error to unwrap")
	}
}

func TestRegistrationClientUnregister(t *testing.T) {
	t.Parallel()

	server := &registrationTestServer{
		registerCalls: make(chan registrationCall, 1),
		unregisterCh:  make(chan struct{}, 1),
		result:        &protocol.RegistrationResult{ConnectionID: uuid.New(), TunnelIsRemotelyManaged: true},
	}
	client, cleanup := newRegistrationRPCClient(t, server)
	defer cleanup()

	err := client.Unregister(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-server.unregisterCh:
	case <-time.After(time.Second):
		t.Fatal("expected unregister RPC")
	}
}

func TestBuildConnectionOptionsAndCredentialsAuth(t *testing.T) {
	t.Parallel()

	connectorID := uuid.New()
	options := control.BuildConnectionOptions(connectorID, []string{"a", "b"}, 7, net.IPv4(10, 0, 0, 1))
	if got := uuid.UUID(options.Client.ClientID); got != connectorID {
		t.Fatalf("unexpected client id %s", got)
	}
	if options.NumPreviousAttempts != 7 {
		t.Fatalf("unexpected previous attempts %d", options.NumPreviousAttempts)
	}
	if !options.OriginLocalIP.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("unexpected origin local ip %v", options.OriginLocalIP)
	}

	credentials := protocol.Credentials{
		AccountTag:   "account",
		TunnelSecret: []byte("secret"),
	}
	auth := credentials.Auth()
	if auth.AccountTag != credentials.AccountTag || string(auth.TunnelSecret) != "secret" {
		t.Fatalf("unexpected auth %#v", auth)
	}
}

func TestBuildConnectionOptionsRoundTripsThroughCapnp(t *testing.T) {
	t.Parallel()

	connectorID := uuid.New()
	original := control.BuildConnectionOptions(connectorID, []string{"serialized_headers", "support_datagram_v3_2"}, 3, net.IPv4(10, 20, 30, 40))

	_, seg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	capnpOptions, err := tunnelrpc.NewConnectionOptions(seg)
	if err != nil {
		t.Fatal(err)
	}
	err = pogs.Insert(tunnelrpc.ConnectionOptions_TypeID, capnpOptions.Struct, original)
	if err != nil {
		t.Fatal(err)
	}

	var decoded protocol.RegistrationConnectionOptions
	err = pogs.Extract(&decoded, tunnelrpc.ConnectionOptions_TypeID, capnpOptions.Struct)
	if err != nil {
		t.Fatal(err)
	}

	if got := uuid.UUID(decoded.Client.ClientID); got != connectorID {
		t.Fatalf("unexpected client id %s", got)
	}
	if len(decoded.Client.Features) != 2 || decoded.Client.Features[0] != "serialized_headers" || decoded.Client.Features[1] != "support_datagram_v3_2" {
		t.Fatalf("unexpected feature list %#v", decoded.Client.Features)
	}
	if decoded.Client.Version != control.ClientVersion {
		t.Fatalf("unexpected client version %q", decoded.Client.Version)
	}
	if decoded.Client.Arch != runtime.GOOS+"_"+runtime.GOARCH {
		t.Fatalf("unexpected client arch %q", decoded.Client.Arch)
	}
	if !decoded.OriginLocalIP.Equal(net.IPv4(10, 20, 30, 40)) {
		t.Fatalf("unexpected origin local IP %v", decoded.OriginLocalIP)
	}
	if decoded.NumPreviousAttempts != 3 {
		t.Fatalf("unexpected previous attempts %d", decoded.NumPreviousAttempts)
	}
	if decoded.ReplaceExisting {
		t.Fatal("expected replace_existing to remain false")
	}
	if decoded.CompressionQuality != 0 {
		t.Fatalf("unexpected compression quality %d", decoded.CompressionQuality)
	}
}

func TestPermanentRegistrationErrorWithNilInner(t *testing.T) {
	t.Parallel()

	var err *control.PermanentRegistrationError
	if err.Error() != "permanent registration error" {
		t.Fatalf("unexpected nil error string %q", err.Error())
	}
	if err.Unwrap() != nil {
		t.Fatal("expected nil unwrap")
	}
}

func TestRetryableErrorUnwrap(t *testing.T) {
	t.Parallel()

	root := errors.New("root")
	err := &protocol.RetryableError{Err: root}
	if !errors.Is(err, root) {
		t.Fatal("expected retryable error to unwrap root error")
	}
}

func TestConnectionTypeStringUnknown(t *testing.T) {
	t.Parallel()

	if got := protocol.ConnectionType(99).String(); got != "unknown" {
		t.Fatalf("unexpected string %q", got)
	}
}

func TestHandleUpdateConfigurationSetsVersionAndError(t *testing.T) {
	t.Parallel()

	_, paramsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	params, err := tunnelrpc.NewConfigurationManager_updateConfiguration_Params(paramsSeg)
	if err != nil {
		t.Fatal(err)
	}
	params.SetVersion(2)
	err = params.SetConfig([]byte(`not-json`))
	if err != nil {
		t.Fatal(err)
	}

	_, resultsSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	results, err := tunnelrpc.NewConfigurationManager_updateConfiguration_Results(resultsSeg)
	if err != nil {
		t.Fatal(err)
	}

	configManager, err := config.NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	serviceInstance := &Service{
		configManager:    configManager,
		logger:           logger.NOP(),
		directTransports: make(map[string]*http.Transport),
	}
	callCfg := tunnelrpc.ConfigurationManager_updateConfiguration{
		Ctx:     context.Background(),
		Params:  params,
		Results: results,
	}
	err = control.HandleUpdateConfiguration(serviceInstance.configApplier(), callCfg)
	if err != nil {
		t.Fatal(err)
	}
	result, err := results.Result()
	if err != nil {
		t.Fatal(err)
	}
	if result.LatestAppliedVersion() != -1 {
		t.Fatalf("unexpected latest applied version %d", result.LatestAppliedVersion())
	}
	errText, err := result.Err()
	if err != nil {
		t.Fatal(err)
	}
	if errText == "" {
		t.Fatal("expected error text in update result")
	}
}
