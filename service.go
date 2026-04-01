package cloudflared

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

var ErrNonRemoteManagedTunnelUnsupported = E.New("cloudflared only supports remote-managed tunnels")

var (
	newQUICConnection   = NewQUICConnection
	newHTTP2Connection  = NewHTTP2Connection
	serveQUICConnection = func(connection *QUICConnection, ctx context.Context, handler StreamHandler) error {
		return connection.Serve(ctx, handler)
	}
	serveHTTP2Connection = func(connection *HTTP2Connection, ctx context.Context) error {
		return connection.Serve(ctx)
	}
)

type Service struct {
	ctx             context.Context
	cancel          context.CancelFunc
	logger          logger.ContextLogger
	handler         Handler
	icmpHandler     ICMPHandler
	newContext      func(context.Context) context.Context
	clientVersion   string
	credentials     Credentials
	connectorID     uuid.UUID
	haConnections   int
	protocol        string
	region          string
	edgeIPVersion   int
	datagramVersion string
	featureSelector *featureSelector
	gracePeriod     time.Duration
	configManager   *ConfigManager
	flowLimiter     *FlowLimiter
	accessCache     *accessValidatorCache
	controlDialer   N.Dialer
	tunnelDialer    N.Dialer

	connectionAccess sync.Mutex
	connections      []io.Closer
	done             sync.WaitGroup

	datagramMuxerAccess sync.Mutex
	datagramV2Muxers    map[DatagramSender]*DatagramV2Muxer
	datagramV3Muxers    map[DatagramSender]*DatagramV3Muxer
	datagramV3Manager   *DatagramV3SessionManager

	connectedAccess  sync.Mutex
	connectedIndices map[uint8]struct{}
	connectedNotify  chan uint8

	stateAccess             sync.Mutex
	connectionStates        []connectionState
	successfulProtocols     map[string]struct{}
	firstSuccessfulProtocol string

	directTransportAccess sync.Mutex
	directTransports      map[string]*http.Transport
}

type connectionState struct {
	protocol string
	retries  uint8
}

func connectionRetryDecision(err error) (retry bool, cancelAll bool) {
	switch {
	case err == nil:
		return false, false
	case errors.Is(err, ErrNonRemoteManagedTunnelUnsupported):
		return false, true
	case isPermanentRegistrationError(err):
		return false, false
	default:
		return true, false
	}
}

func NewService(options ServiceOptions) (*Service, error) {
	if options.Token == "" {
		return nil, E.New("missing token")
	}
	credentials, err := parseToken(options.Token)
	if err != nil {
		return nil, E.Cause(err, "parse token")
	}

	haConnections := options.HAConnections
	if haConnections <= 0 {
		haConnections = 4
	}

	protocol, err := normalizeProtocol(options.Protocol)
	if err != nil {
		return nil, err
	}

	edgeIPVersion := options.EdgeIPVersion
	if edgeIPVersion != 0 && edgeIPVersion != 4 && edgeIPVersion != 6 {
		return nil, E.New("unsupported edge_ip_version: ", edgeIPVersion, ", expected 0, 4 or 6")
	}

	datagramVersion := options.DatagramVersion
	if datagramVersion != "" && datagramVersion != "v2" && datagramVersion != "v3" {
		return nil, E.New("unsupported datagram_version: ", datagramVersion, ", expected v2 or v3")
	}

	gracePeriod := options.GracePeriod
	if gracePeriod <= 0 {
		gracePeriod = 30 * time.Second
	}

	configManager, err := NewConfigManager()
	if err != nil {
		return nil, E.Cause(err, "build cloudflared runtime config")
	}

	controlDialer := options.ControlDialer
	if controlDialer == nil {
		controlDialer = N.SystemDialer
	}
	tunnelDialer := options.TunnelDialer
	if tunnelDialer == nil {
		tunnelDialer = N.SystemDialer
	}

	serviceLogger := options.Logger
	if serviceLogger == nil {
		serviceLogger = logger.NOP()
	}

	region := options.Region
	if region != "" && credentials.Endpoint != "" {
		return nil, E.New("region cannot be specified when credentials already include an endpoint")
	}
	if region == "" {
		region = credentials.Endpoint
	}

	clientVersion := options.ClientVersion
	if clientVersion == "" {
		clientVersion = "sing-cloudflared"
	}

	newContextFn := options.NewContext
	if newContextFn == nil {
		newContextFn = contextWithNewID
	}

	serviceCtx, cancel := context.WithCancel(context.Background())

	return &Service{
		ctx:                 serviceCtx,
		cancel:              cancel,
		logger:              serviceLogger,
		handler:             options.Handler,
		icmpHandler:         options.ICMPHandler,
		newContext:          newContextFn,
		clientVersion:       clientVersion,
		credentials:         credentials,
		connectorID:         uuid.New(),
		haConnections:       haConnections,
		protocol:            protocol,
		region:              region,
		edgeIPVersion:       edgeIPVersion,
		datagramVersion:     datagramVersion,
		featureSelector:     newFeatureSelector(serviceCtx, credentials.AccountTag, datagramVersion),
		gracePeriod:         gracePeriod,
		configManager:       configManager,
		flowLimiter:         &FlowLimiter{},
		accessCache:         &accessValidatorCache{values: make(map[string]accessValidator), dialer: controlDialer},
		controlDialer:       controlDialer,
		tunnelDialer:        tunnelDialer,
		datagramV2Muxers:    make(map[DatagramSender]*DatagramV2Muxer),
		datagramV3Muxers:    make(map[DatagramSender]*DatagramV3Muxer),
		datagramV3Manager:   NewDatagramV3SessionManager(),
		connectedIndices:    make(map[uint8]struct{}),
		connectedNotify:     make(chan uint8, haConnections),
		connectionStates:    make([]connectionState, haConnections),
		successfulProtocols: make(map[string]struct{}),
		directTransports:    make(map[string]*http.Transport),
	}, nil
}

func (s *Service) Start() error {
	s.logger.Info("starting Cloudflare Tunnel with ", s.haConnections, " HA connections")

	regions, err := DiscoverEdge(s.ctx, s.region, s.controlDialer)
	if err != nil {
		return E.Cause(err, "discover edge")
	}
	regions = FilterByIPVersion(regions, s.edgeIPVersion)
	edgeAddrs := flattenRegions(regions)
	if len(edgeAddrs) == 0 {
		return E.New("no edge addresses available")
	}
	if cappedHAConnections := effectiveHAConnections(s.haConnections, len(edgeAddrs)); cappedHAConnections != s.haConnections {
		s.logger.Info("requested ", s.haConnections, " HA connections but only ", cappedHAConnections, " edge addresses are available")
		s.haConnections = cappedHAConnections
	}

	for connIndex := 0; connIndex < s.haConnections; connIndex++ {
		s.initializeConnectionState(uint8(connIndex))
		s.done.Add(1)
		go s.superviseConnection(uint8(connIndex), edgeAddrs)
		select {
		case readyConnIndex := <-s.connectedNotify:
			if readyConnIndex != uint8(connIndex) {
				s.logger.Debug("received unexpected ready notification for connection ", readyConnIndex)
			}
		case <-time.After(firstConnectionReadyTimeout):
		case <-s.ctx.Done():
			if connIndex == 0 {
				return s.ctx.Err()
			}
			return nil
		}
	}
	return nil
}

func (s *Service) notifyConnected(connIndex uint8, protocol string) {
	s.stateAccess.Lock()
	if s.successfulProtocols == nil {
		s.successfulProtocols = make(map[string]struct{})
	}
	s.ensureConnectionStateLocked(connIndex)
	state := s.connectionStates[connIndex]
	state.retries = 0
	state.protocol = protocol
	s.connectionStates[connIndex] = state
	if protocol != "" {
		s.successfulProtocols[protocol] = struct{}{}
		if s.firstSuccessfulProtocol == "" {
			s.firstSuccessfulProtocol = protocol
		}
	}
	s.stateAccess.Unlock()

	if s.connectedNotify == nil {
		return
	}
	s.connectedAccess.Lock()
	if _, loaded := s.connectedIndices[connIndex]; loaded {
		s.connectedAccess.Unlock()
		return
	}
	s.connectedIndices[connIndex] = struct{}{}
	s.connectedAccess.Unlock()
	s.connectedNotify <- connIndex
}

func (s *Service) ApplyConfig(version int32, config []byte) ConfigUpdateResult {
	result := s.configManager.Apply(version, config)
	if result.Err != nil {
		s.logger.Error("update ingress configuration: ", result.Err)
		return result
	}
	s.resetDirectOriginTransports()
	s.logger.Info("updated ingress configuration (version ", result.LastAppliedVersion, ")")
	return result
}

func (s *Service) maxActiveFlows() uint64 {
	return s.configManager.Snapshot().WarpRouting.MaxActiveFlows
}

func (s *Service) Close() error {
	s.cancel()
	s.done.Wait()
	s.connectionAccess.Lock()
	for _, connection := range s.connections {
		connection.Close()
	}
	s.connections = nil
	s.connectionAccess.Unlock()
	s.resetDirectOriginTransports()
	return nil
}

const (
	backoffBaseTime             = time.Second
	backoffMaxTime              = 2 * time.Minute
	firstConnectionReadyTimeout = 15 * time.Second
)

func (s *Service) superviseConnection(connIndex uint8, edgeAddrs []*EdgeAddr) {
	defer s.done.Done()

	edgeIndex := initialEdgeAddrIndex(connIndex, len(edgeAddrs))
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		edgeAddr := edgeAddrs[edgeIndex]
		err := s.safeServeConnection(connIndex, edgeAddr)
		if err == nil || s.ctx.Err() != nil {
			return
		}
		retry, cancelAll := connectionRetryDecision(err)
		if cancelAll {
			s.logger.Error("connection ", connIndex, " failed permanently: ", err)
			s.cancel()
			return
		}
		if !retry {
			s.logger.Error("connection ", connIndex, " failed permanently: ", err)
			return
		}

		retries := s.incrementConnectionRetries(connIndex)
		edgeIndex = rotateEdgeAddrIndex(edgeIndex, len(edgeAddrs))
		backoff := backoffDuration(int(retries))
		var retryableErr *RetryableError
		if errors.As(err, &retryableErr) && retryableErr.Delay > 0 {
			backoff = retryableErr.Delay
		}
		s.logger.Error("connection ", connIndex, " failed: ", err, ", retrying in ", backoff)

		select {
		case <-time.After(backoff):
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Service) serveConnection(connIndex uint8, edgeAddr *EdgeAddr) error {
	state := s.connectionState(connIndex)
	protocol := state.protocol
	numPreviousAttempts := state.retries
	datagramVersion, features := s.currentConnectionFeatures()

	switch protocol {
	case "quic":
		err := s.serveQUIC(connIndex, edgeAddr, datagramVersion, features, numPreviousAttempts)
		if err == nil || s.ctx.Err() != nil {
			return err
		}
		if errors.Is(err, ErrNonRemoteManagedTunnelUnsupported) {
			return err
		}
		if !s.protocolIsAuto() {
			return err
		}
		if s.hasSuccessfulProtocol("quic") {
			return err
		}
		s.setConnectionProtocol(connIndex, "http2")
		s.logger.Warn("QUIC connection failed, falling back to HTTP/2: ", err)
		return s.serveHTTP2(connIndex, edgeAddr, features, numPreviousAttempts)
	case "http2":
		return s.serveHTTP2(connIndex, edgeAddr, features, numPreviousAttempts)
	default:
		return E.New("unsupported protocol: ", protocol)
	}
}

func (s *Service) safeServeConnection(connIndex uint8, edgeAddr *EdgeAddr) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = E.New("panic in serve connection: ", recovered, "\n", string(debug.Stack()))
		}
	}()
	return s.serveConnection(connIndex, edgeAddr)
}

func (s *Service) serveQUIC(connIndex uint8, edgeAddr *EdgeAddr, datagramVersion string, features []string, numPreviousAttempts uint8) error {
	s.logger.Info("connecting to edge via QUIC (connection ", connIndex, ")")

	connection, err := newQUICConnection(
		s.ctx, edgeAddr, connIndex,
		s.credentials, s.connectorID, datagramVersion,
		features, numPreviousAttempts, s.gracePeriod, s.tunnelDialer, func() {
			s.notifyConnected(connIndex, "quic")
		}, s.logger,
	)
	if err != nil {
		return E.Cause(err, "create QUIC connection")
	}

	s.trackConnection(connection)
	defer func() {
		s.untrackConnection(connection)
		s.RemoveDatagramMuxer(connection)
	}()

	return serveQUICConnection(connection, s.ctx, s)
}

func (s *Service) currentConnectionFeatures() (string, []string) {
	if s.featureSelector != nil {
		return s.featureSelector.Snapshot()
	}
	version := s.datagramVersion
	if version == "" {
		version = defaultDatagramVersion
	}
	return version, DefaultFeatures(version)
}

func (s *Service) serveHTTP2(connIndex uint8, edgeAddr *EdgeAddr, features []string, numPreviousAttempts uint8) error {
	s.logger.Info("connecting to edge via HTTP/2 (connection ", connIndex, ")")

	connection, err := newHTTP2Connection(
		s.ctx, edgeAddr, connIndex,
		s.credentials, s.connectorID,
		features, numPreviousAttempts, s.gracePeriod, s, s.logger,
	)
	if err != nil {
		return E.Cause(err, "create HTTP/2 connection")
	}

	s.trackConnection(connection)
	defer s.untrackConnection(connection)

	return serveHTTP2Connection(connection, s.ctx)
}

func (s *Service) initializeConnectionState(connIndex uint8) {
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()
	s.ensureConnectionStateLocked(connIndex)
	if s.connectionStates[connIndex].protocol == "" {
		s.connectionStates[connIndex].protocol = s.initialProtocolLocked()
	}
}

func (s *Service) connectionState(connIndex uint8) connectionState {
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()
	s.ensureConnectionStateLocked(connIndex)
	state := s.connectionStates[connIndex]
	if state.protocol == "" {
		state.protocol = s.initialProtocolLocked()
		s.connectionStates[connIndex] = state
	}
	return state
}

func (s *Service) incrementConnectionRetries(connIndex uint8) uint8 {
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()
	s.ensureConnectionStateLocked(connIndex)
	state := s.connectionStates[connIndex]
	state.retries++
	s.connectionStates[connIndex] = state
	return state.retries
}

func (s *Service) setConnectionProtocol(connIndex uint8, protocol string) {
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()
	s.ensureConnectionStateLocked(connIndex)
	state := s.connectionStates[connIndex]
	state.protocol = protocol
	s.connectionStates[connIndex] = state
}

func (s *Service) hasSuccessfulProtocol(protocol string) bool {
	s.stateAccess.Lock()
	defer s.stateAccess.Unlock()
	if s.successfulProtocols == nil {
		return false
	}
	_, ok := s.successfulProtocols[protocol]
	return ok
}

func (s *Service) protocolIsAuto() bool {
	return s.protocol == ""
}

func (s *Service) ensureConnectionStateLocked(connIndex uint8) {
	requiredLen := int(connIndex) + 1
	if len(s.connectionStates) >= requiredLen {
		return
	}
	grown := make([]connectionState, requiredLen)
	copy(grown, s.connectionStates)
	s.connectionStates = grown
}

func (s *Service) initialProtocolLocked() string {
	if s.protocol != "" {
		return s.protocol
	}
	if s.firstSuccessfulProtocol != "" {
		return s.firstSuccessfulProtocol
	}
	return "quic"
}

func (s *Service) resetDirectOriginTransports() {
	s.directTransportAccess.Lock()
	transports := s.directTransports
	s.directTransports = make(map[string]*http.Transport)
	s.directTransportAccess.Unlock()

	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}

func (s *Service) trackConnection(connection io.Closer) {
	s.connectionAccess.Lock()
	defer s.connectionAccess.Unlock()
	s.connections = append(s.connections, connection)
}

func (s *Service) untrackConnection(connection io.Closer) {
	s.connectionAccess.Lock()
	defer s.connectionAccess.Unlock()
	for index, tracked := range s.connections {
		if tracked == connection {
			s.connections = append(s.connections[:index], s.connections[index+1:]...)
			break
		}
	}
}

func backoffDuration(retries int) time.Duration {
	backoff := backoffBaseTime * (1 << min(retries, 7))
	if backoff > backoffMaxTime {
		backoff = backoffMaxTime
	}
	jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
	return backoff/2 + jitter
}

func initialEdgeAddrIndex(connIndex uint8, size int) int {
	if size <= 1 {
		return 0
	}
	return int(connIndex) % size
}

func rotateEdgeAddrIndex(current int, size int) int {
	if size <= 1 {
		return 0
	}
	return (current + 1) % size
}

func flattenRegions(regions [][]*EdgeAddr) []*EdgeAddr {
	var result []*EdgeAddr
	for _, region := range regions {
		result = append(result, region...)
	}
	return result
}

func effectiveHAConnections(requested, available int) int {
	if available <= 0 {
		return 0
	}
	if requested > available {
		return available
	}
	return requested
}

func parseToken(token string) (Credentials, error) {
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return Credentials{}, E.Cause(err, "decode token")
	}
	var tunnelToken TunnelToken
	err = json.Unmarshal(data, &tunnelToken)
	if err != nil {
		return Credentials{}, E.Cause(err, "unmarshal token")
	}
	return tunnelToken.ToCredentials(), nil
}

func normalizeProtocol(protocol string) (string, error) {
	if protocol == "auto" {
		return "", nil
	}
	if protocol != "" && protocol != "quic" && protocol != "http2" {
		return "", E.New("unsupported protocol: ", protocol, ", expected auto, quic or http2")
	}
	return protocol, nil
}
