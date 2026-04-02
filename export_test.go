package cloudflared

import (
	"github.com/sagernet/sing-cloudflared/internal/config"
	"github.com/sagernet/sing-cloudflared/internal/control"
	"github.com/sagernet/sing-cloudflared/internal/datagram"
	"github.com/sagernet/sing-cloudflared/internal/discovery"
	"github.com/sagernet/sing-cloudflared/internal/icmp"
	"github.com/sagernet/sing-cloudflared/internal/protocol"
	"github.com/sagernet/sing-cloudflared/internal/transport"
)

// protocol types (re-exported for root test files)
type (
	ConnectRequest        = protocol.ConnectRequest
	ConnectResponse       = protocol.ConnectResponse
	ConnectionType        = protocol.ConnectionType
	Metadata              = protocol.Metadata
	ConnectResponseWriter = protocol.ConnectResponseWriter
	Credentials           = protocol.Credentials
	DatagramSender        = protocol.DatagramSender
	RequestID             = protocol.RequestID
	RegistrationResult    = protocol.RegistrationResult
	RetryableError        = protocol.RetryableError
	StreamType            = protocol.StreamType
)

// config types (re-exported for root test files)
type (
	ResolvedService     = config.ResolvedService
	ResolvedServiceKind = config.ResolvedServiceKind
	OriginRequestConfig = config.OriginRequestConfig
	AccessConfig        = config.AccessConfig
	IPRule              = config.IPRule
	RuntimeConfig       = config.RuntimeConfig
)

// protocol constants and variables
const (
	ConnectionTypeHTTP      = protocol.ConnectionTypeHTTP
	ConnectionTypeWebsocket = protocol.ConnectionTypeWebsocket
	ConnectionTypeTCP       = protocol.ConnectionTypeTCP
	StreamTypeData          = protocol.StreamTypeData
	StreamTypeRPC           = protocol.StreamTypeRPC
	DatagramV2TypeUDP         = protocol.DatagramV2TypeUDP
	DatagramV2TypeIP          = protocol.DatagramV2TypeIP
	DatagramV2TypeIPWithTrace = protocol.DatagramV2TypeIPWithTrace
	DatagramV2TypeTracingSpan = protocol.DatagramV2TypeTracingSpan
	DatagramV3TypeRegistration         = protocol.DatagramV3TypeRegistration
	DatagramV3TypePayload              = protocol.DatagramV3TypePayload
	DatagramV3TypeICMP                 = protocol.DatagramV3TypeICMP
	DatagramV3TypeRegistrationResponse = protocol.DatagramV3TypeRegistrationResponse
	MaxV3UDPPayloadLen = protocol.MaxV3UDPPayloadLen
)

var (
	ReadStreamSignature     = protocol.ReadStreamSignature
	ReadConnectRequest      = protocol.ReadConnectRequest
	WriteConnectResponse    = protocol.WriteConnectResponse
	WriteRPCStreamSignature = protocol.WriteRPCStreamSignature
	SerializeHeaders        = protocol.SerializeHeaders
	dataStreamSignature     = protocol.DataStreamSignature
	rpcStreamSignature      = protocol.RPCStreamSignature
	protocolVersion         = protocol.ProtocolVersion
	headerEncoding          = protocol.HeaderEncoding
	isControlResponseHeader = protocol.IsControlResponseHeader
	isWebsocketClientHeader = protocol.IsWebsocketClientHeader
	metadataHTTPMethod      = protocol.MetadataHTTPMethod
	metadataHTTPHost        = protocol.MetadataHTTPHost
	metadataHTTPHeader      = protocol.MetadataHTTPHeader
	metadataHTTPStatus      = protocol.MetadataHTTPStatus
	defaultDatagramVersion  = protocol.DefaultDatagramVersion
	datagramVersionV3       = protocol.DatagramVersionV3
	maxV3UDPPayloadLen      = protocol.MaxV3UDPPayloadLen
	typeIDLength            = protocol.TypeIDLength
)

// discovery
type EdgeAddr = discovery.EdgeAddr

var (
	DiscoverEdge      = discovery.DiscoverEdge
	FilterByIPVersion = discovery.FilterByIPVersion
)

// config
type (
	compiledIngressRule     = config.CompiledIngressRule
	remoteOriginRequestJSON = config.RemoteOriginRequestJSON
	remoteAccessJSON        = config.RemoteAccessJSON
	remoteIPRuleJSON        = config.RemoteIPRuleJSON
	remoteWarpRoutingJSON   = config.RemoteWarpRoutingJSON
)

const (
	ResolvedServiceStatus     = config.ResolvedServiceStatus
	ResolvedServiceHTTP       = config.ResolvedServiceHTTP
	ResolvedServiceStream     = config.ResolvedServiceStream
	ResolvedServiceUnix       = config.ResolvedServiceUnix
	ResolvedServiceUnixTLS    = config.ResolvedServiceUnixTLS
	ResolvedServiceBastion    = config.ResolvedServiceBastion
	ResolvedServiceSocksProxy = config.ResolvedServiceSocksProxy
)

var (
	NewConfigManager               = config.NewConfigManager
	defaultOriginRequestConfig     = config.DefaultOriginRequestConfig
	compileIngressRules            = config.CompileIngressRules
	buildRemoteRuntimeConfig       = config.BuildRemoteRuntimeConfig
	mergeRemoteOriginRequest       = config.MergeRemoteOriginRequest
	warpRoutingFromRemote          = config.WarpRoutingFromRemote
	validateHostname               = config.ValidateHostname
	matchIngressRule               = config.MatchIngressRule
	parseResolvedService           = config.ParseResolvedService
	newIPRulePolicy                = config.NewIPRulePolicy
	resolvePolicyDestination       = config.ResolvePolicyDestination
	defaultWarpRoutingConnectTime  = config.DefaultWarpRoutingConnectTime
	defaultWarpRoutingTCPKeepAlive = config.DefaultWarpRoutingTCPKeepAlive
)

// control
type permanentRegistrationError = control.PermanentRegistrationError

var (
	ErrNonRemoteManagedTunnelUnsupported = control.ErrNonRemoteManagedTunnelUnsupported
	DefaultFeatures                      = control.DefaultFeatures
	safeTransport                        = control.SafeTransport
	newRPCClientConn                     = control.NewRPCClientConn
	newRPCServerConn                     = control.NewRPCServerConn
)

// transport
type (
	HTTP2Connection     = transport.HTTP2Connection
	QUICConnection      = transport.QUICConnection
	StreamHandler       = transport.StreamHandler
	http2FlushState     = transport.HTTP2FlushState
	http2ResponseWriter = transport.HTTP2ResponseWriter
	http2DataStream     = transport.HTTP2DataStream
	http2FlushWriter    = transport.HTTP2FlushWriter
	featureSelector     = transport.FeatureSelector
	quicStreamHandle    = transport.QuicStreamHandle
)

var (
	NewHTTP2Connection           = transport.NewHTTP2Connection
	NewQUICConnection            = transport.NewQUICConnection
	loadCloudflareRootCertPool   = transport.LoadCloudflareRootCertPool
	dialQUIC                     = transport.DialQUIC
	newHTTP2Stream               = transport.NewHTTP2Stream
	newStreamReadWriteCloser     = transport.NewStreamReadWriteCloser
	newWebsocketConn             = transport.NewWebsocketConn
	isRetryableReadError         = transport.IsRetryableReadError
	wrapWebsocketError           = transport.WrapWebsocketError
	newFeatureSelector           = transport.NewFeatureSelector
	resolveRemoteDatagramVersion = transport.ResolveRemoteDatagramVersion
	accountEnabled               = transport.AccountEnabled
	newEdgeTLSConfig             = transport.NewEdgeTLSConfig
	applyPostQuantumCurvePreferences = transport.ApplyPostQuantumCurvePreferences
	h2HeaderUpgrade              = protocol.H2HeaderUpgrade
	h2HeaderResponseMeta         = protocol.H2HeaderResponseMeta
	h2UpgradeWebsocket           = protocol.H2UpgradeWebsocket
	h2ResponseMetaCloudflared    = transport.H2ResponseMetaCloudflared
	h2EdgeSNI                    = transport.H2EdgeSNI
	quicEdgeSNI                  = transport.QuicEdgeSNI
	quicEdgeALPN                 = transport.QuicEdgeALPN
	x25519MLKEM768PQKex          = transport.X25519MLKEM768PQKex
	featurePostQuantum           = transport.FeaturePostQuantum
	protocolQUIC                 = transport.ProtocolQUIC
	protocolHTTP2                = transport.ProtocolHTTP2
)

const defaultProtocolRetry = transport.DefaultProtocolRetry

// datagram
type (
	DatagramV2Muxer     = datagram.DatagramV2Muxer
	DatagramV3Muxer     = datagram.DatagramV3Muxer
	FlowLimiter         = datagram.FlowLimiter
	udpSession          = datagram.UDPSession
	v3Session           = datagram.V3Session
	cloudflaredServer   = datagram.CloudflaredServer
	cloudflaredV3Server = datagram.CloudflaredV3Server
)

var (
	NewDatagramV2Muxer          = datagram.NewDatagramV2Muxer
	NewDatagramV3Muxer          = datagram.NewDatagramV3Muxer
	NewDatagramV3SessionManager = datagram.NewDatagramV3SessionManager
	ServeRPCStream              = datagram.ServeRPCStream
	ServeV3RPCStream            = datagram.ServeV3RPCStream
	newUDPSession               = datagram.NewUDPSession
	newV2SessionRPCClient       = datagram.NewV2SessionRPCClient
	sessionIDLength             = datagram.SessionIDLength
	errUnsupportedDatagramV3UDPRegistration   = datagram.ErrUnsupportedDatagramV3UDPRegistration
	errUnsupportedDatagramV3UDPUnregistration = datagram.ErrUnsupportedDatagramV3UDPUnregistration
	v3FlagIPv6                       = datagram.V3FlagIPv6
	v3ResponseErrorWithMsg           = datagram.V3ResponseErrorWithMsg
	v3ResponseDestinationUnreachable = datagram.V3ResponseDestinationUnreachable
	v3RegistrationFlagLen            = datagram.V3RegistrationFlagLen
	v3RegistrationPortLen            = datagram.V3RegistrationPortLen
	v3RegistrationIdleLen            = datagram.V3RegistrationIdleLen
	v3RequestIDLength                = datagram.V3RequestIDLength
	v3IPv4AddrLen                    = datagram.V3IPv4AddrLen
	v3IPv6AddrLen                    = datagram.V3IPv6AddrLen
	v3PayloadHeaderLen               = datagram.V3PayloadHeaderLen
)

// icmp
type (
	ICMPFlowKey      = icmp.FlowKey
	ICMPRequestKey   = icmp.RequestKey
	ICMPTraceContext = icmp.TraceContext
	icmpWireVersion  = icmp.WireVersion
	traceEntry       = icmp.TraceEntry
)

var (
	NewICMPBridge              = icmp.NewBridge
	ParseICMPPacket            = icmp.ParsePacket
	newRouteCache              = icmp.NewRouteCache
	buildICMPTTLExceededPacket = icmp.BuildTTLExceededPacket
	encodeV3ICMPDatagram       = icmp.EncodeV3Datagram
	maxEncodedICMPPacketLen    = icmp.MaxEncodedPacketLen
	maxICMPPayloadLen          = icmp.MaxPayloadLen
	icmpFlowTimeout            = icmp.FlowTimeout
	icmpTraceIdentityLength    = icmp.TraceIdentityLength
	icmpErrorHeaderLen         = icmp.ErrorHeaderLen
	ipv4TTLExceededQuoteLen    = icmp.IPv4TTLExceededQuoteLen
	ipv6TTLExceededQuoteLen    = icmp.IPv6TTLExceededQuoteLen
	icmpWireV2                 = icmp.WireV2
	icmpWireV3                 = icmp.WireV3
	icmpv4TypeEchoRequest      = icmp.V4TypeEchoRequest
	icmpv4TypeTimeExceeded     = icmp.V4TypeTimeExceeded
	icmpv6TypeEchoRequest      = icmp.V6TypeEchoRequest
	icmpv6TypeTimeExceeded     = icmp.V6TypeTimeExceeded
)

// edge discovery hooks - these are function variables so we alias them
var (
	lookupEdgeSRVFn        = &discovery.LookupEdgeSRVFn
	lookupEdgeSRVWithDoTFn = &discovery.LookupEdgeSRVWithDoTFn
	edgeLookupSRV          = &discovery.EdgeLookupSRV
	edgeLookupIP           = &discovery.EdgeLookupIP
	edgeDoTDestination     = &discovery.EdgeDoTDestination
	edgeDoTTLSClient       = &discovery.EdgeDoTTLSClient
	dotServerName          = discovery.DotServerName
	dotServerAddr          = discovery.DotServerAddr
	edgeSRVService         = discovery.EdgeSRVService
	getRegionalServiceName = discovery.GetRegionalServiceName
	resolveSRVRecords      = discovery.ResolveSRVRecords
)
