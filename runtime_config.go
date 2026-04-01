package cloudflared

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"

	"golang.org/x/net/idna"
)

const (
	defaultHTTPConnectTimeout      = 30 * time.Second
	defaultTLSTimeout              = 10 * time.Second
	defaultTCPKeepAlive            = 30 * time.Second
	defaultKeepAliveTimeout        = 90 * time.Second
	defaultKeepAliveConnections    = 100
	defaultProxyAddress            = "127.0.0.1"
	defaultWarpRoutingConnectTime  = 5 * time.Second
	defaultWarpRoutingTCPKeepAlive = 30 * time.Second
)

type ResolvedServiceKind int

const (
	ResolvedServiceHTTP ResolvedServiceKind = iota
	ResolvedServiceStream
	ResolvedServiceStatus
	ResolvedServiceUnix
	ResolvedServiceUnixTLS
	ResolvedServiceBastion
	ResolvedServiceSocksProxy
)

type ResolvedService struct {
	Kind          ResolvedServiceKind
	Service       string
	Destination   M.Socksaddr
	StreamHasPort bool
	BaseURL       *url.URL
	UnixPath      string
	StatusCode    int
	SocksPolicy   *ipRulePolicy
	OriginRequest OriginRequestConfig
}

func (s ResolvedService) RouterControlled() bool {
	return s.Kind == ResolvedServiceHTTP || s.Kind == ResolvedServiceStream
}

func (s ResolvedService) BuildRequestURL(requestURL string) (string, error) {
	switch s.Kind {
	case ResolvedServiceHTTP, ResolvedServiceUnix, ResolvedServiceUnixTLS:
		requestParsed, err := url.Parse(requestURL)
		if err != nil {
			return "", err
		}
		originURL := *s.BaseURL
		originURL.Path = requestParsed.Path
		originURL.RawPath = requestParsed.RawPath
		originURL.RawQuery = requestParsed.RawQuery
		originURL.Fragment = requestParsed.Fragment
		return originURL.String(), nil
	default:
		return requestURL, nil
	}
}

func canonicalizeHTTPOriginURL(parsedURL *url.URL) *url.URL {
	if parsedURL == nil {
		return nil
	}
	canonicalURL := *parsedURL
	switch canonicalURL.Scheme {
	case "ws":
		canonicalURL.Scheme = "http"
	case "wss":
		canonicalURL.Scheme = "https"
	}
	return &canonicalURL
}

func isHTTPServiceScheme(scheme string) bool {
	switch scheme {
	case "http", "https", "ws", "wss":
		return true
	default:
		return false
	}
}

type compiledIngressRule struct {
	Hostname         string
	PunycodeHostname string
	Path             *regexp.Regexp
	Service          ResolvedService
}

type RuntimeConfig struct {
	Ingress       []compiledIngressRule
	OriginRequest OriginRequestConfig
	WarpRouting   WarpRoutingConfig
}

type OriginRequestConfig struct {
	ConnectTimeout         time.Duration
	TLSTimeout             time.Duration
	TCPKeepAlive           time.Duration
	NoHappyEyeballs        bool
	KeepAliveTimeout       time.Duration
	KeepAliveConnections   int
	HTTPHostHeader         string
	OriginServerName       string
	MatchSNIToHost         bool
	CAPool                 string
	NoTLSVerify            bool
	DisableChunkedEncoding bool
	BastionMode            bool
	ProxyAddress           string
	ProxyPort              uint
	ProxyType              string
	IPRules                []IPRule
	HTTP2Origin            bool
	Access                 AccessConfig
}

type AccessConfig struct {
	Required    bool
	TeamName    string
	AudTag      []string
	Environment string
}

type IPRule struct {
	Prefix string
	Ports  []int
	Allow  bool
}

type WarpRoutingConfig struct {
	ConnectTimeout time.Duration
	MaxActiveFlows uint64
	TCPKeepAlive   time.Duration
}

type ConfigUpdateResult struct {
	LastAppliedVersion int32
	Err                error
}

type ConfigManager struct {
	access         sync.RWMutex
	currentVersion int32
	activeConfig   RuntimeConfig
}

func NewConfigManager() (*ConfigManager, error) {
	config, err := defaultRuntimeConfig()
	if err != nil {
		return nil, err
	}
	return &ConfigManager{
		currentVersion: -1,
		activeConfig:   config,
	}, nil
}

func (m *ConfigManager) Snapshot() RuntimeConfig {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.activeConfig
}

func (m *ConfigManager) CurrentVersion() int32 {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.currentVersion
}

func (m *ConfigManager) Apply(version int32, raw []byte) ConfigUpdateResult {
	m.access.Lock()
	defer m.access.Unlock()

	if version <= m.currentVersion {
		return ConfigUpdateResult{LastAppliedVersion: m.currentVersion}
	}

	config, err := buildRemoteRuntimeConfig(raw)
	if err != nil {
		return ConfigUpdateResult{
			LastAppliedVersion: m.currentVersion,
			Err:                err,
		}
	}

	m.activeConfig = config
	m.currentVersion = version
	return ConfigUpdateResult{LastAppliedVersion: m.currentVersion}
}

func (m *ConfigManager) Resolve(hostname, path string) (ResolvedService, bool) {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.activeConfig.Resolve(hostname, path)
}

func (c RuntimeConfig) Resolve(hostname, path string) (ResolvedService, bool) {
	host := stripPort(hostname)
	for _, rule := range c.Ingress {
		if !matchIngressRule(rule, host, path) {
			continue
		}
		return rule.Service, true
	}
	return ResolvedService{}, false
}

func matchIngressRule(rule compiledIngressRule, hostname, path string) bool {
	hostMatch := rule.Hostname == "" || rule.Hostname == "*" || matchIngressHost(rule.Hostname, hostname)
	if !hostMatch && rule.PunycodeHostname != "" {
		hostMatch = matchIngressHost(rule.PunycodeHostname, hostname)
	}
	if !hostMatch {
		return false
	}
	return rule.Path == nil || rule.Path.MatchString(path)
}

func matchIngressHost(pattern, hostname string) bool {
	if pattern == hostname {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(hostname, strings.TrimPrefix(pattern, "*"))
	}
	return false
}

func defaultRuntimeConfig() (RuntimeConfig, error) {
	defaultOriginRequest := defaultOriginRequestConfig()
	compiledRules, err := compileIngressRules(defaultOriginRequest, nil)
	if err != nil {
		return RuntimeConfig{}, err
	}
	return RuntimeConfig{
		Ingress:       compiledRules,
		OriginRequest: defaultOriginRequest,
		WarpRouting: WarpRoutingConfig{
			ConnectTimeout: defaultWarpRoutingConnectTime,
			TCPKeepAlive:   defaultWarpRoutingTCPKeepAlive,
		},
	}, nil
}

func buildRemoteRuntimeConfig(raw []byte) (RuntimeConfig, error) {
	var remote remoteConfigJSON
	err := json.Unmarshal(raw, &remote)
	if err != nil {
		return RuntimeConfig{}, E.Cause(err, "decode remote config")
	}
	defaultOriginRequest := originRequestFromRemote(remote.OriginRequest)
	warpRouting := warpRoutingFromRemote(remote.WarpRouting)
	var ingressRules []localIngressRule
	for _, rule := range remote.Ingress {
		ingressRules = append(ingressRules, localIngressRule{
			Hostname:      rule.Hostname,
			Path:          rule.Path,
			Service:       rule.Service,
			OriginRequest: mergeRemoteOriginRequest(defaultOriginRequest, rule.OriginRequest),
		})
	}
	compiledRules, err := compileIngressRules(defaultOriginRequest, ingressRules)
	if err != nil {
		return RuntimeConfig{}, err
	}
	return RuntimeConfig{
		Ingress:       compiledRules,
		OriginRequest: defaultOriginRequest,
		WarpRouting:   warpRouting,
	}, nil
}

type localIngressRule struct {
	Hostname      string
	Path          string
	Service       string
	OriginRequest OriginRequestConfig
}

type remoteConfigJSON struct {
	OriginRequest remoteOriginRequestJSON `json:"originRequest"`
	Ingress       []remoteIngressRuleJSON `json:"ingress"`
	WarpRouting   remoteWarpRoutingJSON   `json:"warp-routing"`
}

type remoteIngressRuleJSON struct {
	Hostname      string                  `json:"hostname,omitempty"`
	Path          string                  `json:"path,omitempty"`
	Service       string                  `json:"service"`
	OriginRequest remoteOriginRequestJSON `json:"originRequest,omitempty"`
}

type remoteOriginRequestJSON struct {
	ConnectTimeout         int64              `json:"connectTimeout,omitempty"`
	TLSTimeout             int64              `json:"tlsTimeout,omitempty"`
	TCPKeepAlive           int64              `json:"tcpKeepAlive,omitempty"`
	NoHappyEyeballs        *bool              `json:"noHappyEyeballs,omitempty"`
	KeepAliveTimeout       int64              `json:"keepAliveTimeout,omitempty"`
	KeepAliveConnections   *int               `json:"keepAliveConnections,omitempty"`
	HTTPHostHeader         string             `json:"httpHostHeader,omitempty"`
	OriginServerName       string             `json:"originServerName,omitempty"`
	MatchSNIToHost         *bool              `json:"matchSNIToHost,omitempty"`
	CAPool                 string             `json:"caPool,omitempty"`
	NoTLSVerify            *bool              `json:"noTLSVerify,omitempty"`
	DisableChunkedEncoding *bool              `json:"disableChunkedEncoding,omitempty"`
	BastionMode            *bool              `json:"bastionMode,omitempty"`
	ProxyAddress           string             `json:"proxyAddress,omitempty"`
	ProxyPort              *uint              `json:"proxyPort,omitempty"`
	ProxyType              string             `json:"proxyType,omitempty"`
	IPRules                []remoteIPRuleJSON `json:"ipRules,omitempty"`
	HTTP2Origin            *bool              `json:"http2Origin,omitempty"`
	Access                 *remoteAccessJSON  `json:"access,omitempty"`
}

type remoteAccessJSON struct {
	Required    bool     `json:"required,omitempty"`
	TeamName    string   `json:"teamName,omitempty"`
	AudTag      []string `json:"audTag,omitempty"`
	Environment string   `json:"environment,omitempty"`
}

type remoteIPRuleJSON struct {
	Prefix string `json:"prefix,omitempty"`
	Ports  []int  `json:"ports,omitempty"`
	Allow  bool   `json:"allow,omitempty"`
}

type remoteWarpRoutingJSON struct {
	ConnectTimeout int64  `json:"connectTimeout,omitempty"`
	MaxActiveFlows uint64 `json:"maxActiveFlows,omitempty"`
	TCPKeepAlive   int64  `json:"tcpKeepAlive,omitempty"`
}

func compileIngressRules(defaultOriginRequest OriginRequestConfig, rawRules []localIngressRule) ([]compiledIngressRule, error) {
	if len(rawRules) == 0 {
		rawRules = []localIngressRule{{
			Service:       "http_status:503",
			OriginRequest: defaultOriginRequest,
		}}
	}
	if !isCatchAllRule(rawRules[len(rawRules)-1].Hostname, rawRules[len(rawRules)-1].Path) {
		return nil, E.New("the last ingress rule must be a catch-all rule")
	}

	compiled := make([]compiledIngressRule, 0, len(rawRules))
	for index, rule := range rawRules {
		err := validateHostname(rule.Hostname, index == len(rawRules)-1)
		if err != nil {
			return nil, err
		}
		err = validateAccessConfiguration(rule.OriginRequest.Access)
		if err != nil {
			return nil, err
		}
		service, err := parseResolvedService(rule.Service, rule.OriginRequest)
		if err != nil {
			return nil, err
		}
		var pathPattern *regexp.Regexp
		if rule.Path != "" {
			pathPattern, err = regexp.Compile(rule.Path)
			if err != nil {
				return nil, E.Cause(err, "compile ingress path regex")
			}
		}
		punycode := ""
		if rule.Hostname != "" && rule.Hostname != "*" {
			punycodeValue, err := idna.Lookup.ToASCII(rule.Hostname)
			if err == nil && punycodeValue != rule.Hostname {
				punycode = punycodeValue
			}
		}
		compiled = append(compiled, compiledIngressRule{
			Hostname:         rule.Hostname,
			PunycodeHostname: punycode,
			Path:             pathPattern,
			Service:          service,
		})
	}
	return compiled, nil
}

func parseResolvedService(rawService string, originRequest OriginRequestConfig) (ResolvedService, error) {
	switch {
	case rawService == "":
		if originRequest.BastionMode {
			return ResolvedService{
				Kind:          ResolvedServiceBastion,
				Service:       "bastion",
				OriginRequest: originRequest,
			}, nil
		}
		return ResolvedService{}, E.New("missing ingress service")
	case strings.HasPrefix(rawService, "http_status:"):
		statusCode, err := strconv.Atoi(strings.TrimPrefix(rawService, "http_status:"))
		if err != nil {
			return ResolvedService{}, E.Cause(err, "parse http_status service")
		}
		if statusCode < 100 || statusCode > 999 {
			return ResolvedService{}, E.New("invalid http_status code: ", statusCode)
		}
		return ResolvedService{
			Kind:          ResolvedServiceStatus,
			Service:       rawService,
			StatusCode:    statusCode,
			OriginRequest: originRequest,
		}, nil
	case rawService == "hello_world" || rawService == "hello-world":
		return ResolvedService{}, E.New("unsupported ingress service: hello_world")
	case rawService == "bastion":
		return ResolvedService{
			Kind:          ResolvedServiceBastion,
			Service:       rawService,
			OriginRequest: originRequest,
		}, nil
	case rawService == "socks-proxy":
		policy, err := newIPRulePolicy(originRequest.IPRules)
		if err != nil {
			return ResolvedService{}, E.Cause(err, "compile socks-proxy ip rules")
		}
		return ResolvedService{
			Kind:          ResolvedServiceSocksProxy,
			Service:       rawService,
			SocksPolicy:   policy,
			OriginRequest: originRequest,
		}, nil
	case strings.HasPrefix(rawService, "unix:"):
		return ResolvedService{
			Kind:          ResolvedServiceUnix,
			Service:       rawService,
			UnixPath:      strings.TrimPrefix(rawService, "unix:"),
			BaseURL:       &url.URL{Scheme: "http", Host: "localhost"},
			OriginRequest: originRequest,
		}, nil
	case strings.HasPrefix(rawService, "unix+tls:"):
		return ResolvedService{
			Kind:          ResolvedServiceUnixTLS,
			Service:       rawService,
			UnixPath:      strings.TrimPrefix(rawService, "unix+tls:"),
			BaseURL:       &url.URL{Scheme: "https", Host: "localhost"},
			OriginRequest: originRequest,
		}, nil
	}

	parsedURL, err := url.Parse(rawService)
	if err != nil {
		return ResolvedService{}, E.Cause(err, "parse ingress service URL")
	}
	if parsedURL.Scheme == "" || parsedURL.Hostname() == "" {
		return ResolvedService{}, E.New("ingress service must include scheme and hostname: ", rawService)
	}
	if parsedURL.Path != "" {
		return ResolvedService{}, E.New("ingress service cannot include a path: ", rawService)
	}

	if isHTTPServiceScheme(parsedURL.Scheme) {
		return ResolvedService{
			Kind:          ResolvedServiceHTTP,
			Service:       rawService,
			Destination:   parseHTTPServiceDestination(parsedURL),
			BaseURL:       canonicalizeHTTPOriginURL(parsedURL),
			OriginRequest: originRequest,
		}, nil
	}

	destination, hasPort := parseStreamServiceDestination(parsedURL)
	return ResolvedService{
		Kind:          ResolvedServiceStream,
		Service:       rawService,
		Destination:   destination,
		StreamHasPort: hasPort,
		BaseURL:       parsedURL,
		OriginRequest: originRequest,
	}, nil
}

func parseHTTPServiceDestination(parsedURL *url.URL) M.Socksaddr {
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		switch parsedURL.Scheme {
		case "https", "wss":
			port = "443"
		default:
			port = "80"
		}
	}
	return M.ParseSocksaddr(net.JoinHostPort(host, port))
}

func parseStreamServiceDestination(parsedURL *url.URL) (M.Socksaddr, bool) {
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		switch parsedURL.Scheme {
		case "ssh":
			port = "22"
		case "rdp":
			port = "3389"
		case "smb":
			port = "445"
		case "tcp":
			port = "7864"
		default:
			return M.ParseSocksaddrHostPort(host, 0), false
		}
	}
	return M.ParseSocksaddr(net.JoinHostPort(host, port)), true
}

func validateHostname(hostname string, isLast bool) error {
	if hostname == "" || hostname == "*" {
		if !isLast {
			return E.New("only the last ingress rule may be a catch-all rule")
		}
		return nil
	}
	if strings.Count(hostname, "*") > 1 || (strings.Contains(hostname, "*") && !strings.HasPrefix(hostname, "*.")) {
		return E.New("hostname wildcard must be in the form *.example.com")
	}
	if stripPort(hostname) != hostname {
		return E.New("ingress hostname cannot contain a port")
	}
	return nil
}

func isCatchAllRule(hostname, path string) bool {
	return (hostname == "" || hostname == "*") && path == ""
}

func stripPort(hostname string) string {
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		return host
	}
	return hostname
}

func defaultOriginRequestConfig() OriginRequestConfig {
	return OriginRequestConfig{
		ConnectTimeout:       defaultHTTPConnectTimeout,
		TLSTimeout:           defaultTLSTimeout,
		TCPKeepAlive:         defaultTCPKeepAlive,
		KeepAliveTimeout:     defaultKeepAliveTimeout,
		KeepAliveConnections: defaultKeepAliveConnections,
		ProxyAddress:         defaultProxyAddress,
	}
}

func originRequestFromRemote(input remoteOriginRequestJSON) OriginRequestConfig {
	config := defaultOriginRequestConfig()
	if input.ConnectTimeout != 0 {
		config.ConnectTimeout = time.Duration(input.ConnectTimeout) * time.Second
	}
	if input.TLSTimeout != 0 {
		config.TLSTimeout = time.Duration(input.TLSTimeout) * time.Second
	}
	if input.TCPKeepAlive != 0 {
		config.TCPKeepAlive = time.Duration(input.TCPKeepAlive) * time.Second
	}
	if input.KeepAliveTimeout != 0 {
		config.KeepAliveTimeout = time.Duration(input.KeepAliveTimeout) * time.Second
	}
	if input.KeepAliveConnections != nil {
		config.KeepAliveConnections = *input.KeepAliveConnections
	}
	if input.NoHappyEyeballs != nil {
		config.NoHappyEyeballs = *input.NoHappyEyeballs
	}
	config.HTTPHostHeader = input.HTTPHostHeader
	config.OriginServerName = input.OriginServerName
	if input.MatchSNIToHost != nil {
		config.MatchSNIToHost = *input.MatchSNIToHost
	}
	config.CAPool = input.CAPool
	if input.NoTLSVerify != nil {
		config.NoTLSVerify = *input.NoTLSVerify
	}
	if input.DisableChunkedEncoding != nil {
		config.DisableChunkedEncoding = *input.DisableChunkedEncoding
	}
	if input.BastionMode != nil {
		config.BastionMode = *input.BastionMode
	}
	if input.ProxyAddress != "" {
		config.ProxyAddress = input.ProxyAddress
	}
	if input.ProxyPort != nil {
		config.ProxyPort = *input.ProxyPort
	}
	config.ProxyType = input.ProxyType
	if input.HTTP2Origin != nil {
		config.HTTP2Origin = *input.HTTP2Origin
	}
	if input.Access != nil {
		config.Access = AccessConfig{
			Required:    input.Access.Required,
			TeamName:    input.Access.TeamName,
			AudTag:      append([]string(nil), input.Access.AudTag...),
			Environment: input.Access.Environment,
		}
	}
	for _, rule := range input.IPRules {
		config.IPRules = append(config.IPRules, IPRule{
			Prefix: rule.Prefix,
			Ports:  append([]int(nil), rule.Ports...),
			Allow:  rule.Allow,
		})
	}
	return config
}

func mergeRemoteOriginRequest(base OriginRequestConfig, override remoteOriginRequestJSON) OriginRequestConfig {
	result := base
	if override.ConnectTimeout != 0 {
		result.ConnectTimeout = time.Duration(override.ConnectTimeout) * time.Second
	}
	if override.TLSTimeout != 0 {
		result.TLSTimeout = time.Duration(override.TLSTimeout) * time.Second
	}
	if override.TCPKeepAlive != 0 {
		result.TCPKeepAlive = time.Duration(override.TCPKeepAlive) * time.Second
	}
	if override.NoHappyEyeballs != nil {
		result.NoHappyEyeballs = *override.NoHappyEyeballs
	}
	if override.KeepAliveTimeout != 0 {
		result.KeepAliveTimeout = time.Duration(override.KeepAliveTimeout) * time.Second
	}
	if override.KeepAliveConnections != nil {
		result.KeepAliveConnections = *override.KeepAliveConnections
	}
	if override.HTTPHostHeader != "" {
		result.HTTPHostHeader = override.HTTPHostHeader
	}
	if override.OriginServerName != "" {
		result.OriginServerName = override.OriginServerName
	}
	if override.MatchSNIToHost != nil {
		result.MatchSNIToHost = *override.MatchSNIToHost
	}
	if override.CAPool != "" {
		result.CAPool = override.CAPool
	}
	if override.NoTLSVerify != nil {
		result.NoTLSVerify = *override.NoTLSVerify
	}
	if override.DisableChunkedEncoding != nil {
		result.DisableChunkedEncoding = *override.DisableChunkedEncoding
	}
	if override.BastionMode != nil {
		result.BastionMode = *override.BastionMode
	}
	if override.ProxyAddress != "" {
		result.ProxyAddress = override.ProxyAddress
	}
	if override.ProxyPort != nil {
		result.ProxyPort = *override.ProxyPort
	}
	if override.ProxyType != "" {
		result.ProxyType = override.ProxyType
	}
	if len(override.IPRules) > 0 {
		result.IPRules = nil
		for _, rule := range override.IPRules {
			result.IPRules = append(result.IPRules, IPRule{
				Prefix: rule.Prefix,
				Ports:  append([]int(nil), rule.Ports...),
				Allow:  rule.Allow,
			})
		}
	}
	if override.HTTP2Origin != nil {
		result.HTTP2Origin = *override.HTTP2Origin
	}
	if override.Access != nil {
		result.Access = AccessConfig{
			Required:    override.Access.Required,
			TeamName:    override.Access.TeamName,
			AudTag:      append([]string(nil), override.Access.AudTag...),
			Environment: override.Access.Environment,
		}
	}
	return result
}

func warpRoutingFromRemote(input remoteWarpRoutingJSON) WarpRoutingConfig {
	config := WarpRoutingConfig{
		ConnectTimeout: defaultWarpRoutingConnectTime,
		TCPKeepAlive:   defaultWarpRoutingTCPKeepAlive,
		MaxActiveFlows: input.MaxActiveFlows,
	}
	if input.ConnectTimeout != 0 {
		config.ConnectTimeout = time.Duration(input.ConnectTimeout) * time.Second
	}
	if input.TCPKeepAlive != 0 {
		config.TCPKeepAlive = time.Duration(input.TCPKeepAlive) * time.Second
	}
	return config
}
