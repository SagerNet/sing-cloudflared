package cloudflared

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	metadataHTTPMethod = "HttpMethod"
	metadataHTTPHost   = "HttpHost"
	metadataHTTPHeader = "HttpHeader"
	metadataHTTPStatus = "HttpStatus"
)

var (
	loadOriginCABasePool = cloudflareRootCertPool
	readOriginCAFile     = os.ReadFile
	proxyFromEnvironment = http.ProxyFromEnvironment
)

type ConnectResponseWriter interface {
	WriteResponse(responseError error, metadata []Metadata) error
}

type connectResponseTrailerWriter interface {
	AddTrailer(name, value string)
}

type quicResponseWriter struct {
	stream io.Writer
}

func (w *quicResponseWriter) WriteResponse(responseError error, metadata []Metadata) error {
	return WriteConnectResponse(w.stream, responseError, metadata...)
}

func (s *Service) HandleDataStream(ctx context.Context, stream io.ReadWriteCloser, request *ConnectRequest, connIndex uint8) {
	if s.newContext != nil {
		ctx = s.newContext(ctx)
	}
	respWriter := &quicResponseWriter{stream: stream}
	s.dispatchRequest(ctx, stream, respWriter, request)
}

func (s *Service) HandleRPCStream(ctx context.Context, stream io.ReadWriteCloser, connIndex uint8) {
	s.logger.DebugContext(ctx, "received RPC stream on connection ", connIndex)
}

func (s *Service) HandleRPCStreamWithSender(ctx context.Context, stream io.ReadWriteCloser, connIndex uint8, sender DatagramSender) {
	switch datagramVersionForSender(sender) {
	case "v3":
		ServeV3RPCStream(ctx, stream, s, s.logger)
	default:
		muxer := s.getOrCreateV2Muxer(sender)
		ServeRPCStream(ctx, stream, s, muxer, s.logger)
	}
}

func (s *Service) HandleDatagram(ctx context.Context, datagram []byte, sender DatagramSender) {
	switch datagramVersionForSender(sender) {
	case "v3":
		muxer := s.getOrCreateV3Muxer(sender)
		muxer.HandleDatagram(ctx, datagram)
	default:
		muxer := s.getOrCreateV2Muxer(sender)
		muxer.HandleDatagram(ctx, datagram)
	}
}

func (s *Service) getOrCreateV2Muxer(sender DatagramSender) *DatagramV2Muxer {
	s.datagramMuxerAccess.Lock()
	defer s.datagramMuxerAccess.Unlock()
	muxer, exists := s.datagramV2Muxers[sender]
	if !exists {
		muxer = NewDatagramV2Muxer(s, sender, s.logger)
		s.datagramV2Muxers[sender] = muxer
	}
	return muxer
}

func (s *Service) getOrCreateV3Muxer(sender DatagramSender) *DatagramV3Muxer {
	s.datagramMuxerAccess.Lock()
	defer s.datagramMuxerAccess.Unlock()
	muxer, exists := s.datagramV3Muxers[sender]
	if !exists {
		muxer = NewDatagramV3Muxer(s, sender, s.logger)
		s.datagramV3Muxers[sender] = muxer
	}
	return muxer
}

func (s *Service) RemoveDatagramMuxer(sender DatagramSender) {
	s.datagramMuxerAccess.Lock()
	if muxer, exists := s.datagramV2Muxers[sender]; exists {
		muxer.Close()
		delete(s.datagramV2Muxers, sender)
	}
	if muxer, exists := s.datagramV3Muxers[sender]; exists {
		muxer.Close()
		delete(s.datagramV3Muxers, sender)
	}
	s.datagramMuxerAccess.Unlock()
}

func (s *Service) dispatchRequest(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest) {
	switch request.Type {
	case ConnectionTypeTCP:
		destination := M.ParseSocksaddr(request.Dest)
		s.handleTCPStream(ctx, stream, respWriter, destination)
	case ConnectionTypeHTTP, ConnectionTypeWebsocket:
		service, originURL, err := s.resolveHTTPService(request.Dest)
		if err != nil {
			s.logger.ErrorContext(ctx, "resolve origin service: ", err)
			respWriter.WriteResponse(err, nil)
			return
		}
		request.Dest = originURL
		s.handleHTTPService(ctx, stream, respWriter, request, service)
	default:
		s.logger.ErrorContext(ctx, "unknown connection type: ", request.Type)
	}
}

func (s *Service) resolveHTTPService(requestURL string) (ResolvedService, string, error) {
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return ResolvedService{}, "", E.Cause(err, "parse request URL")
	}
	service, loaded := s.configManager.Resolve(parsedURL.Hostname(), parsedURL.Path)
	if !loaded {
		return ResolvedService{}, "", E.New("no ingress rule matched request host/path")
	}
	originURL, err := service.BuildRequestURL(requestURL)
	if err != nil {
		return ResolvedService{}, "", E.Cause(err, "build origin request URL")
	}
	return service, originURL, nil
}

func parseHTTPDestination(dest string) M.Socksaddr {
	parsed, err := url.Parse(dest)
	if err != nil {
		return M.ParseSocksaddr(dest)
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "https", "wss":
			port = "443"
		default:
			port = "80"
		}
	}
	return M.ParseSocksaddr(net.JoinHostPort(host, port))
}

func (s *Service) handleTCPStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, destination M.Socksaddr) {
	s.logger.InfoContext(ctx, "inbound TCP connection to ", destination)
	limit := s.maxActiveFlows()
	if !s.flowLimiter.Acquire(limit) {
		err := E.New("too many active flows")
		s.logger.ErrorContext(ctx, err)
		respWriter.WriteResponse(err, flowConnectRateLimitedMetadata())
		return
	}
	defer s.flowLimiter.Release(limit)

	warpRouting := s.configManager.Snapshot().WarpRouting
	targetConn, cleanup, err := s.dialRouterTCPWithMetadata(ctx, destination, routedPipeTCPOptions{
		timeout: warpRouting.ConnectTimeout,
		onHandshake: func(conn net.Conn) {
			_ = applyTCPKeepAlive(conn, warpRouting.TCPKeepAlive)
		},
	})
	if err != nil {
		s.logger.ErrorContext(ctx, "dial tcp origin: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer cleanup()

	err = respWriter.WriteResponse(nil, nil)
	if err != nil {
		s.logger.ErrorContext(ctx, "write connect response: ", err)
		return
	}

	err = bufio.CopyConn(ctx, newStreamConn(stream), targetConn)
	if err != nil && !E.IsClosedOrCanceled(err) {
		s.logger.DebugContext(ctx, "copy TCP stream: ", err)
	}
}

func (s *Service) handleHTTPService(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, service ResolvedService) {
	validationRequest, err := buildMetadataOnlyHTTPRequest(ctx, request)
	if err != nil {
		s.logger.ErrorContext(ctx, "build request for access validation: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	validationRequest = applyOriginRequest(validationRequest, service.OriginRequest)
	if service.OriginRequest.Access.Required {
		validator, err := s.accessCache.Get(service.OriginRequest.Access)
		if err != nil {
			s.logger.ErrorContext(ctx, "create access validator: ", err)
			respWriter.WriteResponse(err, nil)
			return
		}
		err = validator.Validate(validationRequest.Context(), validationRequest)
		if err != nil {
			respWriter.WriteResponse(nil, encodeResponseHeaders(http.StatusForbidden, http.Header{}))
			return
		}
	}

	switch service.Kind {
	case ResolvedServiceStatus:
		err = respWriter.WriteResponse(nil, encodeResponseHeaders(service.StatusCode, http.Header{}))
		if err != nil {
			s.logger.ErrorContext(ctx, "write status service response: ", err)
		}
		return
	case ResolvedServiceHTTP:
		destination := service.Destination
		if request.Type == ConnectionTypeHTTP {
			s.handleHTTPStream(ctx, stream, respWriter, request, destination, service)
		} else {
			s.handleWebSocketStream(ctx, stream, respWriter, request, destination, service)
		}
	case ResolvedServiceStream:
		if request.Type != ConnectionTypeWebsocket {
			err = E.New("stream service requires websocket request type")
			s.logger.ErrorContext(ctx, err)
			respWriter.WriteResponse(err, nil)
			return
		}
		s.handleStreamService(ctx, stream, respWriter, request, service)
	case ResolvedServiceUnix, ResolvedServiceUnixTLS:
		if request.Type == ConnectionTypeHTTP {
			s.handleDirectHTTPStream(ctx, stream, respWriter, request, service)
		} else {
			s.handleDirectWebSocketStream(ctx, stream, respWriter, request, service)
		}
	case ResolvedServiceBastion:
		if request.Type != ConnectionTypeWebsocket {
			err = E.New("bastion service requires websocket request type")
			s.logger.ErrorContext(ctx, err)
			respWriter.WriteResponse(err, nil)
			return
		}
		s.handleBastionStream(ctx, stream, respWriter, request, service)
	case ResolvedServiceSocksProxy:
		if request.Type != ConnectionTypeWebsocket {
			err = E.New("socks-proxy service requires websocket request type")
			s.logger.ErrorContext(ctx, err)
			respWriter.WriteResponse(err, nil)
			return
		}
		s.handleSocksProxyStream(ctx, stream, respWriter, request, service)
	default:
		err = E.New("unsupported service kind for HTTP/WebSocket request")
		s.logger.ErrorContext(ctx, err)
		respWriter.WriteResponse(err, nil)
	}
}

func (s *Service) handleHTTPStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, destination M.Socksaddr, service ResolvedService) {
	s.logger.InfoContext(ctx, "inbound HTTP connection to ", destination)

	transport, cleanup, err := s.newRouterOriginTransport(ctx, destination, service.OriginRequest, request.MetadataMap()[metadataHTTPHost])
	if err != nil {
		s.logger.ErrorContext(ctx, "build origin transport: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer cleanup()
	s.roundTripHTTP(ctx, stream, respWriter, request, service, transport)
}

func (s *Service) handleWebSocketStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, destination M.Socksaddr, service ResolvedService) {
	s.logger.InfoContext(ctx, "inbound WebSocket connection to ", destination)

	transport, cleanup, err := s.newRouterOriginTransport(ctx, destination, service.OriginRequest, request.MetadataMap()[metadataHTTPHost])
	if err != nil {
		s.logger.ErrorContext(ctx, "build origin transport: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer cleanup()
	s.roundTripHTTP(ctx, stream, respWriter, request, service, transport)
}

func (s *Service) handleDirectHTTPStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, service ResolvedService) {
	s.logger.InfoContext(ctx, "inbound HTTP connection to ", request.Dest)

	transport, cleanup, err := s.newDirectOriginTransport(service, request.MetadataMap()[metadataHTTPHost])
	if err != nil {
		s.logger.ErrorContext(ctx, "build direct origin transport: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer cleanup()
	s.roundTripHTTP(ctx, stream, respWriter, request, service, transport)
}

func (s *Service) handleDirectWebSocketStream(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, service ResolvedService) {
	s.logger.InfoContext(ctx, "inbound WebSocket connection to ", request.Dest)

	transport, cleanup, err := s.newDirectOriginTransport(service, request.MetadataMap()[metadataHTTPHost])
	if err != nil {
		s.logger.ErrorContext(ctx, "build direct origin transport: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer cleanup()
	s.roundTripHTTP(ctx, stream, respWriter, request, service, transport)
}

func (s *Service) roundTripHTTP(ctx context.Context, stream io.ReadWriteCloser, respWriter ConnectResponseWriter, request *ConnectRequest, service ResolvedService, transport *http.Transport) {
	httpRequest, err := buildHTTPRequestFromMetadata(ctx, request, stream)
	if err != nil {
		s.logger.ErrorContext(ctx, "build HTTP request: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}

	httpRequest = normalizeOriginRequest(request.Type, httpRequest, service.OriginRequest)
	requestCtx := httpRequest.Context()
	if service.OriginRequest.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		requestCtx, cancel = context.WithTimeout(requestCtx, service.OriginRequest.ConnectTimeout)
		defer cancel()
		httpRequest = httpRequest.WithContext(requestCtx)
	}

	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	response, err := httpClient.Do(httpRequest)
	if err != nil {
		s.logger.ErrorContext(ctx, "origin request: ", err)
		respWriter.WriteResponse(err, nil)
		return
	}
	defer response.Body.Close()

	responseMetadata := encodeResponseHeaders(response.StatusCode, response.Header)
	err = respWriter.WriteResponse(nil, responseMetadata)
	if err != nil {
		s.logger.ErrorContext(ctx, "write origin response headers: ", err)
		return
	}

	if request.Type == ConnectionTypeWebsocket && response.StatusCode == http.StatusSwitchingProtocols {
		rwc, ok := response.Body.(io.ReadWriteCloser)
		if !ok {
			s.logger.ErrorContext(ctx, "websocket origin response body is not duplex")
			return
		}
		bidirectionalCopy(stream, rwc)
		return
	}

	_, err = io.Copy(stream, response.Body)
	if err != nil && !E.IsClosedOrCanceled(err) {
		s.logger.DebugContext(ctx, "copy HTTP response body: ", err)
	}
	if trailerWriter, ok := respWriter.(connectResponseTrailerWriter); ok {
		for name, values := range response.Trailer {
			for _, value := range values {
				trailerWriter.AddTrailer(name, value)
			}
		}
	}
}

func (s *Service) newRouterOriginTransport(ctx context.Context, destination M.Socksaddr, originRequest OriginRequestConfig, requestHost string) (*http.Transport, func(), error) {
	tlsConfig, err := newOriginTLSConfig(originRequest, effectiveOriginHost(originRequest, requestHost))
	if err != nil {
		return nil, nil, err
	}
	input, cleanup, _ := s.dialRouterTCPWithMetadata(ctx, destination, routedPipeTCPOptions{})

	transport := &http.Transport{
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     originRequest.HTTP2Origin,
		TLSHandshakeTimeout:   originRequest.TLSTimeout,
		IdleConnTimeout:       originRequest.KeepAliveTimeout,
		MaxIdleConns:          originRequest.KeepAliveConnections,
		MaxIdleConnsPerHost:   originRequest.KeepAliveConnections,
		Proxy:                 proxyFromEnvironment,
		TLSClientConfig:       tlsConfig,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return input, nil
		},
	}
	return transport, cleanup, nil
}

func (s *Service) newDirectOriginTransport(service ResolvedService, requestHost string) (*http.Transport, func(), error) {
	cacheKey, err := directOriginTransportKey(service, requestHost)
	if err != nil {
		return nil, nil, E.Cause(err, "marshal direct origin transport key")
	}

	s.directTransportAccess.Lock()
	if s.directTransports == nil {
		s.directTransports = make(map[string]*http.Transport)
	}
	if transport, exists := s.directTransports[cacheKey]; exists {
		s.directTransportAccess.Unlock()
		return transport, func() {}, nil
	}
	s.directTransportAccess.Unlock()

	dialer := &net.Dialer{
		Timeout:   service.OriginRequest.ConnectTimeout,
		KeepAlive: service.OriginRequest.TCPKeepAlive,
	}
	if service.OriginRequest.NoHappyEyeballs {
		dialer.FallbackDelay = -1
	}
	tlsConfig, err := newOriginTLSConfig(service.OriginRequest, effectiveOriginHost(service.OriginRequest, requestHost))
	if err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     service.OriginRequest.HTTP2Origin,
		TLSHandshakeTimeout:   service.OriginRequest.TLSTimeout,
		IdleConnTimeout:       service.OriginRequest.KeepAliveTimeout,
		MaxIdleConns:          service.OriginRequest.KeepAliveConnections,
		MaxIdleConnsPerHost:   service.OriginRequest.KeepAliveConnections,
		Proxy:                 proxyFromEnvironment,
		TLSClientConfig:       tlsConfig,
	}
	switch service.Kind {
	case ResolvedServiceUnix, ResolvedServiceUnixTLS:
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", service.UnixPath)
		}
	default:
		return nil, nil, E.New("unsupported direct origin service")
	}

	s.directTransportAccess.Lock()
	if s.directTransports == nil {
		s.directTransports = make(map[string]*http.Transport)
	}
	if cached, exists := s.directTransports[cacheKey]; exists {
		s.directTransportAccess.Unlock()
		transport.CloseIdleConnections()
		return cached, func() {}, nil
	}
	s.directTransports[cacheKey] = transport
	s.directTransportAccess.Unlock()
	return transport, func() {}, nil
}

type directOriginTransportCacheKey struct {
	Kind        ResolvedServiceKind `json:"kind"`
	UnixPath    string              `json:"unix_path,omitempty"`
	RequestHost string              `json:"request_host,omitempty"`
	Origin      OriginRequestConfig `json:"origin"`
}

func directOriginTransportKey(service ResolvedService, requestHost string) (string, error) {
	key := directOriginTransportCacheKey{
		Kind:        service.Kind,
		UnixPath:    service.UnixPath,
		RequestHost: effectiveOriginHost(service.OriginRequest, requestHost),
		Origin:      service.OriginRequest,
	}
	data, err := json.Marshal(key)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func effectiveOriginHost(originRequest OriginRequestConfig, requestHost string) string {
	if originRequest.HTTPHostHeader != "" {
		return originRequest.HTTPHostHeader
	}
	return requestHost
}

func newOriginTLSConfig(originRequest OriginRequestConfig, requestHost string) (*tls.Config, error) {
	rootCAs, err := loadOriginCABasePool()
	if err != nil {
		return nil, E.Cause(err, "load origin root CAs")
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: originRequest.NoTLSVerify, //nolint:gosec
		ServerName:         originTLSServerName(originRequest, requestHost),
		RootCAs:            rootCAs,
	}
	if originRequest.CAPool == "" {
		return tlsConfig, nil
	}
	pemData, err := readOriginCAFile(originRequest.CAPool)
	if err != nil {
		return nil, E.Cause(err, "read origin ca pool")
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(pemData) {
		return nil, E.New("parse origin ca pool")
	}
	return tlsConfig, nil
}

func originTLSServerName(originRequest OriginRequestConfig, requestHost string) string {
	if originRequest.OriginServerName != "" {
		return originRequest.OriginServerName
	}
	if !originRequest.MatchSNIToHost {
		return ""
	}
	host, _, err := net.SplitHostPort(requestHost)
	if err == nil {
		return host
	}
	return requestHost
}

func applyOriginRequest(request *http.Request, originRequest OriginRequestConfig) *http.Request {
	request = request.Clone(request.Context())
	if originRequest.HTTPHostHeader != "" {
		request.Header.Set("X-Forwarded-Host", request.Host)
		request.Host = originRequest.HTTPHostHeader
	}
	return request
}

func normalizeOriginRequest(connectType ConnectionType, request *http.Request, originRequest OriginRequestConfig) *http.Request {
	request = applyOriginRequest(request, originRequest)

	switch connectType {
	case ConnectionTypeWebsocket:
		request.Header.Set("Connection", "Upgrade")
		request.Header.Set("Upgrade", "websocket")
		request.Header.Set("Sec-Websocket-Version", "13")
		request.ContentLength = 0
		request.Body = nil
	default:
		if originRequest.DisableChunkedEncoding {
			request.TransferEncoding = []string{"gzip", "deflate"}
			contentLength, err := strconv.ParseInt(request.Header.Get("Content-Length"), 10, 64)
			if err == nil {
				request.ContentLength = contentLength
			}
		}
		request.Header.Set("Connection", "keep-alive")
	}

	if _, exists := request.Header["User-Agent"]; !exists {
		request.Header.Set("User-Agent", "")
	}

	return request
}

func buildMetadataOnlyHTTPRequest(ctx context.Context, connectRequest *ConnectRequest) (*http.Request, error) {
	return buildHTTPRequestFromMetadata(ctx, &ConnectRequest{
		Dest:     connectRequest.Dest,
		Type:     connectRequest.Type,
		Metadata: append([]Metadata(nil), connectRequest.Metadata...),
	}, http.NoBody)
}

func bidirectionalCopy(left, right io.ReadWriteCloser) {
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			common.Close(left, right)
		})
	}

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(left, right)
		closeBoth()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(right, left)
		closeBoth()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func buildHTTPRequestFromMetadata(ctx context.Context, connectRequest *ConnectRequest, body io.Reader) (*http.Request, error) {
	metadataMap := connectRequest.MetadataMap()
	method := metadataMap[metadataHTTPMethod]
	host := metadataMap[metadataHTTPHost]

	request, err := http.NewRequestWithContext(ctx, method, connectRequest.Dest, body)
	if err != nil {
		return nil, E.Cause(err, "create HTTP request")
	}
	request.Host = host

	for _, entry := range connectRequest.Metadata {
		if !strings.Contains(entry.Key, metadataHTTPHeader) {
			continue
		}
		parts := strings.SplitN(entry.Key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		request.Header.Add(parts[1], entry.Val)
	}

	contentLengthStr := request.Header.Get("Content-Length")
	if contentLengthStr != "" {
		request.ContentLength, err = strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return nil, E.Cause(err, "parse content-length")
		}
	}

	if connectRequest.Type != ConnectionTypeWebsocket && !isTransferEncodingChunked(request) && request.ContentLength == 0 {
		request.Body = http.NoBody
	}

	request.Header.Del("Cf-Cloudflared-Proxy-Connection-Upgrade")

	return request, nil
}

func isTransferEncodingChunked(request *http.Request) bool {
	for _, encoding := range request.TransferEncoding {
		if strings.Contains(strings.ToLower(encoding), "chunked") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(request.Header.Get("Transfer-Encoding")), "chunked")
}

func encodeResponseHeaders(statusCode int, header http.Header) []Metadata {
	metadata := make([]Metadata, 0, len(header)+1)
	metadata = append(metadata, Metadata{
		Key: metadataHTTPStatus,
		Val: strconv.Itoa(statusCode),
	})
	for name, values := range header {
		for _, value := range values {
			metadata = append(metadata, Metadata{
				Key: metadataHTTPHeader + ":" + name,
				Val: value,
			})
		}
	}
	return metadata
}

type streamConn struct {
	io.ReadWriteCloser
}

func newStreamConn(stream io.ReadWriteCloser) *streamConn {
	return &streamConn{ReadWriteCloser: stream}
}

func (c *streamConn) LocalAddr() net.Addr                { return nil }
func (c *streamConn) RemoteAddr() net.Addr               { return nil }
func (c *streamConn) SetDeadline(_ time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(_ time.Time) error { return nil }

type datagramVersionedSender interface {
	DatagramVersion() string
}

func datagramVersionForSender(sender DatagramSender) string {
	versioned, ok := sender.(datagramVersionedSender)
	if !ok {
		return defaultDatagramVersion
	}
	version := versioned.DatagramVersion()
	if version == "" {
		return defaultDatagramVersion
	}
	return version
}
