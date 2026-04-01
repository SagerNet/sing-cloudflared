package cloudflared

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-cloudflared/tunnelrpc"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
	"zombiezen.com/go/capnproto2/rpc"
	"zombiezen.com/go/capnproto2/server"
)

// V2 wire format: [payload | 16B sessionID | 1B type] (suffix-based)

type DatagramV2Type byte

const (
	DatagramV2TypeUDP         DatagramV2Type = 0
	DatagramV2TypeIP          DatagramV2Type = 1
	DatagramV2TypeIPWithTrace DatagramV2Type = 2
	DatagramV2TypeTracingSpan DatagramV2Type = 3

	sessionIDLength = 16
	typeIDLength    = 1
)

type DatagramV2Muxer struct {
	service *Service
	logger  logger.ContextLogger
	sender  DatagramSender
	icmp    *ICMPBridge

	sessionAccess sync.RWMutex
	sessions      map[uuid.UUID]*udpSession
}

func NewDatagramV2Muxer(service *Service, sender DatagramSender, log logger.ContextLogger) *DatagramV2Muxer {
	return &DatagramV2Muxer{
		service:  service,
		logger:   log,
		sender:   sender,
		icmp:     NewICMPBridge(service, sender, icmpWireV2),
		sessions: make(map[uuid.UUID]*udpSession),
	}
}

type rpcStreamOpener interface {
	OpenRPCStream(ctx context.Context) (io.ReadWriteCloser, error)
}

type v2SessionRPCClient interface {
	UnregisterSession(ctx context.Context, sessionID uuid.UUID, message string) error
	Close() error
}

var newV2SessionRPCClient = func(ctx context.Context, sender DatagramSender) (v2SessionRPCClient, error) {
	opener, ok := sender.(rpcStreamOpener)
	if !ok {
		return nil, E.New("sender does not support rpc streams")
	}
	stream, err := opener.OpenRPCStream(ctx)
	if err != nil {
		return nil, err
	}
	transport := safeTransport(stream)
	conn := newRPCClientConn(transport)
	return &capnpV2SessionRPCClient{
		client:    tunnelrpc.SessionManager{Client: conn.Bootstrap(ctx)},
		rpcConn:   conn,
		transport: transport,
	}, nil
}

type capnpV2SessionRPCClient struct {
	client    tunnelrpc.SessionManager
	rpcConn   *rpc.Conn
	transport rpc.Transport
}

func (c *capnpV2SessionRPCClient) UnregisterSession(ctx context.Context, sessionID uuid.UUID, message string) error {
	promise := c.client.UnregisterUdpSession(ctx, func(p tunnelrpc.SessionManager_unregisterUdpSession_Params) error {
		err := p.SetSessionId(sessionID[:])
		if err != nil {
			return err
		}
		return p.SetMessage(message)
	})
	_, err := promise.Struct()
	return err
}

func (c *capnpV2SessionRPCClient) Close() error {
	return E.Errors(c.rpcConn.Close(), c.transport.Close())
}

func (m *DatagramV2Muxer) HandleDatagram(ctx context.Context, data []byte) {
	if len(data) < typeIDLength {
		return
	}

	datagramType := DatagramV2Type(data[len(data)-typeIDLength])
	payload := data[:len(data)-typeIDLength]

	switch datagramType {
	case DatagramV2TypeUDP:
		m.handleUDPDatagram(ctx, payload)
	case DatagramV2TypeIP:
		err := m.icmp.HandleV2(ctx, datagramType, payload)
		if err != nil {
			m.logger.Debug("drop V2 ICMP datagram: ", err)
		}
	case DatagramV2TypeIPWithTrace:
		err := m.icmp.HandleV2(ctx, datagramType, payload)
		if err != nil {
			m.logger.Debug("drop V2 traced ICMP datagram: ", err)
		}
	case DatagramV2TypeTracingSpan:
		// Tracing spans, ignore
	}
}

func (m *DatagramV2Muxer) handleUDPDatagram(ctx context.Context, data []byte) {
	if len(data) < sessionIDLength {
		return
	}

	payload := data[:len(data)-sessionIDLength]
	sessionID, err := uuid.FromBytes(data[len(data)-sessionIDLength:])
	if err != nil {
		m.logger.Debug("invalid session ID in V2 datagram: ", err)
		return
	}

	m.sessionAccess.RLock()
	session, exists := m.sessions[sessionID]
	m.sessionAccess.RUnlock()

	if !exists {
		m.logger.Debug("unknown V2 UDP session: ", sessionID)
		return
	}

	session.writeToOrigin(payload)
}

func (m *DatagramV2Muxer) RegisterSession(
	ctx context.Context,
	sessionID uuid.UUID,
	destinationIP net.IP,
	destinationPort uint16,
	closeAfterIdle time.Duration,
) error {
	if destinationIP == nil {
		return E.New("missing destination IP")
	}
	var destinationAddr netip.Addr
	if ip4 := destinationIP.To4(); ip4 != nil {
		destinationAddr = netip.AddrFrom4([4]byte(ip4))
	} else if ip16 := destinationIP.To16(); ip16 != nil {
		destinationAddr = netip.AddrFrom16([16]byte(ip16))
	} else {
		return E.New("invalid destination IP")
	}
	destination := netip.AddrPortFrom(destinationAddr, destinationPort)

	if closeAfterIdle == 0 {
		closeAfterIdle = 210 * time.Second
	}

	m.sessionAccess.Lock()
	if _, exists := m.sessions[sessionID]; exists {
		m.sessionAccess.Unlock()
		return nil
	}
	limit := m.service.maxActiveFlows()
	if !m.service.flowLimiter.Acquire(limit) {
		m.sessionAccess.Unlock()
		return E.New("too many active flows")
	}

	origin, err := m.service.dialWarpPacketConnection(ctx, destination)
	if err != nil {
		m.service.flowLimiter.Release(limit)
		m.sessionAccess.Unlock()
		return err
	}

	session := newUDPSession(sessionID, destination, closeAfterIdle, origin, m)
	m.sessions[sessionID] = session
	m.sessionAccess.Unlock()

	m.logger.Info("registered V2 UDP session ", sessionID, " to ", destination)

	go m.serveSession(ctx, session, limit)
	return nil
}

func (m *DatagramV2Muxer) UnregisterSession(sessionID uuid.UUID, message string) {
	m.sessionAccess.Lock()
	session, exists := m.sessions[sessionID]
	if exists {
		delete(m.sessions, sessionID)
	}
	m.sessionAccess.Unlock()

	if exists {
		session.markRemoteClosed(message)
		session.close()
		m.logger.Info("unregistered V2 UDP session ", sessionID)
	}
}

func (m *DatagramV2Muxer) serveSession(ctx context.Context, session *udpSession, limit uint64) {
	defer m.service.flowLimiter.Release(limit)

	session.serve(ctx)

	m.sessionAccess.Lock()
	if current, exists := m.sessions[session.id]; exists && current == session {
		delete(m.sessions, session.id)
	}
	m.sessionAccess.Unlock()

	if !session.remoteClosed() {
		unregisterCtx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
		defer cancel()
		err := m.unregisterRemoteSession(unregisterCtx, session.id, session.closeReason())
		if err != nil {
			m.logger.Debug("failed to unregister V2 UDP session ", session.id, ": ", err)
		}
	}
}

func (m *DatagramV2Muxer) sendToEdge(sessionID uuid.UUID, payload []byte) {
	data := make([]byte, len(payload)+sessionIDLength+typeIDLength)
	copy(data, payload)
	copy(data[len(payload):], sessionID[:])
	data[len(data)-1] = byte(DatagramV2TypeUDP)
	m.sender.SendDatagram(data)
}

func (m *DatagramV2Muxer) Close() {
	m.sessionAccess.Lock()
	sessions := m.sessions
	m.sessions = make(map[uuid.UUID]*udpSession)
	m.sessionAccess.Unlock()

	for _, session := range sessions {
		session.close()
	}
}

type udpSession struct {
	id             uuid.UUID
	destination    netip.AddrPort
	closeAfterIdle time.Duration
	origin         N.PacketConn
	muxer          *DatagramV2Muxer

	writeChan chan []byte
	closeOnce sync.Once
	closeChan chan struct{}

	activeAccess sync.RWMutex
	activeAt     time.Time

	stateAccess       sync.RWMutex
	closedByRemote    bool
	closeReasonString string
}

func newUDPSession(id uuid.UUID, destination netip.AddrPort, closeAfterIdle time.Duration, origin N.PacketConn, muxer *DatagramV2Muxer) *udpSession {
	return &udpSession{
		id:             id,
		destination:    destination,
		closeAfterIdle: closeAfterIdle,
		origin:         origin,
		muxer:          muxer,
		writeChan:      make(chan []byte, 256),
		closeChan:      make(chan struct{}),
		activeAt:       time.Now(),
	}
}

func (s *udpSession) writeToOrigin(payload []byte) {
	data := make([]byte, len(payload))
	copy(data, payload)
	select {
	case s.writeChan <- data:
	default:
	}
}

func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		if s.origin != nil {
			_ = s.origin.Close()
		}
		close(s.closeChan)
	})
}

func (s *udpSession) serve(ctx context.Context) {
	go s.readLoop()
	go s.writeLoop()

	tickInterval := s.closeAfterIdle / 2
	if tickInterval <= 0 || tickInterval > 10*time.Second {
		tickInterval = time.Second
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.closeWithReason("connection closed")
		case <-ticker.C:
			if time.Since(s.lastActive()) >= s.closeAfterIdle {
				s.closeWithReason("idle timeout")
			}
		case <-s.closeChan:
			return
		}
	}
}

func (s *udpSession) readLoop() {
	for {
		buffer := buf.NewPacket()
		_, err := s.origin.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			s.closeWithReason(err.Error())
			return
		}
		s.markActive()
		s.muxer.sendToEdge(s.id, buffer.Bytes())
		buffer.Release()
	}
}

func (s *udpSession) writeLoop() {
	for {
		select {
		case payload := <-s.writeChan:
			err := s.origin.WritePacket(buf.As(payload), M.SocksaddrFromNetIP(s.destination))
			if err != nil {
				s.closeWithReason(err.Error())
				return
			}
			s.markActive()
		case <-s.closeChan:
			return
		}
	}
}

func (s *udpSession) markActive() {
	s.activeAccess.Lock()
	s.activeAt = time.Now()
	s.activeAccess.Unlock()
}

func (s *udpSession) lastActive() time.Time {
	s.activeAccess.RLock()
	defer s.activeAccess.RUnlock()
	return s.activeAt
}

func (s *udpSession) closeWithReason(reason string) {
	s.stateAccess.Lock()
	if s.closeReasonString == "" {
		s.closeReasonString = reason
	}
	s.stateAccess.Unlock()
	s.close()
}

func (s *udpSession) markRemoteClosed(message string) {
	s.stateAccess.Lock()
	s.closedByRemote = true
	if message != "" {
		s.closeReasonString = message
	} else if s.closeReasonString == "" {
		s.closeReasonString = "unregistered by edge"
	}
	s.stateAccess.Unlock()
}

func (s *udpSession) remoteClosed() bool {
	s.stateAccess.RLock()
	defer s.stateAccess.RUnlock()
	return s.closedByRemote
}

func (s *udpSession) closeReason() string {
	s.stateAccess.RLock()
	defer s.stateAccess.RUnlock()
	if s.closeReasonString == "" {
		return "session closed"
	}
	return s.closeReasonString
}

func (s *udpSession) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case data := <-s.writeChan:
		_, err := buffer.Write(data)
		return M.SocksaddrFromNetIP(s.destination), err
	case <-s.closeChan:
		return M.Socksaddr{}, io.EOF
	}
}

func (s *udpSession) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	s.muxer.sendToEdge(s.id, buffer.Bytes())
	return nil
}

func (s *udpSession) Close() error {
	s.close()
	return nil
}

func (s *udpSession) LocalAddr() net.Addr                { return nil }
func (s *udpSession) SetDeadline(_ time.Time) error      { return nil }
func (s *udpSession) SetReadDeadline(_ time.Time) error  { return nil }
func (s *udpSession) SetWriteDeadline(_ time.Time) error { return nil }

func (m *DatagramV2Muxer) unregisterRemoteSession(ctx context.Context, sessionID uuid.UUID, message string) error {
	client, err := newV2SessionRPCClient(ctx, m.sender)
	if err != nil {
		return err
	}
	defer client.Close()
	return client.UnregisterSession(ctx, sessionID, message)
}

type cloudflaredServer struct {
	service *Service
	muxer   *DatagramV2Muxer
	ctx     context.Context
	logger  logger.ContextLogger
}

func (s *cloudflaredServer) RegisterUdpSession(call tunnelrpc.SessionManager_registerUdpSession) error {
	server.Ack(call.Options)
	sessionIDBytes, err := call.Params.SessionId()
	if err != nil {
		return err
	}
	sessionID, err := uuid.FromBytes(sessionIDBytes)
	if err != nil {
		return err
	}

	destinationIP, err := call.Params.DstIp()
	if err != nil {
		return err
	}

	destinationPort := call.Params.DstPort()
	closeAfterIdle := time.Duration(call.Params.CloseAfterIdleHint())
	if _, traceErr := call.Params.TraceContext(); traceErr != nil {
		return traceErr
	}

	if len(destinationIP) == 0 {
		err = E.New("missing destination IP")
	} else {
		err = s.muxer.RegisterSession(s.ctx, sessionID, net.IP(destinationIP), destinationPort, closeAfterIdle)
	}

	result, allocErr := call.Results.NewResult()
	if allocErr != nil {
		return allocErr
	}
	spansErr := result.SetSpans([]byte{})
	if spansErr != nil {
		return spansErr
	}
	if err != nil {
		result.SetErr(err.Error())
	}
	return nil
}

func (s *cloudflaredServer) UnregisterUdpSession(call tunnelrpc.SessionManager_unregisterUdpSession) error {
	server.Ack(call.Options)
	sessionIDBytes, err := call.Params.SessionId()
	if err != nil {
		return err
	}
	sessionID, err := uuid.FromBytes(sessionIDBytes)
	if err != nil {
		return err
	}

	message, err := call.Params.Message()
	if err != nil {
		return err
	}

	s.muxer.UnregisterSession(sessionID, message)
	return nil
}

func (s *cloudflaredServer) UpdateConfiguration(call tunnelrpc.ConfigurationManager_updateConfiguration) error {
	return handleUpdateConfiguration(s.service, call)
}

func ServeRPCStream(ctx context.Context, stream io.ReadWriteCloser, service *Service, muxer *DatagramV2Muxer, log logger.ContextLogger) {
	srv := &cloudflaredServer{
		service: service,
		muxer:   muxer,
		ctx:     ctx,
		logger:  log,
	}
	client := tunnelrpc.CloudflaredServer_ServerToClient(srv)
	serveRPCConn(ctx, stream, client.Client)
}
