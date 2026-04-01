package cloudflared

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// V3 wire format: [1B type | payload] (prefix-based)

// DatagramV3Type identifies the type of a V3 datagram.
type DatagramV3Type byte

const (
	DatagramV3TypeRegistration         DatagramV3Type = 0
	DatagramV3TypePayload              DatagramV3Type = 1
	DatagramV3TypeICMP                 DatagramV3Type = 2
	DatagramV3TypeRegistrationResponse DatagramV3Type = 3

	// V3 registration header sizes
	v3RegistrationFlagLen = 1
	v3RegistrationPortLen = 2
	v3RegistrationIdleLen = 2
	v3RequestIDLength     = 16
	v3IPv4AddrLen         = 4
	v3IPv6AddrLen         = 16
	v3RegistrationBaseLen = 1 + v3RegistrationFlagLen + v3RegistrationPortLen + v3RegistrationIdleLen + v3RequestIDLength // 22
	v3PayloadHeaderLen    = 1 + v3RequestIDLength                                                                         // 17
	v3RegistrationRespLen = 1 + 1 + v3RequestIDLength + 2                                                                 // 20
	maxV3UDPPayloadLen    = 1280

	// V3 registration flags
	v3FlagIPv6   byte = 0x01
	v3FlagTraced byte = 0x02
	v3FlagBundle byte = 0x04

	// V3 registration response types
	v3ResponseOK                     byte = 0x00
	v3ResponseDestinationUnreachable byte = 0x01
	v3ResponseUnableToBindSocket     byte = 0x02
	v3ResponseTooManyActiveFlows     byte = 0x03
	v3ResponseErrorWithMsg           byte = 0xFF
)

// RequestID is a 128-bit session identifier for V3.
type RequestID [v3RequestIDLength]byte

type v3RegistrationState uint8

const (
	v3RegistrationNew v3RegistrationState = iota
	v3RegistrationExisting
	v3RegistrationMigrated
)

type DatagramV3SessionManager struct {
	sessionAccess sync.RWMutex
	sessions      map[RequestID]*v3Session
}

func NewDatagramV3SessionManager() *DatagramV3SessionManager {
	return &DatagramV3SessionManager{
		sessions: make(map[RequestID]*v3Session),
	}
}

// DatagramV3Muxer handles V3 datagram demuxing and session management.
type DatagramV3Muxer struct {
	service *Service
	logger  logger.ContextLogger
	sender  DatagramSender
	icmp    *ICMPBridge
}

// NewDatagramV3Muxer creates a new V3 datagram muxer.
func NewDatagramV3Muxer(service *Service, sender DatagramSender, log logger.ContextLogger) *DatagramV3Muxer {
	return &DatagramV3Muxer{
		service: service,
		logger:  log,
		sender:  sender,
		icmp:    NewICMPBridge(service, sender, icmpWireV3),
	}
}

// HandleDatagram demuxes an incoming V3 datagram.
func (m *DatagramV3Muxer) HandleDatagram(ctx context.Context, data []byte) {
	if len(data) < 1 {
		return
	}

	datagramType := DatagramV3Type(data[0])
	payload := data[1:]

	switch datagramType {
	case DatagramV3TypeRegistration:
		m.handleRegistration(ctx, payload)
	case DatagramV3TypePayload:
		m.handlePayload(payload)
	case DatagramV3TypeICMP:
		err := m.icmp.HandleV3(ctx, payload)
		if err != nil {
			m.logger.Debug("drop V3 ICMP datagram: ", err)
		}
	case DatagramV3TypeRegistrationResponse:
		// Unexpected - we never send registrations
		m.logger.Debug("received unexpected V3 registration response")
	}
}

func (m *DatagramV3Muxer) handleRegistration(ctx context.Context, data []byte) {
	if len(data) < v3RegistrationFlagLen+v3RegistrationPortLen+v3RegistrationIdleLen+v3RequestIDLength {
		m.logger.Debug("V3 registration too short")
		return
	}

	flags := data[0]
	destinationPort := binary.BigEndian.Uint16(data[1:3])
	idleDurationSeconds := binary.BigEndian.Uint16(data[3:5])

	var requestID RequestID
	copy(requestID[:], data[5:5+v3RequestIDLength])

	offset := 5 + v3RequestIDLength
	var destination netip.AddrPort

	if flags&v3FlagIPv6 != 0 {
		if len(data) < offset+v3IPv6AddrLen {
			m.sendRegistrationResponse(requestID, v3ResponseErrorWithMsg, "registration too short for IPv6")
			return
		}
		var addr [16]byte
		copy(addr[:], data[offset:offset+v3IPv6AddrLen])
		destination = netip.AddrPortFrom(netip.AddrFrom16(addr), destinationPort)
		offset += v3IPv6AddrLen
	} else {
		if len(data) < offset+v3IPv4AddrLen {
			m.sendRegistrationResponse(requestID, v3ResponseErrorWithMsg, "registration too short for IPv4")
			return
		}
		var addr [4]byte
		copy(addr[:], data[offset:offset+v3IPv4AddrLen])
		destination = netip.AddrPortFrom(netip.AddrFrom4(addr), destinationPort)
		offset += v3IPv4AddrLen
	}

	closeAfterIdle := time.Duration(idleDurationSeconds) * time.Second
	if closeAfterIdle == 0 {
		closeAfterIdle = 210 * time.Second
	}
	if !destination.Addr().IsValid() || destination.Addr().IsUnspecified() || destination.Port() == 0 {
		m.sendRegistrationResponse(requestID, v3ResponseDestinationUnreachable, "")
		return
	}

	session, state, err := m.service.datagramV3Manager.Register(m.service, ctx, requestID, destination, closeAfterIdle, m.sender)
	if err == errTooManyActiveFlows {
		m.sendRegistrationResponse(requestID, v3ResponseTooManyActiveFlows, "")
		return
	}
	if err != nil {
		m.sendRegistrationResponse(requestID, v3ResponseUnableToBindSocket, "")
		return
	}

	if state == v3RegistrationNew {
		m.logger.Info("registered V3 UDP session to ", destination)
	}
	m.sendRegistrationResponse(requestID, v3ResponseOK, "")

	// Handle bundled first payload
	if flags&v3FlagBundle != 0 && len(data) > offset {
		session.writeToOrigin(data[offset:])
	}
}

func (m *DatagramV3Muxer) handlePayload(data []byte) {
	if len(data) < v3RequestIDLength || len(data) > v3RequestIDLength+maxV3UDPPayloadLen {
		return
	}

	var requestID RequestID
	copy(requestID[:], data[:v3RequestIDLength])
	payload := data[v3RequestIDLength:]

	session, exists := m.service.datagramV3Manager.Get(requestID)
	if !exists {
		return
	}

	session.writeToOrigin(payload)
}

func (m *DatagramV3Muxer) sendRegistrationResponse(requestID RequestID, responseType byte, errorMessage string) {
	errorBytes := []byte(errorMessage)
	data := make([]byte, v3RegistrationRespLen+len(errorBytes))
	data[0] = byte(DatagramV3TypeRegistrationResponse)
	data[1] = responseType
	copy(data[2:2+v3RequestIDLength], requestID[:])
	binary.BigEndian.PutUint16(data[2+v3RequestIDLength:], uint16(len(errorBytes)))
	copy(data[v3RegistrationRespLen:], errorBytes)
	m.sender.SendDatagram(data)
}

func (m *DatagramV3Muxer) sendPayload(requestID RequestID, payload []byte) {
	data := make([]byte, v3PayloadHeaderLen+len(payload))
	data[0] = byte(DatagramV3TypePayload)
	copy(data[1:1+v3RequestIDLength], requestID[:])
	copy(data[v3PayloadHeaderLen:], payload)
	m.sender.SendDatagram(data)
}

// Close closes all V3 sessions.
func (m *DatagramV3Muxer) Close() {}

// v3Session represents a V3 UDP session.
type v3Session struct {
	id             RequestID
	destination    netip.AddrPort
	closeAfterIdle time.Duration
	origin         N.PacketConn
	manager        *DatagramV3SessionManager
	service        *Service

	writeChan chan []byte
	closeOnce sync.Once
	closeChan chan struct{}

	activeAccess sync.RWMutex
	activeAt     time.Time

	senderAccess sync.RWMutex
	sender       DatagramSender

	contextAccess sync.RWMutex
	connCtx       context.Context
	contextChan   chan context.Context
}

var errTooManyActiveFlows = E.New("too many active flows")

func (m *DatagramV3SessionManager) Register(
	service *Service,
	ctx context.Context,
	requestID RequestID,
	destination netip.AddrPort,
	closeAfterIdle time.Duration,
	sender DatagramSender,
) (*v3Session, v3RegistrationState, error) {
	m.sessionAccess.Lock()
	if existing, exists := m.sessions[requestID]; exists {
		if existing.sender == sender {
			existing.updateContext(ctx)
			existing.markActive()
			m.sessionAccess.Unlock()
			return existing, v3RegistrationExisting, nil
		}
		existing.migrate(sender, ctx)
		existing.markActive()
		m.sessionAccess.Unlock()
		return existing, v3RegistrationMigrated, nil
	}

	limit := service.maxActiveFlows()
	if !service.flowLimiter.Acquire(limit) {
		m.sessionAccess.Unlock()
		return nil, 0, errTooManyActiveFlows
	}
	origin, err := service.dialWarpPacketConnection(ctx, destination)
	if err != nil {
		service.flowLimiter.Release(limit)
		m.sessionAccess.Unlock()
		return nil, 0, err
	}

	session := &v3Session{
		id:             requestID,
		destination:    destination,
		closeAfterIdle: closeAfterIdle,
		origin:         origin,
		manager:        m,
		service:        service,
		writeChan:      make(chan []byte, 512),
		closeChan:      make(chan struct{}),
		activeAt:       time.Now(),
		sender:         sender,
		connCtx:        ctx,
		contextChan:    make(chan context.Context, 1),
	}
	m.sessions[requestID] = session
	m.sessionAccess.Unlock()

	sessionCtx := ctx
	if sessionCtx == nil {
		sessionCtx = context.Background()
	}
	session.connCtx = sessionCtx
	go session.serve(sessionCtx, limit)
	return session, v3RegistrationNew, nil
}

func (m *DatagramV3SessionManager) Get(requestID RequestID) (*v3Session, bool) {
	m.sessionAccess.RLock()
	defer m.sessionAccess.RUnlock()
	session, exists := m.sessions[requestID]
	return session, exists
}

func (m *DatagramV3SessionManager) remove(session *v3Session) {
	m.sessionAccess.Lock()
	if current, exists := m.sessions[session.id]; exists && current == session {
		delete(m.sessions, session.id)
	}
	m.sessionAccess.Unlock()
}

func (s *v3Session) serve(ctx context.Context, limit uint64) {
	defer s.service.flowLimiter.Release(limit)
	defer s.manager.remove(s)

	go s.readLoop()
	go s.writeLoop()

	connCtx := ctx

	tickInterval := s.closeAfterIdle / 2
	if tickInterval <= 0 || tickInterval > 10*time.Second {
		tickInterval = time.Second
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-connCtx.Done():
			if latestCtx := s.currentContext(); latestCtx != nil && latestCtx != connCtx {
				connCtx = latestCtx
				continue
			}
			s.close()
		case newCtx := <-s.contextChan:
			if newCtx != nil {
				connCtx = newCtx
			}
		case <-ticker.C:
			if time.Since(s.lastActive()) >= s.closeAfterIdle {
				s.close()
			}
		case <-s.closeChan:
			return
		}
	}
}

func (s *v3Session) readLoop() {
	for {
		buffer := buf.NewPacket()
		_, err := s.origin.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			s.close()
			return
		}
		if buffer.Len() > maxV3UDPPayloadLen {
			s.service.logger.Debug("drop oversized V3 UDP payload: ", buffer.Len())
			buffer.Release()
			continue
		}
		s.markActive()
		err = s.senderDatagram(append([]byte(nil), buffer.Bytes()...))
		if err != nil {
			buffer.Release()
			s.close()
			return
		}
		buffer.Release()
	}
}

func (s *v3Session) writeLoop() {
	for {
		select {
		case payload := <-s.writeChan:
			err := s.origin.WritePacket(buf.As(payload), M.SocksaddrFromNetIP(s.destination))
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					s.service.logger.Debug("drop V3 UDP payload due to write deadline exceeded")
					continue
				}
				s.close()
				return
			}
			s.markActive()
		case <-s.closeChan:
			return
		}
	}
}

func (s *v3Session) writeToOrigin(payload []byte) {
	data := make([]byte, len(payload))
	copy(data, payload)
	select {
	case s.writeChan <- data:
	default:
	}
}

func (s *v3Session) senderDatagram(payload []byte) error {
	data := make([]byte, v3PayloadHeaderLen+len(payload))
	data[0] = byte(DatagramV3TypePayload)
	copy(data[1:1+v3RequestIDLength], s.id[:])
	copy(data[v3PayloadHeaderLen:], payload)

	s.senderAccess.RLock()
	sender := s.sender
	s.senderAccess.RUnlock()
	return sender.SendDatagram(data)
}

func (s *v3Session) setSender(sender DatagramSender) {
	s.senderAccess.Lock()
	s.sender = sender
	s.senderAccess.Unlock()
}

func (s *v3Session) updateContext(ctx context.Context) {
	if ctx == nil {
		return
	}
	s.contextAccess.Lock()
	s.connCtx = ctx
	s.contextAccess.Unlock()
	select {
	case s.contextChan <- ctx:
	default:
		select {
		case <-s.contextChan:
		default:
		}
		s.contextChan <- ctx
	}
}

func (s *v3Session) migrate(sender DatagramSender, ctx context.Context) {
	s.setSender(sender)
	s.updateContext(ctx)
}

func (s *v3Session) currentContext() context.Context {
	s.contextAccess.RLock()
	defer s.contextAccess.RUnlock()
	return s.connCtx
}

func (s *v3Session) markActive() {
	s.activeAccess.Lock()
	s.activeAt = time.Now()
	s.activeAccess.Unlock()
}

func (s *v3Session) lastActive() time.Time {
	s.activeAccess.RLock()
	defer s.activeAccess.RUnlock()
	return s.activeAt
}

func (s *v3Session) close() {
	s.closeOnce.Do(func() {
		if s.origin != nil {
			_ = s.origin.Close()
		}
		close(s.closeChan)
	})
}
