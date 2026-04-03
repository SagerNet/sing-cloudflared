package datagram

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-cloudflared/internal/icmp"
	"github.com/sagernet/sing-cloudflared/internal/icmptest"
	"github.com/sagernet/sing-cloudflared/internal/protocol"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

type captureDatagramSender struct {
	sent [][]byte
}

func (s *captureDatagramSender) SendDatagram(data []byte) error {
	s.sent = append(s.sent, append([]byte(nil), data...))
	return nil
}

type noopPacketConn struct{}

func (noopPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.EOF
}

func (noopPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}
func (noopPacketConn) Close() error                     { return nil }
func (noopPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (noopPacketConn) SetDeadline(time.Time) error      { return nil }
func (noopPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (noopPacketConn) SetWriteDeadline(time.Time) error { return nil }

func uuidTest(last byte) uuid.UUID {
	var value uuid.UUID
	value[15] = last
	return value
}

func testMuxerContext(t *testing.T, limit uint64) MuxerContext {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return MuxerContext{
		Context: ctx,
		Logger:  logger.NOP(),
		MaxActiveFlows: func() uint64 {
			return limit
		},
		FlowLimiter: &FlowLimiter{},
		DialPacket: func(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
			return noopPacketConn{}, nil
		},
	}
}

func TestDatagramV2SendToEdgeEncodesSessionSuffix(t *testing.T) {
	t.Parallel()

	sender := &captureDatagramSender{}
	muxer := &DatagramV2Muxer{sender: sender}
	sessionID := uuidTest(9)
	muxer.sendToEdge(sessionID, []byte("hello"))

	if len(sender.sent) != 1 {
		t.Fatalf("unexpected sent datagrams %#v", sender.sent)
	}
	data := sender.sent[0]
	if string(data[:5]) != "hello" {
		t.Fatalf("unexpected payload %x", data)
	}
	gotID, err := uuid.FromBytes(data[5 : 5+SessionIDLength])
	if err != nil || gotID != sessionID {
		t.Fatalf("unexpected encoded session id %x err=%v", data, err)
	}
	if data[len(data)-1] != byte(protocol.DatagramV2TypeUDP) {
		t.Fatalf("unexpected datagram type %d", data[len(data)-1])
	}
}

func TestDatagramV2HandleUDPDatagramRoutesToSession(t *testing.T) {
	t.Parallel()

	sessionID := uuidTest(10)
	session := NewUDPSession(sessionID, netip.MustParseAddrPort("127.0.0.1:53"), time.Second, noopPacketConn{}, nil)
	muxer := &DatagramV2Muxer{sessions: map[uuid.UUID]*UDPSession{sessionID: session}}

	payload := []byte("payload")
	data := append(append([]byte(nil), payload...), sessionID[:]...)
	muxer.handleUDPDatagram(context.Background(), data)

	select {
	case queued := <-session.writeChan:
		if string(queued) != "payload" {
			t.Fatalf("unexpected queued payload %q", queued)
		}
	case <-time.After(time.Second):
		t.Fatal("expected payload to be queued to session")
	}
}

func TestDatagramV2HandleUDPDatagramDropsShortAndUnknownSessions(t *testing.T) {
	t.Parallel()

	muxer := &DatagramV2Muxer{
		logger:   logger.NOP(),
		sessions: make(map[uuid.UUID]*UDPSession),
	}

	muxer.handleUDPDatagram(context.Background(), []byte("short"))
	unknownSessionID := uuidTest(44)
	unknownSessionPayload := append([]byte("payload"), unknownSessionID[:]...)
	muxer.handleUDPDatagram(context.Background(), unknownSessionPayload)
}

func TestDatagramV2HandleDatagramDispatchesByType(t *testing.T) {
	t.Parallel()

	sessionID := uuidTest(13)
	session := NewUDPSession(sessionID, netip.MustParseAddrPort("127.0.0.1:53"), time.Second, noopPacketConn{}, nil)
	sender := &captureDatagramSender{}
	muxerCtx := testMuxerContext(t, 0)
	muxer := NewDatagramV2Muxer(muxerCtx, sender, logger.NOP())
	muxer.sessions[sessionID] = session
	muxer.icmp = icmp.NewBridge(muxerCtx.Context, &replyICMPHandler{reply: buildEchoReply}, sender, icmp.WireV2, logger.NOP())

	udpPayload := append([]byte("udp"), sessionID[:]...)
	udpPayload = append(udpPayload, byte(protocol.DatagramV2TypeUDP))
	muxer.HandleDatagram(context.Background(), udpPayload)
	select {
	case queued := <-session.writeChan:
		if string(queued) != "udp" {
			t.Fatalf("unexpected queued udp payload %q", queued)
		}
	case <-time.After(time.Second):
		t.Fatal("expected UDP payload to be dispatched")
	}

	icmpPayload := append(icmptest.BuildIPv4ICMPPacket(
		netip.MustParseAddr("198.18.0.2"),
		netip.MustParseAddr("1.1.1.1"),
		header.ICMPv4Echo, 0, 1, 1,
	), byte(protocol.DatagramV2TypeIP))
	muxer.HandleDatagram(context.Background(), icmpPayload)
	if len(sender.sent) != 1 || sender.sent[0][len(sender.sent[0])-1] != byte(protocol.DatagramV2TypeIP) {
		t.Fatalf("unexpected v2 ICMP response %#v", sender.sent)
	}

	traceIdentity := bytes.Repeat([]byte{0x7a}, icmp.TraceIdentityLength)
	tracedPayload := append(icmptest.BuildIPv4ICMPPacket(
		netip.MustParseAddr("198.18.0.3"),
		netip.MustParseAddr("1.1.1.1"),
		header.ICMPv4Echo, 0, 2, 2,
	), traceIdentity...)
	tracedPayload = append(tracedPayload, byte(protocol.DatagramV2TypeIPWithTrace))
	muxer.HandleDatagram(context.Background(), tracedPayload)
	if len(sender.sent) != 2 || sender.sent[1][len(sender.sent[1])-1] != byte(protocol.DatagramV2TypeIP) {
		t.Fatalf("unexpected traced v2 ICMP response %#v", sender.sent)
	}

	muxer.HandleDatagram(context.Background(), []byte{byte(protocol.DatagramV2TypeTracingSpan)})
	muxer.HandleDatagram(context.Background(), []byte{0xff})
	if len(sender.sent) != 2 {
		t.Fatalf("unexpected datagrams after ignored types %#v", sender.sent)
	}
}

func TestUDPSessionPacketConnAdapter(t *testing.T) {
	t.Parallel()

	sender := &captureDatagramSender{}
	muxer := &DatagramV2Muxer{sender: sender}
	session := NewUDPSession(uuidTest(11), netip.MustParseAddrPort("127.0.0.1:53"), time.Second, noopPacketConn{}, muxer)
	session.writeToOrigin([]byte("abc"))

	buffer := buf.New()
	destination, err := session.ReadPacket(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if destination.String() != "127.0.0.1:53" || string(buffer.Bytes()) != "abc" {
		t.Fatalf("unexpected packet read destination=%s payload=%q", destination, buffer.Bytes())
	}
	buffer.Release()

	writeErr := session.WritePacket(buf.As([]byte("def")), destination)
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one sent datagram, got %#v", sender.sent)
	}
}

func TestDatagramV2CloseClearsSessions(t *testing.T) {
	t.Parallel()

	sessionID := uuidTest(12)
	session := NewUDPSession(sessionID, netip.MustParseAddrPort("127.0.0.1:53"), time.Second, noopPacketConn{}, nil)
	muxer := &DatagramV2Muxer{sessions: map[uuid.UUID]*UDPSession{sessionID: session}}
	muxer.Close()

	if len(muxer.sessions) != 0 {
		t.Fatalf("expected sessions to be cleared, got %#v", muxer.sessions)
	}
	select {
	case <-session.closeChan:
	default:
		t.Fatal("expected session to be closed")
	}
}

func TestDatagramV3HandleDatagramPayloadRoutesToSession(t *testing.T) {
	t.Parallel()

	muxerCtx := testMuxerContext(t, 0)
	manager := NewDatagramV3SessionManager()
	requestID := protocol.RequestID{}
	requestID[15] = 2
	session := &V3Session{
		id:        requestID,
		writeChan: make(chan []byte, 1),
		closeChan: make(chan struct{}),
	}
	manager.sessions[requestID] = session
	muxer := NewDatagramV3Muxer(muxerCtx, &captureDatagramSender{}, logger.NOP(), manager)

	payload := append([]byte{byte(protocol.DatagramV3TypePayload)}, requestID[:]...)
	payload = append(payload, []byte("data")...)
	muxer.HandleDatagram(context.Background(), payload)

	select {
	case queued := <-session.writeChan:
		if string(queued) != "data" {
			t.Fatalf("unexpected queued payload %q", queued)
		}
	case <-time.After(time.Second):
		t.Fatal("expected V3 payload to be queued")
	}
}

func TestDatagramV3SendPayloadEncodesRequestID(t *testing.T) {
	t.Parallel()

	sender := &captureDatagramSender{}
	muxer := &DatagramV3Muxer{sender: sender}
	requestID := protocol.RequestID{}
	requestID[15] = 3
	muxer.sendPayload(requestID, []byte("hello"))

	if len(sender.sent) != 1 {
		t.Fatalf("unexpected sent datagrams %#v", sender.sent)
	}
	data := sender.sent[0]
	if data[0] != byte(protocol.DatagramV3TypePayload) {
		t.Fatalf("unexpected datagram type %d", data[0])
	}
	if string(data[1+V3RequestIDLength:]) != "hello" {
		t.Fatalf("unexpected encoded payload %q", data)
	}
}

func TestV3SessionUpdateContextReplacesPendingContext(t *testing.T) {
	t.Parallel()

	session := &V3Session{
		contextChan: make(chan context.Context, 1),
	}
	ctx1 := context.WithValue(context.Background(), "id", 1)
	ctx2 := context.WithValue(context.Background(), "id", 2)
	session.updateContext(ctx1)
	session.updateContext(ctx2)

	select {
	case ctx := <-session.contextChan:
		if ctx.Value("id") != 2 {
			t.Fatalf("expected latest context, got %v", ctx.Value("id"))
		}
	default:
		t.Fatal("expected pending context update")
	}
}

func TestDatagramV3HandleRegistrationErrorDatagram(t *testing.T) {
	t.Parallel()

	muxerCtx := testMuxerContext(t, 0)
	manager := NewDatagramV3SessionManager()
	sender := &captureDatagramSender{}
	muxer := NewDatagramV3Muxer(muxerCtx, sender, logger.NOP(), manager)

	requestID := protocol.RequestID{}
	requestID[15] = 4
	payload := make([]byte, 1+1+2+2+16)
	payload[0] = byte(protocol.DatagramV3TypeRegistration)
	payload[1] = V3FlagIPv6
	binary.BigEndian.PutUint16(payload[2:4], 53)
	binary.BigEndian.PutUint16(payload[4:6], 30)
	copy(payload[6:22], requestID[:])
	muxer.HandleDatagram(context.Background(), payload)

	if len(sender.sent) != 1 {
		t.Fatalf("expected one registration error response, got %#v", sender.sent)
	}
	if sender.sent[0][1] != V3ResponseErrorWithMsg {
		t.Fatalf("unexpected registration response %x", sender.sent[0])
	}
}

func TestDatagramV3HandleRegistrationValidationErrors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		payload      []byte
		responseType byte
	}{
		{
			name:         "short IPv4 body",
			payload:      append([]byte{byte(protocol.DatagramV3TypeRegistration)}, make([]byte, V3RegistrationFlagLen+V3RegistrationPortLen+V3RegistrationIdleLen+V3RequestIDLength+V3IPv4AddrLen-1)...),
			responseType: V3ResponseErrorWithMsg,
		},
		{
			name: "unspecified IPv6 destination",
			payload: func() []byte {
				requestID := protocol.RequestID{}
				requestID[15] = 5
				payload := make([]byte, 1+V3RegistrationFlagLen+V3RegistrationPortLen+V3RegistrationIdleLen+V3RequestIDLength+V3IPv6AddrLen)
				payload[0] = byte(protocol.DatagramV3TypeRegistration)
				payload[1] = V3FlagIPv6
				binary.BigEndian.PutUint16(payload[2:4], 53)
				binary.BigEndian.PutUint16(payload[4:6], 30)
				copy(payload[6:22], requestID[:])
				return payload
			}(),
			responseType: V3ResponseDestinationUnreachable,
		},
		{
			name: "zero destination port",
			payload: func() []byte {
				requestID := protocol.RequestID{}
				requestID[15] = 6
				payload := make([]byte, 1+V3RegistrationFlagLen+V3RegistrationPortLen+V3RegistrationIdleLen+V3RequestIDLength+V3IPv4AddrLen)
				payload[0] = byte(protocol.DatagramV3TypeRegistration)
				binary.BigEndian.PutUint16(payload[4:6], 30)
				copy(payload[6:22], requestID[:])
				copy(payload[22:26], []byte{127, 0, 0, 1})
				return payload
			}(),
			responseType: V3ResponseDestinationUnreachable,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			muxerCtx := testMuxerContext(t, 0)
			manager := NewDatagramV3SessionManager()
			sender := &captureDatagramSender{}
			muxer := NewDatagramV3Muxer(muxerCtx, sender, logger.NOP(), manager)

			muxer.HandleDatagram(context.Background(), testCase.payload)

			if len(sender.sent) != 1 {
				t.Fatalf("expected one registration response, got %#v", sender.sent)
			}
			if sender.sent[0][0] != byte(protocol.DatagramV3TypeRegistrationResponse) || sender.sent[0][1] != testCase.responseType {
				t.Fatalf("unexpected registration response %x", sender.sent[0])
			}
		})
	}
}

func TestDatagramV3HandlePayloadIgnoresShortAndUnknownSessions(t *testing.T) {
	t.Parallel()

	muxerCtx := testMuxerContext(t, 0)
	manager := NewDatagramV3SessionManager()
	muxer := NewDatagramV3Muxer(muxerCtx, &captureDatagramSender{}, logger.NOP(), manager)

	muxer.HandleDatagram(context.Background(), []byte{byte(protocol.DatagramV3TypePayload)})

	unknownID := protocol.RequestID{}
	unknownID[15] = 7
	payload := append([]byte{byte(protocol.DatagramV3TypePayload)}, unknownID[:]...)
	payload = append(payload, []byte("data")...)
	muxer.HandleDatagram(context.Background(), payload)
}
