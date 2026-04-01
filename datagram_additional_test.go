package cloudflared

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/google/uuid"
)

type noopPacketConn struct{}

func (noopPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) { return M.Socksaddr{}, io.EOF }
func (noopPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}
func (noopPacketConn) Close() error                     { return nil }
func (noopPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (noopPacketConn) SetDeadline(time.Time) error      { return nil }
func (noopPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (noopPacketConn) SetWriteDeadline(time.Time) error { return nil }

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
	if gotID, err := uuid.FromBytes(data[5 : 5+sessionIDLength]); err != nil || gotID != sessionID {
		t.Fatalf("unexpected encoded session id %x err=%v", data, err)
	}
	if data[len(data)-1] != byte(DatagramV2TypeUDP) {
		t.Fatalf("unexpected datagram type %d", data[len(data)-1])
	}
}

func TestDatagramV2HandleUDPDatagramRoutesToSession(t *testing.T) {
	t.Parallel()

	sessionID := uuidTest(10)
	session := newUDPSession(sessionID, netip.MustParseAddrPort("127.0.0.1:53"), time.Second, noopPacketConn{}, nil)
	muxer := &DatagramV2Muxer{sessions: map[uuid.UUID]*udpSession{sessionID: session}}

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

func TestUDPSessionPacketConnAdapter(t *testing.T) {
	t.Parallel()

	sender := &captureDatagramSender{}
	muxer := &DatagramV2Muxer{sender: sender}
	session := newUDPSession(uuidTest(11), netip.MustParseAddrPort("127.0.0.1:53"), time.Second, noopPacketConn{}, muxer)
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

	if err := session.WritePacket(buf.As([]byte("def")), destination); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one sent datagram, got %#v", sender.sent)
	}
}

func TestDatagramV2CloseClearsSessions(t *testing.T) {
	t.Parallel()

	sessionID := uuidTest(12)
	session := newUDPSession(sessionID, netip.MustParseAddrPort("127.0.0.1:53"), time.Second, noopPacketConn{}, nil)
	muxer := &DatagramV2Muxer{sessions: map[uuid.UUID]*udpSession{sessionID: session}}
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

	serviceInstance := newLimitedService(t, 0)
	requestID := RequestID{}
	requestID[15] = 2
	session := &v3Session{
		id:        requestID,
		writeChan: make(chan []byte, 1),
		closeChan: make(chan struct{}),
	}
	serviceInstance.datagramV3Manager.sessions[requestID] = session
	muxer := NewDatagramV3Muxer(serviceInstance, &captureDatagramSender{}, serviceInstance.logger)

	payload := append([]byte{byte(DatagramV3TypePayload)}, requestID[:]...)
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
	requestID := RequestID{}
	requestID[15] = 3
	muxer.sendPayload(requestID, []byte("hello"))

	if len(sender.sent) != 1 {
		t.Fatalf("unexpected sent datagrams %#v", sender.sent)
	}
	data := sender.sent[0]
	if data[0] != byte(DatagramV3TypePayload) {
		t.Fatalf("unexpected datagram type %d", data[0])
	}
	if string(data[1+v3RequestIDLength:]) != "hello" {
		t.Fatalf("unexpected encoded payload %q", data)
	}
}

func TestV3SessionUpdateContextReplacesPendingContext(t *testing.T) {
	t.Parallel()

	session := &v3Session{
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

	serviceInstance := newLimitedService(t, 0)
	sender := &captureDatagramSender{}
	muxer := NewDatagramV3Muxer(serviceInstance, sender, serviceInstance.logger)

	requestID := RequestID{}
	requestID[15] = 4
	payload := make([]byte, 1+1+2+2+16)
	payload[0] = byte(DatagramV3TypeRegistration)
	payload[1] = v3FlagIPv6
	binary.BigEndian.PutUint16(payload[2:4], 53)
	binary.BigEndian.PutUint16(payload[4:6], 30)
	copy(payload[6:22], requestID[:])
	muxer.HandleDatagram(context.Background(), payload)

	if len(sender.sent) != 1 {
		t.Fatalf("expected one registration error response, got %#v", sender.sent)
	}
	if sender.sent[0][1] != v3ResponseErrorWithMsg {
		t.Fatalf("unexpected registration response %x", sender.sent[0])
	}
}
