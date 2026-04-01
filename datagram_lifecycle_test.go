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
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

type v2UnregisterCall struct {
	sessionID uuid.UUID
	message   string
}

type captureRPCDatagramSender struct {
	captureDatagramSender
}

type captureV2SessionRPCClient struct {
	unregisterCh chan v2UnregisterCall
}

type recordingPacketConn struct {
	closed chan struct{}
	writes chan []byte
}

type blockingPacketConn struct {
	closed chan struct{}
}

func newRecordingPacketConn() *recordingPacketConn {
	return &recordingPacketConn{
		closed: make(chan struct{}),
		writes: make(chan []byte, 8),
	}
}

func newBlockingPacketConn() *blockingPacketConn {
	return &blockingPacketConn{closed: make(chan struct{})}
}

func (c *recordingPacketConn) ReadPacket(_ *buf.Buffer) (M.Socksaddr, error) {
	<-c.closed
	return M.Socksaddr{}, io.EOF
}

func (c *recordingPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	data := append([]byte(nil), buffer.Bytes()...)
	buffer.Release()
	c.writes <- data
	return nil
}

func (c *recordingPacketConn) Close() error {
	closeOnce(c.closed)
	return nil
}

func (c *recordingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *blockingPacketConn) ReadPacket(_ *buf.Buffer) (M.Socksaddr, error) {
	<-c.closed
	return M.Socksaddr{}, io.EOF
}

func (c *blockingPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *blockingPacketConn) Close() error {
	closeOnce(c.closed)
	return nil
}

func (c *blockingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *blockingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type packetDialingHandler struct {
	testHandler
	packetConn N.PacketConn
}

func (h *packetDialingHandler) DialPacket(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
	return h.packetConn, nil
}

func (c *captureV2SessionRPCClient) UnregisterSession(ctx context.Context, sessionID uuid.UUID, message string) error {
	c.unregisterCh <- v2UnregisterCall{sessionID: sessionID, message: message}
	return nil
}

func (c *captureV2SessionRPCClient) Close() error { return nil }

func waitForV2Unregister(t *testing.T, unregisterCh <-chan v2UnregisterCall, sessionID uuid.UUID, message string) {
	t.Helper()

	select {
	case call := <-unregisterCh:
		if call.sessionID != sessionID {
			t.Fatalf("unexpected session id: %s", call.sessionID)
		}
		if call.message != message {
			t.Fatalf("unexpected message: %q", call.message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected unregister rpc")
	}
}

func waitForV2SessionRemoval(t *testing.T, muxer *DatagramV2Muxer, sessionID uuid.UUID) {
	t.Helper()

	deadline := time.After(2 * time.Second)
	for {
		muxer.sessionAccess.RLock()
		_, exists := muxer.sessions[sessionID]
		muxer.sessionAccess.RUnlock()
		if !exists {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("expected V2 session %s to be removed", sessionID)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func waitForV3SessionRemoval(t *testing.T, manager *DatagramV3SessionManager, requestID RequestID) {
	t.Helper()

	deadline := time.After(2 * time.Second)
	for {
		if _, exists := manager.Get(requestID); !exists {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("expected V3 session %x to be removed", requestID)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func newV3RegistrationPayload(requestID RequestID, flags byte, destinationPort uint16, idleSeconds uint16, destinationIP []byte, bundledPayload []byte) []byte {
	payload := make([]byte, 1+2+2+len(requestID)+len(destinationIP)+len(bundledPayload))
	payload[0] = flags
	binary.BigEndian.PutUint16(payload[1:3], destinationPort)
	binary.BigEndian.PutUint16(payload[3:5], idleSeconds)
	copy(payload[5:21], requestID[:])
	copy(payload[21:21+len(destinationIP)], destinationIP)
	copy(payload[21+len(destinationIP):], bundledPayload)
	return payload
}

func TestDatagramV2LocalCloseUnregistersRemote(t *testing.T) {
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.handler = &packetDialingHandler{packetConn: newBlockingPacketConn()}
	sender := &captureRPCDatagramSender{}
	muxer := NewDatagramV2Muxer(serviceInstance, sender, serviceInstance.logger)
	unregisterCh := make(chan v2UnregisterCall, 1)
	originalClientFactory := newV2SessionRPCClient
	newV2SessionRPCClient = func(ctx context.Context, sender DatagramSender) (v2SessionRPCClient, error) {
		return &captureV2SessionRPCClient{unregisterCh: unregisterCh}, nil
	}
	defer func() {
		newV2SessionRPCClient = originalClientFactory
	}()

	sessionID := uuidTest(7)
	if err := muxer.RegisterSession(context.Background(), sessionID, net.IPv4(127, 0, 0, 1), 53, time.Second); err != nil {
		t.Fatal(err)
	}

	muxer.sessionAccess.RLock()
	session := muxer.sessions[sessionID]
	muxer.sessionAccess.RUnlock()
	if session == nil {
		t.Fatal("expected registered session")
	}

	session.closeWithReason("local close")

	waitForV2Unregister(t, unregisterCh, sessionID, "local close")
	waitForV2SessionRemoval(t, muxer, sessionID)
}

func TestDatagramV2IdleTimeoutUnregistersRemote(t *testing.T) {
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.handler = &packetDialingHandler{packetConn: newBlockingPacketConn()}
	muxer := NewDatagramV2Muxer(serviceInstance, &captureRPCDatagramSender{}, serviceInstance.logger)
	unregisterCh := make(chan v2UnregisterCall, 1)
	originalClientFactory := newV2SessionRPCClient
	newV2SessionRPCClient = func(ctx context.Context, sender DatagramSender) (v2SessionRPCClient, error) {
		return &captureV2SessionRPCClient{unregisterCh: unregisterCh}, nil
	}
	defer func() {
		newV2SessionRPCClient = originalClientFactory
	}()

	sessionID := uuidTest(8)
	if err := muxer.RegisterSession(context.Background(), sessionID, net.IPv4(127, 0, 0, 1), 53, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	waitForV2Unregister(t, unregisterCh, sessionID, "idle timeout")
	waitForV2SessionRemoval(t, muxer, sessionID)
}

func TestDatagramV2ContextCancellationUnregistersRemote(t *testing.T) {
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.handler = &packetDialingHandler{packetConn: newBlockingPacketConn()}
	muxer := NewDatagramV2Muxer(serviceInstance, &captureRPCDatagramSender{}, serviceInstance.logger)
	unregisterCh := make(chan v2UnregisterCall, 1)
	originalClientFactory := newV2SessionRPCClient
	newV2SessionRPCClient = func(ctx context.Context, sender DatagramSender) (v2SessionRPCClient, error) {
		return &captureV2SessionRPCClient{unregisterCh: unregisterCh}, nil
	}
	defer func() {
		newV2SessionRPCClient = originalClientFactory
	}()

	ctx, cancel := context.WithCancel(context.Background())
	sessionID := uuidTest(9)
	if err := muxer.RegisterSession(ctx, sessionID, net.IPv4(127, 0, 0, 1), 53, time.Second); err != nil {
		t.Fatal(err)
	}
	cancel()

	waitForV2Unregister(t, unregisterCh, sessionID, "connection closed")
	waitForV2SessionRemoval(t, muxer, sessionID)
}

func TestUDPSessionWriteActivityDelaysIdleTimeout(t *testing.T) {
	origin := newRecordingPacketConn()
	session := newUDPSession(
		uuidTest(10),
		netip.MustParseAddrPort("127.0.0.1:53"),
		80*time.Millisecond,
		origin,
		nil,
	)

	done := make(chan struct{})
	go func() {
		session.serve(context.Background())
		close(done)
	}()

	for range 3 {
		session.writeToOrigin([]byte("keepalive"))
		select {
		case payload := <-origin.writes:
			if string(payload) != "keepalive" {
				t.Fatalf("unexpected payload %q", payload)
			}
		case <-time.After(time.Second):
			t.Fatal("expected payload to be written to origin")
		}

		time.Sleep(30 * time.Millisecond)
		select {
		case <-session.closeChan:
			t.Fatal("expected session to remain open while writes stay active")
		default:
		}
	}

	select {
	case <-session.closeChan:
		t.Fatal("expected session to remain open shortly after the last activity")
	case <-time.After(40 * time.Millisecond):
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected session to close after activity stops")
	}
	if reason := session.closeReason(); reason != "idle timeout" {
		t.Fatalf("unexpected close reason %q", reason)
	}
}

func TestDatagramV3RegistrationMigratesSender(t *testing.T) {
	t.Parallel()
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.handler = &packetDialingHandler{packetConn: newBlockingPacketConn()}
	sender1 := &captureDatagramSender{}
	sender2 := &captureDatagramSender{}
	muxer1 := NewDatagramV3Muxer(serviceInstance, sender1, serviceInstance.logger)
	muxer2 := NewDatagramV3Muxer(serviceInstance, sender2, serviceInstance.logger)

	requestID := RequestID{}
	requestID[15] = 9
	payload := make([]byte, 1+2+2+16+4)
	payload[0] = 0
	binary.BigEndian.PutUint16(payload[1:3], 53)
	binary.BigEndian.PutUint16(payload[3:5], 30)
	copy(payload[5:21], requestID[:])
	copy(payload[21:25], []byte{127, 0, 0, 1})

	muxer1.handleRegistration(context.Background(), payload)
	session, exists := serviceInstance.datagramV3Manager.Get(requestID)
	if !exists {
		t.Fatal("expected v3 session after first registration")
	}

	muxer2.handleRegistration(context.Background(), payload)

	session.senderAccess.RLock()
	currentSender := session.sender
	session.senderAccess.RUnlock()
	if currentSender != sender2 {
		t.Fatal("expected v3 session sender migration to second sender")
	}

	session.close()
	waitForV3SessionRemoval(t, serviceInstance.datagramV3Manager, requestID)
}

func TestDatagramV3RegistrationExistingSessionRefreshesContext(t *testing.T) {
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.handler = &packetDialingHandler{packetConn: newBlockingPacketConn()}
	sender := &captureDatagramSender{}
	muxer := NewDatagramV3Muxer(serviceInstance, sender, serviceInstance.logger)

	requestID := RequestID{}
	requestID[15] = 11
	payload := newV3RegistrationPayload(requestID, 0, 53, 30, []byte{127, 0, 0, 1}, nil)

	ctx1 := context.WithValue(context.Background(), "id", 1)
	muxer.handleRegistration(ctx1, payload)

	session, exists := serviceInstance.datagramV3Manager.Get(requestID)
	if !exists {
		t.Fatal("expected v3 session after first registration")
	}
	session.activeAccess.Lock()
	session.activeAt = time.Time{}
	session.activeAccess.Unlock()

	ctx2 := context.WithValue(context.Background(), "id", 2)
	muxer.handleRegistration(ctx2, payload)

	refreshed, exists := serviceInstance.datagramV3Manager.Get(requestID)
	if !exists {
		t.Fatal("expected existing v3 session after re-registration")
	}
	if refreshed != session {
		t.Fatal("expected same V3 session to be reused for same sender")
	}
	if refreshed.currentContext() != ctx2 {
		t.Fatal("expected latest context to replace the original session context")
	}
	if refreshed.lastActive().IsZero() {
		t.Fatal("expected existing session registration to refresh activity")
	}
	refreshed.senderAccess.RLock()
	currentSender := refreshed.sender
	refreshed.senderAccess.RUnlock()
	if currentSender != sender {
		t.Fatal("expected existing session sender to remain unchanged")
	}
	if len(sender.sent) != 2 || sender.sent[0][1] != v3ResponseOK || sender.sent[1][1] != v3ResponseOK {
		t.Fatalf("unexpected registration responses %#v", sender.sent)
	}

	refreshed.close()
	waitForV3SessionRemoval(t, serviceInstance.datagramV3Manager, requestID)
}

func TestDatagramV3RegistrationBundleWritesInitialPayload(t *testing.T) {
	serviceInstance := newLimitedService(t, 0)
	origin := newRecordingPacketConn()
	serviceInstance.handler = &packetDialingHandler{packetConn: origin}
	sender := &captureDatagramSender{}
	muxer := NewDatagramV3Muxer(serviceInstance, sender, serviceInstance.logger)

	requestID := RequestID{}
	requestID[15] = 12
	payload := newV3RegistrationPayload(requestID, v3FlagBundle, 53, 30, []byte{127, 0, 0, 1}, []byte("hello"))

	muxer.handleRegistration(context.Background(), payload)

	select {
	case written := <-origin.writes:
		if string(written) != "hello" {
			t.Fatalf("unexpected bundled payload %q", written)
		}
	case <-time.After(time.Second):
		t.Fatal("expected bundled registration payload to be written to origin")
	}
	if len(sender.sent) != 1 || sender.sent[0][1] != v3ResponseOK {
		t.Fatalf("unexpected registration response %#v", sender.sent)
	}

	session, exists := serviceInstance.datagramV3Manager.Get(requestID)
	if !exists {
		t.Fatal("expected v3 session to exist after bundled registration")
	}
	session.close()
	waitForV3SessionRemoval(t, serviceInstance.datagramV3Manager, requestID)
}

func TestDatagramV3MigrationUpdatesSessionContext(t *testing.T) {
	t.Parallel()
	packetConn := newBlockingPacketConn()
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.handler = &packetDialingHandler{packetConn: packetConn}
	sender1 := &captureDatagramSender{}
	sender2 := &captureDatagramSender{}
	muxer1 := NewDatagramV3Muxer(serviceInstance, sender1, serviceInstance.logger)
	muxer2 := NewDatagramV3Muxer(serviceInstance, sender2, serviceInstance.logger)

	requestID := RequestID{}
	requestID[15] = 10
	payload := make([]byte, 1+2+2+16+4)
	payload[0] = 0
	binary.BigEndian.PutUint16(payload[1:3], 53)
	binary.BigEndian.PutUint16(payload[3:5], 30)
	copy(payload[5:21], requestID[:])
	copy(payload[21:25], []byte{127, 0, 0, 1})

	ctx1, cancel1 := context.WithCancel(context.Background())
	muxer1.handleRegistration(ctx1, payload)

	ctx2, cancel2 := context.WithCancel(context.Background())
	muxer2.handleRegistration(ctx2, payload)

	cancel1()
	time.Sleep(50 * time.Millisecond)

	session, exists := serviceInstance.datagramV3Manager.Get(requestID)
	if !exists {
		t.Fatal("expected session to survive old connection context cancellation")
	}

	session.senderAccess.RLock()
	currentSender := session.sender
	session.senderAccess.RUnlock()
	if currentSender != sender2 {
		t.Fatal("expected migrated sender to stay active")
	}

	cancel2()

	deadline := time.After(time.Second)
	for {
		if _, exists := serviceInstance.datagramV3Manager.Get(requestID); !exists {
			return
		}
		select {
		case <-deadline:
			t.Fatal("expected session to be removed after new context cancellation")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
