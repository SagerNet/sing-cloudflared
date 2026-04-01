package cloudflared

import (
	"context"
	"encoding/binary"
	"io"
	"net"
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

type blockingPacketConn struct {
	closed chan struct{}
}

func newBlockingPacketConn() *blockingPacketConn {
	return &blockingPacketConn{closed: make(chan struct{})}
}

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

func TestDatagramV2LocalCloseUnregistersRemote(t *testing.T) {
	t.Parallel()
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

	select {
	case call := <-unregisterCh:
		if call.sessionID != sessionID {
			t.Fatalf("unexpected session id: %s", call.sessionID)
		}
		if call.message != "local close" {
			t.Fatalf("unexpected message: %q", call.message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected unregister rpc")
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
