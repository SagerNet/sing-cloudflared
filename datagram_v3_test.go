package cloudflared

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func TestDatagramV3RegistrationDestinationUnreachable(t *testing.T) {
	t.Parallel()
	sender := &captureDatagramSender{}
	serviceInstance := &Service{
		flowLimiter:       &FlowLimiter{},
		datagramV3Manager: NewDatagramV3SessionManager(),
	}
	muxer := NewDatagramV3Muxer(serviceInstance, sender, nil)

	requestID := RequestID{}
	requestID[15] = 1
	payload := make([]byte, 1+2+2+16+4)
	payload[0] = 0
	binary.BigEndian.PutUint16(payload[1:3], 0)
	binary.BigEndian.PutUint16(payload[3:5], 30)
	copy(payload[5:21], requestID[:])
	copy(payload[21:25], []byte{0, 0, 0, 0})

	muxer.handleRegistration(context.Background(), payload)
	if len(sender.sent) != 1 {
		t.Fatalf("expected one registration response, got %d", len(sender.sent))
	}
	if sender.sent[0][0] != byte(DatagramV3TypeRegistrationResponse) || sender.sent[0][1] != v3ResponseDestinationUnreachable {
		t.Fatalf("unexpected datagram response: %v", sender.sent[0])
	}
}

func TestDatagramV3RegistrationErrorWithMessage(t *testing.T) {
	t.Parallel()
	sender := &captureDatagramSender{}
	serviceInstance := &Service{
		flowLimiter:       &FlowLimiter{},
		datagramV3Manager: NewDatagramV3SessionManager(),
	}
	muxer := NewDatagramV3Muxer(serviceInstance, sender, nil)

	requestID := RequestID{}
	requestID[15] = 2
	payload := make([]byte, 1+2+2+16+1)
	payload[0] = 1
	binary.BigEndian.PutUint16(payload[1:3], 53)
	binary.BigEndian.PutUint16(payload[3:5], 30)
	copy(payload[5:21], requestID[:])
	payload[21] = 0xaa

	muxer.handleRegistration(context.Background(), payload)
	if len(sender.sent) != 1 {
		t.Fatalf("expected one registration response, got %d", len(sender.sent))
	}
	if sender.sent[0][0] != byte(DatagramV3TypeRegistrationResponse) || sender.sent[0][1] != v3ResponseErrorWithMsg {
		t.Fatalf("unexpected datagram response: %v", sender.sent[0])
	}
}

type scriptedPacketConn struct {
	reads [][]byte
	index int
}

func (c *scriptedPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if c.index >= len(c.reads) {
		return M.Socksaddr{}, io.EOF
	}
	_, err := buffer.Write(c.reads[c.index])
	c.index++
	return M.Socksaddr{}, err
}

func (c *scriptedPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *scriptedPacketConn) Close() error                     { return nil }
func (c *scriptedPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *scriptedPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedPacketConn) SetWriteDeadline(time.Time) error { return nil }

type sizeLimitedSender struct {
	sent [][]byte
	max  int
}

func (s *sizeLimitedSender) SendDatagram(data []byte) error {
	if len(data) > s.max {
		return errors.New("datagram too large")
	}
	s.sent = append(s.sent, append([]byte(nil), data...))
	return nil
}

func TestDatagramV3ReadLoopDropsOversizedOriginPackets(t *testing.T) {
	t.Parallel()
	sender := &sizeLimitedSender{max: v3PayloadHeaderLen + maxV3UDPPayloadLen}
	session := &v3Session{
		id:          RequestID{},
		destination: netip.MustParseAddrPort("127.0.0.1:53"),
		origin: &scriptedPacketConn{reads: [][]byte{
			make([]byte, maxV3UDPPayloadLen+1),
			[]byte("ok"),
		}},
		service: &Service{
			logger: logger.NOP(),
		},
		writeChan:   make(chan []byte, 1),
		closeChan:   make(chan struct{}),
		contextChan: make(chan context.Context, 1),
		sender:      sender,
	}

	done := make(chan struct{})
	go func() {
		session.readLoop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected read loop to finish")
	}

	if len(sender.sent) != 1 {
		t.Fatalf("expected one datagram after dropping oversized payload, got %d", len(sender.sent))
	}
	if len(sender.sent[0]) != v3PayloadHeaderLen+2 {
		t.Fatalf("unexpected forwarded datagram length: %d", len(sender.sent[0]))
	}
}

func TestDatagramV3HandlePayloadDropsOversizedPayload(t *testing.T) {
	t.Parallel()
	requestID := RequestID{}
	requestID[15] = 9
	session := &v3Session{
		id:        requestID,
		writeChan: make(chan []byte, 1),
	}
	manager := NewDatagramV3SessionManager()
	manager.sessions[requestID] = session
	muxer := &DatagramV3Muxer{
		service: &Service{
			datagramV3Manager: manager,
		},
	}

	payload := make([]byte, v3RequestIDLength+maxV3UDPPayloadLen+1)
	copy(payload[:v3RequestIDLength], requestID[:])
	muxer.handlePayload(payload)

	select {
	case <-session.writeChan:
		t.Fatal("expected oversized payload to be dropped")
	default:
	}
}

type deadlinePacketConn struct {
	err error
}

func (c *deadlinePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	buffer.Release()
	return M.Socksaddr{}, io.EOF
}

func (c *deadlinePacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return c.err
}

func (c *deadlinePacketConn) Close() error                     { return nil }
func (c *deadlinePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *deadlinePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *deadlinePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *deadlinePacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestDatagramV3WriteLoopDropsDeadlineExceeded(t *testing.T) {
	t.Parallel()
	session := &v3Session{
		destination: netip.MustParseAddrPort("127.0.0.1:53"),
		origin:      &deadlinePacketConn{err: os.ErrDeadlineExceeded},
		service: &Service{
			logger: logger.NOP(),
		},
		writeChan: make(chan []byte, 1),
		closeChan: make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		session.writeLoop()
		close(done)
	}()

	session.writeToOrigin([]byte("payload"))
	time.Sleep(50 * time.Millisecond)

	select {
	case <-session.closeChan:
		t.Fatal("expected session to remain open after deadline exceeded")
	default:
	}

	session.close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected write loop to exit after manual close")
	}
}
