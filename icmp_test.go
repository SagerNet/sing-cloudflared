package cloudflared

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type captureDatagramSender struct {
	sent [][]byte
}

func (s *captureDatagramSender) SendDatagram(data []byte) error {
	s.sent = append(s.sent, append([]byte(nil), data...))
	return nil
}

type fakeICMPRouteDestination struct {
	routeContext ICMPRouteContext
	packets      [][]byte
	reply        func(packet []byte) []byte
	closed       bool
}

func (d *fakeICMPRouteDestination) WritePacket(packet *buf.Buffer) error {
	data := append([]byte(nil), packet.Bytes()...)
	packet.Release()
	d.packets = append(d.packets, data)
	if d.reply != nil {
		reply := d.reply(data)
		if reply != nil {
			return d.routeContext.WritePacket(buf.As(reply).ToOwned(), M.Socksaddr{})
		}
	}
	return nil
}

func (d *fakeICMPRouteDestination) Timeout() time.Duration {
	return icmpFlowTimeout
}

func (d *fakeICMPRouteDestination) Close() error {
	d.closed = true
	return nil
}

func (d *fakeICMPRouteDestination) IsClosed() bool {
	return d.closed
}

type fakeICMPHandler struct {
	calls       int
	destination *fakeICMPRouteDestination
}

func (h *fakeICMPHandler) RouteICMPConnection(ctx context.Context, session ICMPRouteSession, routeContext ICMPRouteContext, timeout time.Duration) (ICMPRouteDestination, error) {
	h.calls++
	h.destination = &fakeICMPRouteDestination{routeContext: routeContext}
	return h.destination, nil
}

func TestICMPBridgeHandleV2RoutesEchoRequest(t *testing.T) {
	t.Parallel()
	handler := &fakeICMPHandler{}
	serviceInstance := &Service{
		icmpHandler: handler,
	}
	sender := &captureDatagramSender{}
	bridge := NewICMPBridge(serviceInstance, sender, icmpWireV2)

	source := netip.MustParseAddr("198.18.0.2")
	target := netip.MustParseAddr("1.1.1.1")
	packet1 := buildIPv4ICMPPacket(source, target, 8, 0, 1, 1)
	packet2 := buildIPv4ICMPPacket(source, target, 8, 0, 1, 2)

	if err := bridge.HandleV2(context.Background(), DatagramV2TypeIP, packet1); err != nil {
		t.Fatal(err)
	}
	if err := bridge.HandleV2(context.Background(), DatagramV2TypeIP, packet2); err != nil {
		t.Fatal(err)
	}
	if handler.calls != 1 {
		t.Fatalf("expected one direct-route lookup, got %d", handler.calls)
	}
	if len(handler.destination.packets) != 2 {
		t.Fatalf("expected two packets written, got %d", len(handler.destination.packets))
	}
	if len(sender.sent) != 0 {
		t.Fatalf("expected no reply datagrams, got %d", len(sender.sent))
	}
}

func TestICMPBridgeHandleV2TracedReply(t *testing.T) {
	t.Parallel()
	traceIdentity := bytes.Repeat([]byte{0x7a}, icmpTraceIdentityLength)
	sender := &captureDatagramSender{}
	handler := &fakeICMPHandler{}
	handler.RouteICMPConnection(context.Background(), ICMPRouteSession{}, nil, 0)
	replyHandler := &fakeICMPHandler{}
	serviceInstance := &Service{
		icmpHandler: &replyICMPHandler{reply: buildEchoReply},
	}
	_ = replyHandler
	bridge := NewICMPBridge(serviceInstance, sender, icmpWireV2)

	request := buildIPv4ICMPPacket(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1"), 8, 0, 9, 7)
	request = append(request, traceIdentity...)
	if err := bridge.HandleV2(context.Background(), DatagramV2TypeIPWithTrace, request); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one reply datagram, got %d", len(sender.sent))
	}
	reply := sender.sent[0]
	if reply[len(reply)-1] != byte(DatagramV2TypeIP) {
		t.Fatalf("expected plain v2 IP reply, got type %d", reply[len(reply)-1])
	}
}

type replyICMPHandler struct {
	reply func([]byte) []byte
}

func (h *replyICMPHandler) RouteICMPConnection(ctx context.Context, session ICMPRouteSession, routeContext ICMPRouteContext, timeout time.Duration) (ICMPRouteDestination, error) {
	return &fakeICMPRouteDestination{
		routeContext: routeContext,
		reply:        h.reply,
	}, nil
}

func TestICMPBridgeHandleV3Reply(t *testing.T) {
	t.Parallel()
	sender := &captureDatagramSender{}
	serviceInstance := &Service{
		icmpHandler: &replyICMPHandler{reply: buildEchoReply},
	}
	bridge := NewICMPBridge(serviceInstance, sender, icmpWireV3)

	request := buildIPv6ICMPPacket(netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2606:4700:4700::1111"), 128, 0, 3, 5)
	if err := bridge.HandleV3(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one reply datagram, got %d", len(sender.sent))
	}
	reply := sender.sent[0]
	if reply[0] != byte(DatagramV3TypeICMP) {
		t.Fatalf("expected v3 ICMP datagram, got %d", reply[0])
	}
}

func TestICMPBridgeDecrementsIPv4TTLBeforeRouting(t *testing.T) {
	t.Parallel()
	handler := &fakeICMPHandler{}
	serviceInstance := &Service{
		icmpHandler: handler,
	}
	bridge := NewICMPBridge(serviceInstance, &captureDatagramSender{}, icmpWireV2)

	packet := buildIPv4ICMPPacket(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1"), icmpv4TypeEchoRequest, 0, 1, 1)
	packet[8] = 5

	if err := bridge.HandleV2(context.Background(), DatagramV2TypeIP, packet); err != nil {
		t.Fatal(err)
	}
	if len(handler.destination.packets) != 1 {
		t.Fatalf("expected one routed packet, got %d", len(handler.destination.packets))
	}
	if got := handler.destination.packets[0][8]; got != 4 {
		t.Fatalf("expected decremented IPv4 TTL, got %d", got)
	}
}

func TestICMPBridgeDecrementsIPv6HopLimitBeforeRouting(t *testing.T) {
	t.Parallel()
	handler := &fakeICMPHandler{}
	serviceInstance := &Service{
		icmpHandler: handler,
	}
	bridge := NewICMPBridge(serviceInstance, &captureDatagramSender{}, icmpWireV3)

	packet := buildIPv6ICMPPacket(netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2606:4700:4700::1111"), icmpv6TypeEchoRequest, 0, 1, 1)
	packet[7] = 3

	if err := bridge.HandleV3(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	if len(handler.destination.packets) != 1 {
		t.Fatalf("expected one routed packet, got %d", len(handler.destination.packets))
	}
	if got := handler.destination.packets[0][7]; got != 2 {
		t.Fatalf("expected decremented IPv6 hop limit, got %d", got)
	}
}

func TestICMPBridgeHandleV2TTLExceededTracedReply(t *testing.T) {
	t.Parallel()
	traceIdentity := bytes.Repeat([]byte{0x6b}, icmpTraceIdentityLength)
	sender := &captureDatagramSender{}
	serviceInstance := &Service{
		icmpHandler: &fakeICMPHandler{},
	}
	bridge := NewICMPBridge(serviceInstance, sender, icmpWireV2)

	source := netip.MustParseAddr("198.18.0.2")
	target := netip.MustParseAddr("1.1.1.1")
	packet := buildIPv4ICMPPacket(source, target, icmpv4TypeEchoRequest, 0, 1, 1)
	packet[8] = 1
	packet = append(packet, traceIdentity...)

	if err := bridge.HandleV2(context.Background(), DatagramV2TypeIPWithTrace, packet); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one TTL exceeded reply, got %d", len(sender.sent))
	}
	reply := sender.sent[0]
	if reply[len(reply)-1] != byte(DatagramV2TypeIP) {
		t.Fatalf("expected plain v2 reply, got type %d", reply[len(reply)-1])
	}
	rawReply := reply[:len(reply)-1]
	packetInfo, err := ParseICMPPacket(rawReply)
	if err != nil {
		t.Fatal(err)
	}
	if packetInfo.ICMPType != icmpv4TypeTimeExceeded || packetInfo.ICMPCode != 0 {
		t.Fatalf("expected IPv4 time exceeded reply, got type=%d code=%d", packetInfo.ICMPType, packetInfo.ICMPCode)
	}
	if packetInfo.SourceIP != target || packetInfo.Destination != source {
		t.Fatalf("unexpected TTL exceeded routing: src=%s dst=%s", packetInfo.SourceIP, packetInfo.Destination)
	}
	if packetInfo.TTL() != 255 {
		t.Fatalf("expected TTL exceeded packet TTL 255, got %d", packetInfo.TTL())
	}
}

func TestICMPBridgeHandleV3TTLExceededReply(t *testing.T) {
	t.Parallel()
	sender := &captureDatagramSender{}
	serviceInstance := &Service{
		icmpHandler: &fakeICMPHandler{},
	}
	bridge := NewICMPBridge(serviceInstance, sender, icmpWireV3)

	source := netip.MustParseAddr("2001:db8::2")
	target := netip.MustParseAddr("2606:4700:4700::1111")
	packet := buildIPv6ICMPPacket(source, target, icmpv6TypeEchoRequest, 0, 1, 1)
	packet[7] = 1

	if err := bridge.HandleV3(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one TTL exceeded reply, got %d", len(sender.sent))
	}
	if sender.sent[0][0] != byte(DatagramV3TypeICMP) {
		t.Fatalf("expected v3 ICMP reply, got %d", sender.sent[0][0])
	}
	packetInfo, err := ParseICMPPacket(sender.sent[0][1:])
	if err != nil {
		t.Fatal(err)
	}
	if packetInfo.ICMPType != icmpv6TypeTimeExceeded || packetInfo.ICMPCode != 0 {
		t.Fatalf("expected IPv6 time exceeded reply, got type=%d code=%d", packetInfo.ICMPType, packetInfo.ICMPCode)
	}
	if packetInfo.SourceIP != target || packetInfo.Destination != source {
		t.Fatalf("unexpected TTL exceeded routing: src=%s dst=%s", packetInfo.SourceIP, packetInfo.Destination)
	}
	if packetInfo.TTL() != 255 {
		t.Fatalf("expected TTL exceeded packet TTL 255, got %d", packetInfo.TTL())
	}
}

func TestICMPBridgeDropsNonEcho(t *testing.T) {
	t.Parallel()
	handler := &fakeICMPHandler{}
	serviceInstance := &Service{
		icmpHandler: handler,
	}
	sender := &captureDatagramSender{}
	bridge := NewICMPBridge(serviceInstance, sender, icmpWireV2)

	packet := buildIPv4ICMPPacket(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1"), 3, 0, 1, 1)
	if err := bridge.HandleV2(context.Background(), DatagramV2TypeIP, packet); err != nil {
		t.Fatal(err)
	}
	if handler.calls != 0 {
		t.Fatalf("expected no route lookup, got %d", handler.calls)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("expected no sender datagrams, got %d", len(sender.sent))
	}
}

func TestBuildICMPTTLExceededPacketUsesRFCQuoteLengths(t *testing.T) {
	t.Parallel()
	ipv4Packet := buildIPv4ICMPPacket(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1"), icmpv4TypeEchoRequest, 0, 1, 1)
	ipv4Packet = append(ipv4Packet, bytes.Repeat([]byte{0xaa}, 4096)...)
	ipv4Info, err := ParseICMPPacket(ipv4Packet)
	if err != nil {
		t.Fatal(err)
	}
	ipv4Reply, err := buildICMPTTLExceededPacket(ipv4Info)
	if err != nil {
		t.Fatal(err)
	}
	if len(ipv4Reply) != 20+icmpErrorHeaderLen+ipv4TTLExceededQuoteLen {
		t.Fatalf("unexpected IPv4 TTL exceeded size: %d", len(ipv4Reply))
	}

	ipv6Packet := buildIPv6ICMPPacket(netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2606:4700:4700::1111"), icmpv6TypeEchoRequest, 0, 1, 1)
	ipv6Packet = append(ipv6Packet, bytes.Repeat([]byte{0xbb}, 4096)...)
	ipv6Info, err := ParseICMPPacket(ipv6Packet)
	if err != nil {
		t.Fatal(err)
	}
	ipv6Reply, err := buildICMPTTLExceededPacket(ipv6Info)
	if err != nil {
		t.Fatal(err)
	}
	if len(ipv6Reply) != 40+icmpErrorHeaderLen+ipv6TTLExceededQuoteLen {
		t.Fatalf("unexpected IPv6 TTL exceeded size: %d", len(ipv6Reply))
	}
}

func TestEncodeV3ICMPDatagramRejectsEmptyPayload(t *testing.T) {
	t.Parallel()
	if _, err := encodeV3ICMPDatagram(nil); err == nil {
		t.Fatal("expected empty payload to be rejected")
	}
}

func TestEncodeV3ICMPDatagramRejectsOversizedPayload(t *testing.T) {
	t.Parallel()
	if _, err := encodeV3ICMPDatagram(make([]byte, maxICMPPayloadLen+1)); err == nil {
		t.Fatal("expected oversized payload to be rejected")
	}
}

func TestICMPBridgeCleanupExpired(t *testing.T) {
	t.Parallel()
	bridge := NewICMPBridge(&Service{}, &captureDatagramSender{}, icmpWireV2)
	now := time.Now()

	expiredKey := ICMPFlowKey{
		IPVersion:   4,
		SourceIP:    netip.MustParseAddr("198.18.0.2"),
		Destination: netip.MustParseAddr("1.1.1.1"),
	}
	expiredState := bridge.getFlowState(expiredKey)
	expiredState.lastActive = now.Add(-icmpFlowTimeout - time.Second)
	expiredState.writer.traces[ICMPRequestKey{Flow: expiredKey, Identifier: 1, Sequence: 1}] = traceEntry{
		context:   ICMPTraceContext{Traced: true, Identity: []byte{1}},
		createdAt: now.Add(-icmpFlowTimeout - time.Second),
	}

	activeKey := ICMPFlowKey{
		IPVersion:   6,
		SourceIP:    netip.MustParseAddr("2001:db8::2"),
		Destination: netip.MustParseAddr("2606:4700:4700::1111"),
	}
	activeState := bridge.getFlowState(activeKey)
	activeState.lastActive = now
	activeState.writer.traces[ICMPRequestKey{Flow: activeKey, Identifier: 2, Sequence: 2}] = traceEntry{
		context:   ICMPTraceContext{Traced: true, Identity: []byte{2}},
		createdAt: now,
	}

	bridge.cleanupExpired(now)

	if _, exists := bridge.flows[expiredKey]; exists {
		t.Fatal("expected expired flow to be removed")
	}
	if _, exists := bridge.flows[activeKey]; !exists {
		t.Fatal("expected active flow to remain")
	}
	if len(activeState.writer.traces) != 1 {
		t.Fatalf("expected active trace to remain, got %d", len(activeState.writer.traces))
	}
}

func buildEchoReply(packet []byte) []byte {
	info, err := ParseICMPPacket(packet)
	if err != nil {
		panic(err)
	}
	switch info.IPVersion {
	case 4:
		return buildIPv4ICMPPacket(info.Destination, info.SourceIP, 0, 0, info.Identifier, info.Sequence)
	case 6:
		return buildIPv6ICMPPacket(info.Destination, info.SourceIP, 129, 0, info.Identifier, info.Sequence)
	default:
		panic("unsupported version")
	}
}

func buildIPv4ICMPPacket(source, destination netip.Addr, icmpType, icmpCode uint8, identifier, sequence uint16) []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	packet[20] = icmpType
	packet[21] = icmpCode
	binary.BigEndian.PutUint16(packet[24:26], identifier)
	binary.BigEndian.PutUint16(packet[26:28], sequence)
	return packet
}

func buildIPv6ICMPPacket(source, destination netip.Addr, icmpType, icmpCode uint8, identifier, sequence uint16) []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 8)
	packet[6] = 58
	packet[7] = 64
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], destination.AsSlice())
	packet[40] = icmpType
	packet[41] = icmpCode
	binary.BigEndian.PutUint16(packet[44:46], identifier)
	binary.BigEndian.PutUint16(packet[46:48], sequence)
	return packet
}
