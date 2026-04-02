package icmp

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-cloudflared/internal/icmptest"
	"github.com/sagernet/sing-cloudflared/internal/protocol"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
)

type captureDatagramSender struct {
	sent [][]byte
}

func (s *captureDatagramSender) SendDatagram(data []byte) error {
	s.sent = append(s.sent, append([]byte(nil), data...))
	return nil
}

type fakeRouteDestination struct {
	routeContext tun.DirectRouteContext
	packets      [][]byte
	reply        func(packet []byte) []byte
	closed       bool
}

func (d *fakeRouteDestination) WritePacket(packet *buf.Buffer) error {
	data := append([]byte(nil), packet.Bytes()...)
	packet.Release()
	d.packets = append(d.packets, data)
	if d.reply != nil {
		replyData := d.reply(data)
		if replyData != nil {
			return d.routeContext.WritePacket(replyData)
		}
	}
	return nil
}

func (d *fakeRouteDestination) Close() error {
	d.closed = true
	return nil
}

func (d *fakeRouteDestination) IsClosed() bool {
	return d.closed
}

type fakeHandler struct {
	calls       int
	destination *fakeRouteDestination
}

func (h *fakeHandler) RouteICMPConnection(ctx context.Context, session tun.DirectRouteSession, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	h.calls++
	h.destination = &fakeRouteDestination{routeContext: routeContext}
	return h.destination, nil
}

type replyHandler struct {
	reply func([]byte) []byte
}

func (h *replyHandler) RouteICMPConnection(ctx context.Context, session tun.DirectRouteSession, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	return &fakeRouteDestination{
		routeContext: routeContext,
		reply:        h.reply,
	}, nil
}

func buildEchoReply(packet []byte) []byte {
	info, err := ParsePacket(packet)
	if err != nil {
		panic(err)
	}
	switch info.IPVersion {
	case 4:
		return icmptest.BuildIPv4ICMPPacket(info.Destination, info.SourceIP, header.ICMPv4EchoReply, 0, info.Identifier, info.Sequence)
	case 6:
		return icmptest.BuildIPv6ICMPPacket(info.Destination, info.SourceIP, header.ICMPv6EchoReply, 0, info.Identifier, info.Sequence)
	default:
		panic("unsupported version")
	}
}

func TestBridgeHandleV2RoutesEchoRequest(t *testing.T) {
	t.Parallel()
	handler := &fakeHandler{}
	sender := &captureDatagramSender{}
	bridge := NewBridge(nil, handler, sender, WireV2, nil)

	source := netip.MustParseAddr("198.18.0.2")
	target := netip.MustParseAddr("1.1.1.1")
	packet1 := icmptest.BuildIPv4ICMPPacket(source, target, header.ICMPv4Echo, 0, 1, 1)
	packet2 := icmptest.BuildIPv4ICMPPacket(source, target, header.ICMPv4Echo, 0, 1, 2)

	err := bridge.HandleV2(context.Background(), protocol.DatagramV2TypeIP, packet1)
	if err != nil {
		t.Fatal(err)
	}
	err = bridge.HandleV2(context.Background(), protocol.DatagramV2TypeIP, packet2)
	if err != nil {
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

func TestBridgeHandleV2TracedReply(t *testing.T) {
	t.Parallel()
	traceIdentity := bytes.Repeat([]byte{0x7a}, TraceIdentityLength)
	sender := &captureDatagramSender{}
	bridge := NewBridge(nil, &replyHandler{reply: buildEchoReply}, sender, WireV2, nil)

	request := icmptest.BuildIPv4ICMPPacket(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1"), header.ICMPv4Echo, 0, 9, 7)
	request = append(request, traceIdentity...)
	err := bridge.HandleV2(context.Background(), protocol.DatagramV2TypeIPWithTrace, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one reply datagram, got %d", len(sender.sent))
	}
	reply := sender.sent[0]
	if reply[len(reply)-1] != byte(protocol.DatagramV2TypeIP) {
		t.Fatalf("expected plain v2 IP reply, got type %d", reply[len(reply)-1])
	}
}

func TestBridgeHandleV3Reply(t *testing.T) {
	t.Parallel()
	sender := &captureDatagramSender{}
	bridge := NewBridge(nil, &replyHandler{reply: buildEchoReply}, sender, WireV3, nil)

	request := icmptest.BuildIPv6ICMPPacket(netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2606:4700:4700::1111"), header.ICMPv6EchoRequest, 0, 3, 5)
	err := bridge.HandleV3(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one reply datagram, got %d", len(sender.sent))
	}
	reply := sender.sent[0]
	if reply[0] != byte(protocol.DatagramV3TypeICMP) {
		t.Fatalf("expected v3 ICMP datagram, got %d", reply[0])
	}
}

func TestBridgeDecrementsIPv4TTLBeforeRouting(t *testing.T) {
	t.Parallel()
	handler := &fakeHandler{}
	bridge := NewBridge(nil, handler, &captureDatagramSender{}, WireV2, nil)

	packet := icmptest.BuildIPv4ICMPPacket(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1"), header.ICMPv4Echo, 0, 1, 1)
	header.IPv4(packet).SetTTL(5)

	err := bridge.HandleV2(context.Background(), protocol.DatagramV2TypeIP, packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(handler.destination.packets) != 1 {
		t.Fatalf("expected one routed packet, got %d", len(handler.destination.packets))
	}
	if got := header.IPv4(handler.destination.packets[0]).TTL(); got != 4 {
		t.Fatalf("expected decremented IPv4 TTL, got %d", got)
	}
}

func TestBridgeDecrementsIPv6HopLimitBeforeRouting(t *testing.T) {
	t.Parallel()
	handler := &fakeHandler{}
	bridge := NewBridge(nil, handler, &captureDatagramSender{}, WireV3, nil)

	packet := icmptest.BuildIPv6ICMPPacket(netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2606:4700:4700::1111"), header.ICMPv6EchoRequest, 0, 1, 1)
	header.IPv6(packet).SetHopLimit(3)

	err := bridge.HandleV3(context.Background(), packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(handler.destination.packets) != 1 {
		t.Fatalf("expected one routed packet, got %d", len(handler.destination.packets))
	}
	if got := header.IPv6(handler.destination.packets[0]).HopLimit(); got != 2 {
		t.Fatalf("expected decremented IPv6 hop limit, got %d", got)
	}
}

func TestBridgeHandleV2TTLExceededTracedReply(t *testing.T) {
	t.Parallel()
	traceIdentity := bytes.Repeat([]byte{0x6b}, TraceIdentityLength)
	sender := &captureDatagramSender{}
	bridge := NewBridge(nil, &fakeHandler{}, sender, WireV2, nil)

	source := netip.MustParseAddr("198.18.0.2")
	target := netip.MustParseAddr("1.1.1.1")
	packet := icmptest.BuildIPv4ICMPPacket(source, target, header.ICMPv4Echo, 0, 1, 1)
	header.IPv4(packet).SetTTL(1)
	packet = append(packet, traceIdentity...)

	err := bridge.HandleV2(context.Background(), protocol.DatagramV2TypeIPWithTrace, packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one TTL exceeded reply, got %d", len(sender.sent))
	}
	reply := sender.sent[0]
	if reply[len(reply)-1] != byte(protocol.DatagramV2TypeIP) {
		t.Fatalf("expected plain v2 reply, got type %d", reply[len(reply)-1])
	}
	rawReply := reply[:len(reply)-1]
	packetInfo, err := ParsePacket(rawReply)
	if err != nil {
		t.Fatal(err)
	}
	if packetInfo.ICMPType != uint8(header.ICMPv4TimeExceeded) || packetInfo.ICMPCode != 0 {
		t.Fatalf("expected IPv4 time exceeded reply, got type=%d code=%d", packetInfo.ICMPType, packetInfo.ICMPCode)
	}
	if packetInfo.SourceIP != target || packetInfo.Destination != source {
		t.Fatalf("unexpected TTL exceeded routing: src=%s dst=%s", packetInfo.SourceIP, packetInfo.Destination)
	}
	if packetInfo.TTL() != 255 {
		t.Fatalf("expected TTL exceeded packet TTL 255, got %d", packetInfo.TTL())
	}
}

func TestBridgeHandleV3TTLExceededReply(t *testing.T) {
	t.Parallel()
	sender := &captureDatagramSender{}
	bridge := NewBridge(nil, &fakeHandler{}, sender, WireV3, nil)

	source := netip.MustParseAddr("2001:db8::2")
	target := netip.MustParseAddr("2606:4700:4700::1111")
	packet := icmptest.BuildIPv6ICMPPacket(source, target, header.ICMPv6EchoRequest, 0, 1, 1)
	header.IPv6(packet).SetHopLimit(1)

	err := bridge.HandleV3(context.Background(), packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("expected one TTL exceeded reply, got %d", len(sender.sent))
	}
	if sender.sent[0][0] != byte(protocol.DatagramV3TypeICMP) {
		t.Fatalf("expected v3 ICMP reply, got %d", sender.sent[0][0])
	}
	packetInfo, err := ParsePacket(sender.sent[0][1:])
	if err != nil {
		t.Fatal(err)
	}
	if packetInfo.ICMPType != uint8(header.ICMPv6TimeExceeded) || packetInfo.ICMPCode != 0 {
		t.Fatalf("expected IPv6 time exceeded reply, got type=%d code=%d", packetInfo.ICMPType, packetInfo.ICMPCode)
	}
	if packetInfo.SourceIP != target || packetInfo.Destination != source {
		t.Fatalf("unexpected TTL exceeded routing: src=%s dst=%s", packetInfo.SourceIP, packetInfo.Destination)
	}
	if packetInfo.TTL() != 255 {
		t.Fatalf("expected TTL exceeded packet TTL 255, got %d", packetInfo.TTL())
	}
}

func TestBridgeDropsNonEcho(t *testing.T) {
	t.Parallel()
	handler := &fakeHandler{}
	sender := &captureDatagramSender{}
	bridge := NewBridge(nil, handler, sender, WireV2, nil)

	packet := icmptest.BuildIPv4ICMPPacket(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1"), header.ICMPv4DstUnreachable, 0, 1, 1)
	err := bridge.HandleV2(context.Background(), protocol.DatagramV2TypeIP, packet)
	if err != nil {
		t.Fatal(err)
	}
	if handler.calls != 0 {
		t.Fatalf("expected no route lookup, got %d", handler.calls)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("expected no sender datagrams, got %d", len(sender.sent))
	}
}

func TestBuildTTLExceededPacketUsesRFCQuoteLengths(t *testing.T) {
	t.Parallel()
	ipv4Packet := icmptest.BuildIPv4ICMPPacket(netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1"), header.ICMPv4Echo, 0, 1, 1)
	ipv4Packet = append(ipv4Packet, bytes.Repeat([]byte{0xaa}, 4096)...)
	ipv4Info, err := ParsePacket(ipv4Packet)
	if err != nil {
		t.Fatal(err)
	}
	ipv4Reply, err := BuildTTLExceededPacket(ipv4Info)
	if err != nil {
		t.Fatal(err)
	}
	if len(ipv4Reply) != header.IPv4MinimumSize+header.ICMPv4MinimumSize+IPv4TTLExceededQuoteLen {
		t.Fatalf("unexpected IPv4 TTL exceeded size: %d", len(ipv4Reply))
	}

	ipv6Packet := icmptest.BuildIPv6ICMPPacket(netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2606:4700:4700::1111"), header.ICMPv6EchoRequest, 0, 1, 1)
	ipv6Packet = append(ipv6Packet, bytes.Repeat([]byte{0xbb}, 4096)...)
	ipv6Info, err := ParsePacket(ipv6Packet)
	if err != nil {
		t.Fatal(err)
	}
	ipv6Reply, err := BuildTTLExceededPacket(ipv6Info)
	if err != nil {
		t.Fatal(err)
	}
	if len(ipv6Reply) != header.IPv6MinimumSize+header.ICMPv6MinimumSize+IPv6TTLExceededQuoteLen {
		t.Fatalf("unexpected IPv6 TTL exceeded size: %d", len(ipv6Reply))
	}
}

func TestEncodeV3DatagramRejectsEmptyPayload(t *testing.T) {
	t.Parallel()
	_, err := EncodeV3Datagram(nil)
	if err == nil {
		t.Fatal("expected empty payload to be rejected")
	}
}

func TestEncodeV3DatagramRejectsOversizedPayload(t *testing.T) {
	t.Parallel()
	_, err := EncodeV3Datagram(make([]byte, MaxPayloadLen+1))
	if err == nil {
		t.Fatal("expected oversized payload to be rejected")
	}
}

func TestBridgeCleanupExpired(t *testing.T) {
	t.Parallel()
	bridge := NewBridge(nil, nil, &captureDatagramSender{}, WireV2, nil)
	now := time.Now()

	expiredKey := FlowKey{
		IPVersion:   4,
		SourceIP:    netip.MustParseAddr("198.18.0.2"),
		Destination: netip.MustParseAddr("1.1.1.1"),
	}
	expiredState := bridge.getFlowState(expiredKey)
	expiredState.lastActive = now.Add(-FlowTimeout - time.Second)
	expiredState.writer.traces[RequestKey{Flow: expiredKey, Identifier: 1, Sequence: 1}] = TraceEntry{
		context:   TraceContext{Traced: true, Identity: []byte{1}},
		createdAt: now.Add(-FlowTimeout - time.Second),
	}

	activeKey := FlowKey{
		IPVersion:   6,
		SourceIP:    netip.MustParseAddr("2001:db8::2"),
		Destination: netip.MustParseAddr("2606:4700:4700::1111"),
	}
	activeState := bridge.getFlowState(activeKey)
	activeState.lastActive = now
	activeState.writer.traces[RequestKey{Flow: activeKey, Identifier: 2, Sequence: 2}] = TraceEntry{
		context:   TraceContext{Traced: true, Identity: []byte{2}},
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

func TestParsePacketRejectsMalformedPackets(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		packet     []byte
		wantErrSub string
	}{
		{
			name:       "empty packet",
			packet:     nil,
			wantErrSub: "empty IP packet",
		},
		{
			name:       "unsupported version",
			packet:     []byte{0x30},
			wantErrSub: "unsupported IP version",
		},
		{
			name:       "short IPv4 header",
			packet:     bytes.Repeat([]byte{0x45}, 10),
			wantErrSub: "IPv4 packet too short",
		},
		{
			name:       "invalid IPv4 header length",
			packet:     append([]byte{0x41}, make([]byte, 19)...),
			wantErrSub: "invalid IPv4 header length",
		},
		{
			name: "IPv4 non-ICMP protocol",
			packet: func() []byte {
				packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
				ipHeader := header.IPv4(packet)
				ipHeader.Encode(&header.IPv4Fields{
					TotalLength: uint16(len(packet)),
					Protocol:    17,
				})
				return packet
			}(),
			wantErrSub: "IPv4 packet is not ICMP",
		},
		{
			name:       "short IPv6 header",
			packet:     append([]byte{0x60}, make([]byte, 10)...),
			wantErrSub: "IPv6 packet too short",
		},
		{
			name: "IPv6 non-ICMP protocol",
			packet: func() []byte {
				packet := make([]byte, header.IPv6MinimumSize+header.ICMPv6MinimumSize)
				ipHeader := header.IPv6(packet)
				ipHeader.Encode(&header.IPv6Fields{
					PayloadLength:     header.ICMPv6MinimumSize,
					TransportProtocol: 17,
					HopLimit:          64,
				})
				return packet
			}(),
			wantErrSub: "IPv6 packet is not ICMP",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := ParsePacket(testCase.packet)
			if err == nil || !strings.Contains(err.Error(), testCase.wantErrSub) {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}

func TestMaxEncodedPacketLenScenarios(t *testing.T) {
	t.Parallel()

	traceContext := TraceContext{
		Traced:   true,
		Identity: bytes.Repeat([]byte{0xaa}, TraceIdentityLength),
	}
	if got := MaxEncodedPacketLen(WireV2, TraceContext{}); got != protocol.MaxV3UDPPayloadLen-protocol.TypeIDLength {
		t.Fatalf("unexpected v2 untraced limit %d", got)
	}
	if got := MaxEncodedPacketLen(WireV2, traceContext); got != protocol.MaxV3UDPPayloadLen-protocol.TypeIDLength-TraceIdentityLength {
		t.Fatalf("unexpected v2 traced limit %d", got)
	}
	if got := MaxEncodedPacketLen(WireV3, traceContext); got != protocol.MaxV3UDPPayloadLen-1 {
		t.Fatalf("unexpected v3 limit %d", got)
	}
	if got := MaxEncodedPacketLen(WireVersion(99), traceContext); got != 0 {
		t.Fatalf("expected unknown wire version to return 0, got %d", got)
	}
}
