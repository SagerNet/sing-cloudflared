package cloudflared

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	internalicmp "github.com/sagernet/sing-cloudflared/internal/icmp"
	"github.com/sagernet/sing-cloudflared/internal/icmptest"
	internalprotocol "github.com/sagernet/sing-cloudflared/internal/protocol"
	pkgicmp "github.com/sagernet/sing-cloudflared/pkg/icmp"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
)

type captureRouteContext struct {
	packetCh chan []byte
}

func (c *captureRouteContext) WritePacket(packet []byte) error {
	copied := append([]byte(nil), packet...)
	select {
	case c.packetCh <- copied:
	default:
	}
	return nil
}

type syncDatagramSender struct {
	version  string
	packetCh chan []byte

	access sync.Mutex
	sent   [][]byte
}

func newSyncDatagramSender(version string) *syncDatagramSender {
	return &syncDatagramSender{
		version:  version,
		packetCh: make(chan []byte, 1),
	}
}

func (s *syncDatagramSender) SendDatagram(data []byte) error {
	copied := append([]byte(nil), data...)
	s.access.Lock()
	s.sent = append(s.sent, copied)
	s.access.Unlock()
	select {
	case s.packetCh <- copied:
	default:
	}
	return nil
}

func (s *syncDatagramSender) DatagramVersion() string {
	return s.version
}

func (s *syncDatagramSender) waitForPacket(t *testing.T, timeout time.Duration) []byte {
	t.Helper()
	select {
	case packet := <-s.packetCh:
		return packet
	case <-time.After(timeout):
		t.Fatal("timed out waiting for ICMP reply datagram")
		return nil
	}
}

func requireIPv6Loopback(t *testing.T) {
	t.Helper()
	listener, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	_ = listener.Close()
}

func shouldSkipICMPError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "permission denied") ||
		strings.Contains(lower, "operation not permitted") ||
		strings.Contains(lower, "network is unreachable") ||
		strings.Contains(lower, "cannot assign requested address")
}

func buildLoopbackICMPRequest(source, destination netip.Addr, identifier, sequence uint16) []byte {
	if destination.Is6() {
		return icmptest.BuildIPv6ICMPPacket(source, destination, header.ICMPv6EchoRequest, 0, identifier, sequence)
	}
	return icmptest.BuildIPv4ICMPPacket(source, destination, header.ICMPv4Echo, 0, identifier, sequence)
}

func requireDirectHandlerLoopbackCapability(t *testing.T, source, destination netip.Addr) {
	t.Helper()
	if destination.Is6() {
		requireIPv6Loopback(t)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler := pkgicmp.NewDirectHandler(logger.NOP())
	routeContext := &captureRouteContext{packetCh: make(chan []byte, 1)}
	destinationConn, err := handler.RouteICMPConnection(ctx, tun.DirectRouteSession{
		Source:      source,
		Destination: destination,
	}, routeContext, 2*time.Second)
	if shouldSkipICMPError(err) {
		t.Skipf("ICMP loopback unavailable for %s: %v", destination, err)
	}
	if err != nil {
		t.Fatalf("RouteICMPConnection(%s): %v", destination, err)
	}
	defer destinationConn.Close()

	err = destinationConn.WritePacket(buf.As(buildLoopbackICMPRequest(source, destination, 0x40, 1)).ToOwned())
	if shouldSkipICMPError(err) {
		t.Skipf("ICMP loopback write unavailable for %s: %v", destination, err)
	}
	if err != nil {
		t.Fatalf("WritePacket(%s): %v", destination, err)
	}

	select {
	case packet := <-routeContext.packetCh:
		info, err := ParseICMPPacket(packet)
		if err != nil {
			t.Fatalf("parse capability probe reply: %v", err)
		}
		if !info.IsEchoReply() {
			t.Fatalf("expected echo reply from capability probe, got type=%d code=%d", info.ICMPType, info.ICMPCode)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for ICMP loopback capability probe reply to %s", destination)
	}
}

func newICMPIntegrationService(t *testing.T) *Service {
	t.Helper()
	serviceInstance := newLimitedService(t, 0)
	serviceInstance.logger = logger.NOP()
	serviceInstance.icmpHandler = pkgicmp.NewDirectHandler(serviceInstance.logger)
	serviceInstance.datagramV2Muxers = make(map[DatagramSender]*DatagramV2Muxer)
	serviceInstance.datagramV3Muxers = make(map[DatagramSender]*DatagramV3Muxer)
	return serviceInstance
}

func encodeInboundICMPDatagram(t *testing.T, version string, packet []byte, traced bool) []byte {
	t.Helper()
	switch version {
	case datagramVersionV3:
		datagram, err := encodeV3ICMPDatagram(packet)
		if err != nil {
			t.Fatalf("encode V3 ICMP datagram: %v", err)
		}
		return datagram
	default:
		if traced {
			traceIdentity := bytes.Repeat([]byte{0x7a}, icmpTraceIdentityLength)
			payload := append(append([]byte(nil), packet...), traceIdentity...)
			return append(payload, byte(DatagramV2TypeIPWithTrace))
		}
		return append(append([]byte(nil), packet...), byte(DatagramV2TypeIP))
	}
}

func roundTripServiceICMP(t *testing.T, version string, source, destination netip.Addr, identifier, sequence uint16, traced bool) []byte {
	t.Helper()
	requireDirectHandlerLoopbackCapability(t, source, destination)

	serviceInstance := newICMPIntegrationService(t)
	sender := newSyncDatagramSender(version)
	request := buildLoopbackICMPRequest(source, destination, identifier, sequence)
	serviceInstance.handleDatagram(serviceInstance.ctx, encodeInboundICMPDatagram(t, version, request, traced), sender)
	return sender.waitForPacket(t, 3*time.Second)
}

func parseICMPReplyDatagram(t *testing.T, version string, datagram []byte) (internalprotocol.DatagramV2Type, internalprotocol.DatagramV3Type, internalicmp.PacketInfo) {
	t.Helper()
	switch version {
	case datagramVersionV3:
		if len(datagram) == 0 {
			t.Fatal("empty V3 reply datagram")
		}
		replyType := internalprotocol.DatagramV3Type(datagram[0])
		info, err := ParseICMPPacket(datagram[1:])
		if err != nil {
			t.Fatalf("parse V3 ICMP reply: %v", err)
		}
		return 0, replyType, info
	default:
		if len(datagram) == 0 {
			t.Fatal("empty V2 reply datagram")
		}
		replyType := internalprotocol.DatagramV2Type(datagram[len(datagram)-1])
		info, err := ParseICMPPacket(datagram[:len(datagram)-1])
		if err != nil {
			t.Fatalf("parse V2 ICMP reply: %v", err)
		}
		return replyType, 0, info
	}
}

func TestDirectHandlerICMPRoundTrip(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		version     string
		source      netip.Addr
		destination netip.Addr
		identifier  uint16
		sequence    uint16
		traced      bool
	}{
		{
			name:        "v2 ipv4",
			version:     defaultDatagramVersion,
			source:      netip.MustParseAddr("127.0.0.2"),
			destination: netip.MustParseAddr("127.0.0.1"),
			identifier:  0x101,
			sequence:    1,
		},
		{
			name:        "v2 traced ipv4",
			version:     defaultDatagramVersion,
			source:      netip.MustParseAddr("127.0.0.2"),
			destination: netip.MustParseAddr("127.0.0.1"),
			identifier:  0x102,
			sequence:    2,
			traced:      true,
		},
		{
			name:        "v3 ipv4",
			version:     datagramVersionV3,
			source:      netip.MustParseAddr("127.0.0.2"),
			destination: netip.MustParseAddr("127.0.0.1"),
			identifier:  0x103,
			sequence:    3,
		},
		{
			name:        "v2 ipv6",
			version:     defaultDatagramVersion,
			source:      netip.MustParseAddr("::1"),
			destination: netip.MustParseAddr("::1"),
			identifier:  0x201,
			sequence:    4,
		},
		{
			name:        "v3 ipv6",
			version:     datagramVersionV3,
			source:      netip.MustParseAddr("::1"),
			destination: netip.MustParseAddr("::1"),
			identifier:  0x202,
			sequence:    5,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			reply := roundTripServiceICMP(t, testCase.version, testCase.source, testCase.destination, testCase.identifier, testCase.sequence, testCase.traced)
			v2Type, v3Type, info := parseICMPReplyDatagram(t, testCase.version, reply)

			switch testCase.version {
			case datagramVersionV3:
				if v3Type != internalprotocol.DatagramV3TypeICMP {
					t.Fatalf("expected V3 ICMP reply type, got %d", v3Type)
				}
			default:
				if v2Type != internalprotocol.DatagramV2TypeIP {
					t.Fatalf("expected plain V2 IP reply type, got %d", v2Type)
				}
			}

			if !info.IsEchoReply() {
				t.Fatalf("expected echo reply, got type=%d code=%d", info.ICMPType, info.ICMPCode)
			}
			if info.Identifier != testCase.identifier || info.Sequence != testCase.sequence {
				t.Fatalf("unexpected reply id/seq %d/%d", info.Identifier, info.Sequence)
			}
			if info.SourceIP != testCase.destination || info.Destination != testCase.source {
				t.Fatalf("unexpected reply routing src=%s dst=%s", info.SourceIP, info.Destination)
			}
		})
	}
}
