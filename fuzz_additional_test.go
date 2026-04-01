package cloudflared

import (
	"context"
	"net/netip"
	"testing"
)

func FuzzParseICMPPacket(f *testing.F) {
	ipv4Source := netip.MustParseAddr("198.18.0.2")
	ipv4Target := netip.MustParseAddr("1.1.1.1")
	ipv6Source := netip.MustParseAddr("2001:db8::2")
	ipv6Target := netip.MustParseAddr("2606:4700:4700::1111")

	f.Add([]byte{})
	f.Add([]byte{0x45})
	f.Add([]byte{0x60})
	f.Add(buildIPv4ICMPPacket(ipv4Source, ipv4Target, icmpv4TypeEchoRequest, 0, 1, 1))
	f.Add(buildIPv6ICMPPacket(ipv6Source, ipv6Target, icmpv6TypeEchoRequest, 0, 1, 1))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseICMPPacket(data)
	})
}

func FuzzDatagramV3HandleDatagram(f *testing.F) {
	f.Add([]byte{byte(DatagramV3TypePayload)})
	f.Add([]byte{byte(DatagramV3TypeRegistration)})
	f.Add([]byte{byte(DatagramV3TypeRegistrationResponse)})
	f.Add([]byte{byte(DatagramV3TypeICMP)})

	f.Fuzz(func(t *testing.T, data []byte) {
		serviceInstance := newLimitedService(t, 0)
		serviceInstance.handler = &packetDialingHandler{packetConn: noopPacketConn{}}
		muxer := NewDatagramV3Muxer(serviceInstance, &captureDatagramSender{}, serviceInstance.logger)
		muxer.HandleDatagram(context.Background(), data)
	})
}
