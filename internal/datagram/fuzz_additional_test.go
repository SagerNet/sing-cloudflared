package datagram

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-cloudflared/internal/icmp"
	"github.com/sagernet/sing-cloudflared/internal/icmptest"
	"github.com/sagernet/sing-cloudflared/internal/protocol"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func FuzzParseICMPPacket(f *testing.F) {
	ipv4Source := netip.MustParseAddr("198.18.0.2")
	ipv4Target := netip.MustParseAddr("1.1.1.1")
	ipv6Source := netip.MustParseAddr("2001:db8::2")
	ipv6Target := netip.MustParseAddr("2606:4700:4700::1111")

	f.Add([]byte{})
	f.Add([]byte{0x45})
	f.Add([]byte{0x60})
	f.Add(icmptest.BuildIPv4ICMPPacket(ipv4Source, ipv4Target, header.ICMPv4Echo, 0, 1, 1))
	f.Add(icmptest.BuildIPv6ICMPPacket(ipv6Source, ipv6Target, header.ICMPv6EchoRequest, 0, 1, 1))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = icmp.ParsePacket(data)
	})
}

func FuzzDatagramV3HandleDatagram(f *testing.F) {
	f.Add([]byte{byte(protocol.DatagramV3TypePayload)})
	f.Add([]byte{byte(protocol.DatagramV3TypeRegistration)})
	f.Add([]byte{byte(protocol.DatagramV3TypeRegistrationResponse)})
	f.Add([]byte{byte(protocol.DatagramV3TypeICMP)})

	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		muxerCtx := MuxerContext{
			Context: ctx,
			Logger:  logger.NOP(),
			MaxActiveFlows: func() uint64 {
				return 0
			},
			FlowLimiter: &FlowLimiter{},
			DialPacket: func(ctx context.Context, destination M.Socksaddr) (N.PacketConn, error) {
				return noopPacketConn{}, nil
			},
		}
		manager := NewDatagramV3SessionManager()
		muxer := NewDatagramV3Muxer(muxerCtx, &captureDatagramSender{}, logger.NOP(), manager)
		muxer.HandleDatagram(context.Background(), data)
	})
}
