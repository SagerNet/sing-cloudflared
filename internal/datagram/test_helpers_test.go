package datagram

import (
	"net/netip"

	"github.com/sagernet/sing-cloudflared/internal/icmp"
	"github.com/sagernet/sing-cloudflared/internal/icmptest"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
)

type fakeICMPPort struct {
	returnPath tun.Return
	reply      func(packet []byte) []byte
}

func (p *fakeICMPPort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.IPv4Unspecified(), netip.IPv6Unspecified()
}

func (p *fakeICMPPort) PortMTU() uint32 {
	return 0
}

func (p *fakeICMPPort) AttachReturn(returnPath tun.Return) error {
	p.returnPath = returnPath
	return nil
}

func (p *fakeICMPPort) DetachReturn(returnPath tun.Return) error {
	p.returnPath = nil
	return nil
}

func (p *fakeICMPPort) WritePackets(packets [][]byte) error {
	for _, packet := range packets {
		replyData := p.reply(packet)
		if replyData != nil {
			p.returnPath.ReturnPackets([][]byte{replyData})
		}
	}
	return nil
}

type replyICMPHandler struct {
	reply func([]byte) []byte
}

func (h *replyICMPHandler) RouteICMPFlow(source netip.Addr, destination netip.Addr) (tun.Port, error) {
	return &fakeICMPPort{reply: h.reply}, nil
}

func buildEchoReply(packet []byte) []byte {
	info, err := icmp.ParsePacket(packet)
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
