package datagram

import (
	"context"
	"time"

	"github.com/sagernet/sing-cloudflared/internal/icmp"
	"github.com/sagernet/sing-cloudflared/internal/icmptest"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
)

type fakeICMPRouteDestination struct {
	routeContext tun.DirectRouteContext
	packets      [][]byte
	reply        func(packet []byte) []byte
	closed       bool
}

func (d *fakeICMPRouteDestination) WritePacket(packet *buf.Buffer) error {
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

func (d *fakeICMPRouteDestination) Close() error {
	d.closed = true
	return nil
}

func (d *fakeICMPRouteDestination) IsClosed() bool {
	return d.closed
}

type replyICMPHandler struct {
	reply func([]byte) []byte
}

func (h *replyICMPHandler) RouteICMPConnection(ctx context.Context, session tun.DirectRouteSession, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	return &fakeICMPRouteDestination{
		routeContext: routeContext,
		reply:        h.reply,
	}, nil
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
