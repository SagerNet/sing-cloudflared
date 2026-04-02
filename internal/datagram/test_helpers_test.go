package datagram

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/sagernet/sing-cloudflared/internal/icmp"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type fakeICMPRouteDestination struct {
	routeContext icmp.RouteContext
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
			return d.routeContext.WritePacket(buf.As(replyData).ToOwned(), M.Socksaddr{})
		}
	}
	return nil
}

func (d *fakeICMPRouteDestination) Timeout() time.Duration {
	return icmp.FlowTimeout
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

func (h *replyICMPHandler) RouteICMPConnection(ctx context.Context, session icmp.RouteSession, routeContext icmp.RouteContext, timeout time.Duration) (icmp.RouteDestination, error) {
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
