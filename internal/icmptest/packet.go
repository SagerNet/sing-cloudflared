package icmptest

import (
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

func BuildIPv4ICMPPacket(source, destination netip.Addr, icmpType header.ICMPv4Type, icmpCode header.ICMPv4Code, identifier, sequence uint16) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	ipHeader := header.IPv4(packet)
	ipHeader.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     source,
		DstAddr:     destination,
	})
	icmpHeader := header.ICMPv4(ipHeader.Payload())
	icmpHeader.SetType(icmpType)
	icmpHeader.SetCode(icmpCode)
	icmpHeader.SetIdent(identifier)
	icmpHeader.SetSequence(sequence)
	return packet
}

func BuildIPv6ICMPPacket(source, destination netip.Addr, icmpType header.ICMPv6Type, icmpCode header.ICMPv6Code, identifier, sequence uint16) []byte {
	packet := make([]byte, header.IPv6MinimumSize+header.ICMPv6MinimumSize)
	ipHeader := header.IPv6(packet)
	ipHeader.Encode(&header.IPv6Fields{
		PayloadLength:     header.ICMPv6MinimumSize,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           source,
		DstAddr:           destination,
	})
	icmpHeader := header.ICMPv6(ipHeader.Payload())
	icmpHeader.SetType(icmpType)
	icmpHeader.SetCode(icmpCode)
	icmpHeader.SetIdent(identifier)
	icmpHeader.SetSequence(sequence)
	return packet
}
