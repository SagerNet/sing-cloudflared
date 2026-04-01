package cloudflared

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	icmpFlowTimeout         = 30 * time.Second
	icmpTraceIdentityLength = 16 + 8 + 1
	defaultICMPPacketTTL    = 255
	icmpErrorHeaderLen      = 8
	ipv4TTLExceededQuoteLen = 548
	ipv6TTLExceededQuoteLen = 1232
	maxICMPPayloadLen       = 1280

	icmpv4TypeEchoRequest  = 8
	icmpv4TypeEchoReply    = 0
	icmpv4TypeTimeExceeded = 11
	icmpv6TypeEchoRequest  = 128
	icmpv6TypeEchoReply    = 129
	icmpv6TypeTimeExceeded = 3
)

type ICMPTraceContext struct {
	Traced   bool
	Identity []byte
}

type ICMPFlowKey struct {
	IPVersion   uint8
	SourceIP    netip.Addr
	Destination netip.Addr
}

type ICMPRequestKey struct {
	Flow       ICMPFlowKey
	Identifier uint16
	Sequence   uint16
}

type ICMPPacketInfo struct {
	IPVersion     uint8
	Protocol      uint8
	SourceIP      netip.Addr
	Destination   netip.Addr
	ICMPType      uint8
	ICMPCode      uint8
	Identifier    uint16
	Sequence      uint16
	IPv4HeaderLen int
	IPv4TTL       uint8
	IPv6HopLimit  uint8
	RawPacket     []byte
}

func (i ICMPPacketInfo) FlowKey() ICMPFlowKey {
	return ICMPFlowKey{
		IPVersion:   i.IPVersion,
		SourceIP:    i.SourceIP,
		Destination: i.Destination,
	}
}

func (i ICMPPacketInfo) RequestKey() ICMPRequestKey {
	return ICMPRequestKey{
		Flow:       i.FlowKey(),
		Identifier: i.Identifier,
		Sequence:   i.Sequence,
	}
}

func (i ICMPPacketInfo) ReplyRequestKey() ICMPRequestKey {
	return ICMPRequestKey{
		Flow: ICMPFlowKey{
			IPVersion:   i.IPVersion,
			SourceIP:    i.Destination,
			Destination: i.SourceIP,
		},
		Identifier: i.Identifier,
		Sequence:   i.Sequence,
	}
}

func (i ICMPPacketInfo) IsEchoRequest() bool {
	switch i.IPVersion {
	case 4:
		return i.ICMPType == icmpv4TypeEchoRequest && i.ICMPCode == 0
	case 6:
		return i.ICMPType == icmpv6TypeEchoRequest && i.ICMPCode == 0
	default:
		return false
	}
}

func (i ICMPPacketInfo) IsEchoReply() bool {
	switch i.IPVersion {
	case 4:
		return i.ICMPType == icmpv4TypeEchoReply && i.ICMPCode == 0
	case 6:
		return i.ICMPType == icmpv6TypeEchoReply && i.ICMPCode == 0
	default:
		return false
	}
}

func (i ICMPPacketInfo) TTL() uint8 {
	if i.IPVersion == 4 {
		return i.IPv4TTL
	}
	return i.IPv6HopLimit
}

func (i ICMPPacketInfo) TTLExpired() bool {
	return i.TTL() <= 1
}

func (i *ICMPPacketInfo) DecrementTTL() error {
	switch i.IPVersion {
	case 4:
		if i.IPv4TTL == 0 || i.IPv4HeaderLen < 20 || len(i.RawPacket) < i.IPv4HeaderLen {
			return E.New("invalid IPv4 packet TTL state")
		}
		i.IPv4TTL--
		i.RawPacket[8] = i.IPv4TTL
		binary.BigEndian.PutUint16(i.RawPacket[10:12], 0)
		binary.BigEndian.PutUint16(i.RawPacket[10:12], checksum(i.RawPacket[:i.IPv4HeaderLen], 0))
	case 6:
		if i.IPv6HopLimit == 0 || len(i.RawPacket) < 40 {
			return E.New("invalid IPv6 packet hop limit state")
		}
		i.IPv6HopLimit--
		i.RawPacket[7] = i.IPv6HopLimit
	default:
		return E.New("unsupported IP version: ", i.IPVersion)
	}
	return nil
}

type icmpWireVersion uint8

const (
	icmpWireV2 icmpWireVersion = iota + 1
	icmpWireV3
)

type icmpFlowState struct {
	writer     *ICMPReplyWriter
	lastActive time.Time
}

type traceEntry struct {
	context   ICMPTraceContext
	createdAt time.Time
}

type ICMPReplyWriter struct {
	sender      DatagramSender
	wireVersion icmpWireVersion

	access sync.Mutex
	traces map[ICMPRequestKey]traceEntry
}

func NewICMPReplyWriter(sender DatagramSender, wireVersion icmpWireVersion) *ICMPReplyWriter {
	return &ICMPReplyWriter{
		sender:      sender,
		wireVersion: wireVersion,
		traces:      make(map[ICMPRequestKey]traceEntry),
	}
}

func (w *ICMPReplyWriter) RegisterRequestTrace(packetInfo ICMPPacketInfo, traceContext ICMPTraceContext) {
	if !traceContext.Traced {
		return
	}
	w.access.Lock()
	w.traces[packetInfo.RequestKey()] = traceEntry{
		context:   traceContext,
		createdAt: time.Now(),
	}
	w.access.Unlock()
}

func (w *ICMPReplyWriter) WritePacket(packet *buf.Buffer, destination M.Socksaddr) error {
	packetInfo, err := ParseICMPPacket(packet.Bytes())
	if err != nil {
		return err
	}
	if !packetInfo.IsEchoReply() {
		return nil
	}

	requestKey := packetInfo.ReplyRequestKey()
	w.access.Lock()
	entry, loaded := w.traces[requestKey]
	if loaded {
		delete(w.traces, requestKey)
	}
	w.access.Unlock()
	traceContext := entry.context

	datagram, err := encodeICMPDatagram(packetInfo.RawPacket, w.wireVersion, traceContext)
	if err != nil {
		return err
	}
	return w.sender.SendDatagram(datagram)
}

func (w *ICMPReplyWriter) cleanupExpired(now time.Time) {
	w.access.Lock()
	defer w.access.Unlock()
	for key, entry := range w.traces {
		if now.After(entry.createdAt.Add(icmpFlowTimeout)) {
			delete(w.traces, key)
		}
	}
}

type ICMPBridge struct {
	service     *Service
	sender      DatagramSender
	wireVersion icmpWireVersion
	routeCache  *routeCache

	flowAccess sync.Mutex
	flows      map[ICMPFlowKey]*icmpFlowState
}

func NewICMPBridge(service *Service, sender DatagramSender, wireVersion icmpWireVersion) *ICMPBridge {
	bridge := &ICMPBridge{
		service:     service,
		sender:      sender,
		wireVersion: wireVersion,
		routeCache:  newRouteCache(icmpFlowTimeout),
		flows:       make(map[ICMPFlowKey]*icmpFlowState),
	}
	if service != nil && service.ctx != nil {
		go bridge.cleanupLoop(service.ctx)
	}
	return bridge
}

func (b *ICMPBridge) HandleV2(ctx context.Context, datagramType DatagramV2Type, payload []byte) error {
	traceContext := ICMPTraceContext{}
	switch datagramType {
	case DatagramV2TypeIP:
	case DatagramV2TypeIPWithTrace:
		if len(payload) < icmpTraceIdentityLength {
			return E.New("icmp trace payload is too short")
		}
		traceContext.Traced = true
		traceContext.Identity = append([]byte(nil), payload[len(payload)-icmpTraceIdentityLength:]...)
		payload = payload[:len(payload)-icmpTraceIdentityLength]
	default:
		return E.New("unsupported v2 icmp datagram type: ", datagramType)
	}
	return b.handlePacket(ctx, payload, traceContext)
}

func (b *ICMPBridge) HandleV3(ctx context.Context, payload []byte) error {
	return b.handlePacket(ctx, payload, ICMPTraceContext{})
}

func (b *ICMPBridge) handlePacket(ctx context.Context, payload []byte, traceContext ICMPTraceContext) error {
	packetInfo, err := ParseICMPPacket(payload)
	if err != nil {
		return err
	}
	if !packetInfo.IsEchoRequest() {
		return nil
	}
	if packetInfo.TTLExpired() {
		ttlExceededPacket, err := buildICMPTTLExceededPacket(packetInfo)
		if err != nil {
			return err
		}
		datagram, err := encodeICMPDatagram(ttlExceededPacket, b.wireVersion, traceContext)
		if err != nil {
			return err
		}
		return b.sender.SendDatagram(datagram)
	}

	err = packetInfo.DecrementTTL()
	if err != nil {
		return err
	}

	state := b.getFlowState(packetInfo.FlowKey())
	state.lastActive = time.Now()
	if traceContext.Traced {
		state.writer.RegisterRequestTrace(packetInfo, traceContext)
	}

	if b.service.icmpHandler == nil {
		return nil
	}

	session := ICMPRouteSession{
		Source:      packetInfo.SourceIP,
		Destination: packetInfo.Destination,
	}
	destination, found := b.routeCache.Lookup(session)
	if !found {
		destination, err = b.service.icmpHandler.RouteICMPConnection(
			ctx,
			session,
			state.writer,
			icmpFlowTimeout,
		)
		if err != nil {
			return nil
		}
		b.routeCache.Store(session, destination)
	}

	return destination.WritePacket(buf.As(packetInfo.RawPacket).ToOwned())
}

func (b *ICMPBridge) getFlowState(key ICMPFlowKey) *icmpFlowState {
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()
	state, loaded := b.flows[key]
	if loaded {
		return state
	}
	state = &icmpFlowState{
		writer: NewICMPReplyWriter(b.sender, b.wireVersion),
	}
	b.flows[key] = state
	return state
}

func (b *ICMPBridge) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(icmpFlowTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			b.cleanupExpired(now)
		}
	}
}

func (b *ICMPBridge) cleanupExpired(now time.Time) {
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()
	for key, state := range b.flows {
		state.writer.cleanupExpired(now)
		if now.After(state.lastActive.Add(icmpFlowTimeout)) {
			delete(b.flows, key)
		}
	}
}

func ParseICMPPacket(packet []byte) (ICMPPacketInfo, error) {
	if len(packet) < 1 {
		return ICMPPacketInfo{}, E.New("empty IP packet")
	}
	version := packet[0] >> 4
	switch version {
	case 4:
		return parseIPv4ICMPPacket(packet)
	case 6:
		return parseIPv6ICMPPacket(packet)
	default:
		return ICMPPacketInfo{}, E.New("unsupported IP version: ", version)
	}
}

func parseIPv4ICMPPacket(packet []byte) (ICMPPacketInfo, error) {
	if len(packet) < 20 {
		return ICMPPacketInfo{}, E.New("IPv4 packet too short")
	}
	headerLen := int(packet[0]&0x0F) * 4
	if headerLen < 20 || len(packet) < headerLen+8 {
		return ICMPPacketInfo{}, E.New("invalid IPv4 header length")
	}
	if packet[9] != 1 {
		return ICMPPacketInfo{}, E.New("IPv4 packet is not ICMP")
	}
	sourceIP, ok := netip.AddrFromSlice(packet[12:16])
	if !ok {
		return ICMPPacketInfo{}, E.New("invalid IPv4 source address")
	}
	destinationIP, ok := netip.AddrFromSlice(packet[16:20])
	if !ok {
		return ICMPPacketInfo{}, E.New("invalid IPv4 destination address")
	}
	return ICMPPacketInfo{
		IPVersion:     4,
		Protocol:      1,
		SourceIP:      sourceIP,
		Destination:   destinationIP,
		ICMPType:      packet[headerLen],
		ICMPCode:      packet[headerLen+1],
		Identifier:    binary.BigEndian.Uint16(packet[headerLen+4 : headerLen+6]),
		Sequence:      binary.BigEndian.Uint16(packet[headerLen+6 : headerLen+8]),
		IPv4HeaderLen: headerLen,
		IPv4TTL:       packet[8],
		RawPacket:     append([]byte(nil), packet...),
	}, nil
}

func parseIPv6ICMPPacket(packet []byte) (ICMPPacketInfo, error) {
	if len(packet) < 48 {
		return ICMPPacketInfo{}, E.New("IPv6 packet too short")
	}
	if packet[6] != 58 {
		return ICMPPacketInfo{}, E.New("IPv6 packet is not ICMP")
	}
	sourceIP, ok := netip.AddrFromSlice(packet[8:24])
	if !ok {
		return ICMPPacketInfo{}, E.New("invalid IPv6 source address")
	}
	destinationIP, ok := netip.AddrFromSlice(packet[24:40])
	if !ok {
		return ICMPPacketInfo{}, E.New("invalid IPv6 destination address")
	}
	return ICMPPacketInfo{
		IPVersion:    6,
		Protocol:     58,
		SourceIP:     sourceIP,
		Destination:  destinationIP,
		ICMPType:     packet[40],
		ICMPCode:     packet[41],
		Identifier:   binary.BigEndian.Uint16(packet[44:46]),
		Sequence:     binary.BigEndian.Uint16(packet[46:48]),
		IPv6HopLimit: packet[7],
		RawPacket:    append([]byte(nil), packet...),
	}, nil
}

func maxEncodedICMPPacketLen(wireVersion icmpWireVersion, traceContext ICMPTraceContext) int {
	limit := maxV3UDPPayloadLen
	switch wireVersion {
	case icmpWireV2:
		limit -= typeIDLength
		if traceContext.Traced {
			limit -= len(traceContext.Identity)
		}
	case icmpWireV3:
		limit -= 1
	default:
		return 0
	}
	if limit < 0 {
		return 0
	}
	return limit
}

func buildICMPTTLExceededPacket(packetInfo ICMPPacketInfo) ([]byte, error) {
	switch packetInfo.IPVersion {
	case 4:
		return buildIPv4ICMPTTLExceededPacket(packetInfo)
	case 6:
		return buildIPv6ICMPTTLExceededPacket(packetInfo)
	default:
		return nil, E.New("unsupported IP version: ", packetInfo.IPVersion)
	}
}

func buildIPv4ICMPTTLExceededPacket(packetInfo ICMPPacketInfo) ([]byte, error) {
	const headerLen = 20
	if !packetInfo.SourceIP.Is4() || !packetInfo.Destination.Is4() {
		return nil, E.New("TTL exceeded packet requires IPv4 addresses")
	}

	quotedLength := min(len(packetInfo.RawPacket), ipv4TTLExceededQuoteLen)
	packet := make([]byte, headerLen+icmpErrorHeaderLen+quotedLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = defaultICMPPacketTTL
	packet[9] = 1
	copy(packet[12:16], packetInfo.Destination.AsSlice())
	copy(packet[16:20], packetInfo.SourceIP.AsSlice())
	packet[20] = icmpv4TypeTimeExceeded
	packet[21] = 0
	copy(packet[headerLen+icmpErrorHeaderLen:], packetInfo.RawPacket[:quotedLength])
	binary.BigEndian.PutUint16(packet[22:24], checksum(packet[20:], 0))
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerLen], 0))
	return packet, nil
}

func buildIPv6ICMPTTLExceededPacket(packetInfo ICMPPacketInfo) ([]byte, error) {
	const headerLen = 40
	if !packetInfo.SourceIP.Is6() || !packetInfo.Destination.Is6() {
		return nil, E.New("TTL exceeded packet requires IPv6 addresses")
	}

	quotedLength := min(len(packetInfo.RawPacket), ipv6TTLExceededQuoteLen)
	packet := make([]byte, headerLen+icmpErrorHeaderLen+quotedLength)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(icmpErrorHeaderLen+quotedLength))
	packet[6] = 58
	packet[7] = defaultICMPPacketTTL
	copy(packet[8:24], packetInfo.Destination.AsSlice())
	copy(packet[24:40], packetInfo.SourceIP.AsSlice())
	packet[40] = icmpv6TypeTimeExceeded
	packet[41] = 0
	copy(packet[headerLen+icmpErrorHeaderLen:], packetInfo.RawPacket[:quotedLength])
	binary.BigEndian.PutUint16(packet[42:44], checksum(packet[40:], ipv6PseudoHeaderChecksum(packetInfo.Destination, packetInfo.SourceIP, uint32(icmpErrorHeaderLen+quotedLength), 58)))
	return packet, nil
}

func encodeICMPDatagram(packet []byte, wireVersion icmpWireVersion, traceContext ICMPTraceContext) ([]byte, error) {
	switch wireVersion {
	case icmpWireV2:
		return encodeV2ICMPDatagram(packet, traceContext)
	case icmpWireV3:
		return encodeV3ICMPDatagram(packet)
	default:
		return nil, E.New("unsupported icmp wire version: ", wireVersion)
	}
}

func ipv6PseudoHeaderChecksum(source, destination netip.Addr, payloadLength uint32, nextHeader uint8) uint32 {
	var sum uint32
	sum = checksumSum(source.AsSlice(), sum)
	sum = checksumSum(destination.AsSlice(), sum)
	var lengthBytes [4]byte
	binary.BigEndian.PutUint32(lengthBytes[:], payloadLength)
	sum = checksumSum(lengthBytes[:], sum)
	sum = checksumSum([]byte{0, 0, 0, nextHeader}, sum)
	return sum
}

func checksumSum(data []byte, sum uint32) uint32 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	return sum
}

func checksum(data []byte, initial uint32) uint16 {
	sum := checksumSum(data, initial)
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func encodeV2ICMPDatagram(packet []byte, _ ICMPTraceContext) ([]byte, error) {
	data := make([]byte, 0, len(packet)+1)
	data = append(data, packet...)
	data = append(data, byte(DatagramV2TypeIP))
	return data, nil
}

func encodeV3ICMPDatagram(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, E.New("icmp payload is missing")
	}
	if len(packet) > maxICMPPayloadLen {
		return nil, E.New("icmp payload is too large")
	}
	data := make([]byte, 0, len(packet)+1)
	data = append(data, byte(DatagramV3TypeICMP))
	data = append(data, packet...)
	return data, nil
}
