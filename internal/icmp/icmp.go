package icmp

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-cloudflared/internal/protocol"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	FlowTimeout         = 30 * time.Second
	TraceIdentityLength = 16 + 8 + 1
	defaultPacketTTL    = 255
	ErrorHeaderLen      = 8
	IPv4TTLExceededQuoteLen = 548
	IPv6TTLExceededQuoteLen = 1232
	MaxPayloadLen       = 1280

	V4TypeEchoRequest  = 8
	icmpv4TypeEchoReply    = 0
	V4TypeTimeExceeded = 11
	V6TypeEchoRequest  = 128
	icmpv6TypeEchoReply    = 129
	V6TypeTimeExceeded = 3
)

type WireVersion uint8

const (
	WireV2 WireVersion = iota + 1
	WireV3
)

type TraceContext struct {
	Traced   bool
	Identity []byte
}

type FlowKey struct {
	IPVersion   uint8
	SourceIP    netip.Addr
	Destination netip.Addr
}

type RequestKey struct {
	Flow       FlowKey
	Identifier uint16
	Sequence   uint16
}

type PacketInfo struct {
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

func (i PacketInfo) FlowKey() FlowKey {
	return FlowKey{
		IPVersion:   i.IPVersion,
		SourceIP:    i.SourceIP,
		Destination: i.Destination,
	}
}

func (i PacketInfo) RequestKey() RequestKey {
	return RequestKey{
		Flow:       i.FlowKey(),
		Identifier: i.Identifier,
		Sequence:   i.Sequence,
	}
}

func (i PacketInfo) ReplyRequestKey() RequestKey {
	return RequestKey{
		Flow: FlowKey{
			IPVersion:   i.IPVersion,
			SourceIP:    i.Destination,
			Destination: i.SourceIP,
		},
		Identifier: i.Identifier,
		Sequence:   i.Sequence,
	}
}

func (i PacketInfo) IsEchoRequest() bool {
	switch i.IPVersion {
	case 4:
		return i.ICMPType == V4TypeEchoRequest && i.ICMPCode == 0
	case 6:
		return i.ICMPType == V6TypeEchoRequest && i.ICMPCode == 0
	default:
		return false
	}
}

func (i PacketInfo) IsEchoReply() bool {
	switch i.IPVersion {
	case 4:
		return i.ICMPType == icmpv4TypeEchoReply && i.ICMPCode == 0
	case 6:
		return i.ICMPType == icmpv6TypeEchoReply && i.ICMPCode == 0
	default:
		return false
	}
}

func (i PacketInfo) TTL() uint8 {
	if i.IPVersion == 4 {
		return i.IPv4TTL
	}
	return i.IPv6HopLimit
}

func (i PacketInfo) TTLExpired() bool {
	return i.TTL() <= 1
}

func (i *PacketInfo) DecrementTTL() error {
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

type FlowState struct {
	writer       *ReplyWriter
	activeAccess sync.RWMutex
	lastActive   time.Time
}

type TraceEntry struct {
	context   TraceContext
	createdAt time.Time
}

type ReplyWriter struct {
	sender      protocol.DatagramSender
	WireVersion WireVersion

	access sync.Mutex
	traces map[RequestKey]TraceEntry
}

func NewReplyWriter(sender protocol.DatagramSender, WireVersion WireVersion) *ReplyWriter {
	return &ReplyWriter{
		sender:      sender,
		WireVersion: WireVersion,
		traces:      make(map[RequestKey]TraceEntry),
	}
}

func (w *ReplyWriter) RegisterRequestTrace(packetInfo PacketInfo, traceContext TraceContext) {
	if !traceContext.Traced {
		return
	}
	w.access.Lock()
	w.traces[packetInfo.RequestKey()] = TraceEntry{
		context:   traceContext,
		createdAt: time.Now(),
	}
	w.access.Unlock()
}

func (w *ReplyWriter) WritePacket(packet *buf.Buffer, destination M.Socksaddr) error {
	packetInfo, err := ParsePacket(packet.Bytes())
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

	datagram, err := EncodeDatagram(packetInfo.RawPacket, w.WireVersion, traceContext)
	if err != nil {
		return err
	}
	return w.sender.SendDatagram(datagram)
}

func (w *ReplyWriter) cleanupExpired(now time.Time) {
	w.access.Lock()
	defer w.access.Unlock()
	for key, entry := range w.traces {
		if now.After(entry.createdAt.Add(FlowTimeout)) {
			delete(w.traces, key)
		}
	}
}

type Bridge struct {
	ctx         context.Context
	handler     RouteHandler
	sender      protocol.DatagramSender
	WireVersion WireVersion
	logger      logger.ContextLogger
	RouteCache  *RouteCache

	flowAccess sync.Mutex
	flows      map[FlowKey]*FlowState
}

func NewBridge(ctx context.Context, handler RouteHandler, sender protocol.DatagramSender, WireVersion WireVersion, logger logger.ContextLogger) *Bridge {
	bridge := &Bridge{
		ctx:         ctx,
		handler:     handler,
		sender:      sender,
		WireVersion: WireVersion,
		logger:      logger,
		RouteCache:  NewRouteCache(FlowTimeout),
		flows:       make(map[FlowKey]*FlowState),
	}
	if ctx != nil {
		go bridge.cleanupLoop(ctx)
	}
	return bridge
}

func (b *Bridge) HandleV2(ctx context.Context, datagramType protocol.DatagramV2Type, payload []byte) error {
	traceContext := TraceContext{}
	switch datagramType {
	case protocol.DatagramV2TypeIP:
	case protocol.DatagramV2TypeIPWithTrace:
		if len(payload) < TraceIdentityLength {
			return E.New("icmp trace payload is too short")
		}
		traceContext.Traced = true
		traceContext.Identity = append([]byte(nil), payload[len(payload)-TraceIdentityLength:]...)
		payload = payload[:len(payload)-TraceIdentityLength]
	default:
		return E.New("unsupported v2 icmp datagram type: ", datagramType)
	}
	return b.handlePacket(ctx, payload, traceContext)
}

func (b *Bridge) HandleV3(ctx context.Context, payload []byte) error {
	return b.handlePacket(ctx, payload, TraceContext{})
}

func (b *Bridge) handlePacket(ctx context.Context, payload []byte, traceContext TraceContext) error {
	packetInfo, err := ParsePacket(payload)
	if err != nil {
		return err
	}
	if !packetInfo.IsEchoRequest() {
		return nil
	}
	if packetInfo.TTLExpired() {
		ttlExceededPacket, err := BuildTTLExceededPacket(packetInfo)
		if err != nil {
			return err
		}
		datagram, err := EncodeDatagram(ttlExceededPacket, b.WireVersion, traceContext)
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
	state.activeAccess.Lock()
	state.lastActive = time.Now()
	state.activeAccess.Unlock()
	if traceContext.Traced {
		state.writer.RegisterRequestTrace(packetInfo, traceContext)
	}

	if b.handler == nil {
		return nil
	}

	session := RouteSession{
		Source:      packetInfo.SourceIP,
		Destination: packetInfo.Destination,
	}
	destination, found := b.RouteCache.Lookup(session)
	if !found {
		destination, err = b.handler.RouteICMPConnection(
			ctx,
			session,
			state.writer,
			FlowTimeout,
		)
		if err != nil {
			return nil
		}
		b.RouteCache.Store(session, destination)
	}

	return destination.WritePacket(buf.As(packetInfo.RawPacket).ToOwned())
}

func (b *Bridge) getFlowState(key FlowKey) *FlowState {
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()
	state, loaded := b.flows[key]
	if loaded {
		return state
	}
	state = &FlowState{
		writer: NewReplyWriter(b.sender, b.WireVersion),
	}
	b.flows[key] = state
	return state
}

func (b *Bridge) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(FlowTimeout)
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

func (b *Bridge) cleanupExpired(now time.Time) {
	b.flowAccess.Lock()
	var expiredWriters []*ReplyWriter
	var activeWriters []*ReplyWriter
	for key, state := range b.flows {
		state.activeAccess.RLock()
		expired := now.After(state.lastActive.Add(FlowTimeout))
		state.activeAccess.RUnlock()
		if expired {
			expiredWriters = append(expiredWriters, state.writer)
			delete(b.flows, key)
		} else {
			activeWriters = append(activeWriters, state.writer)
		}
	}
	b.flowAccess.Unlock()
	for _, writer := range expiredWriters {
		writer.cleanupExpired(now)
	}
	for _, writer := range activeWriters {
		writer.cleanupExpired(now)
	}
}

func ParsePacket(packet []byte) (PacketInfo, error) {
	if len(packet) < 1 {
		return PacketInfo{}, E.New("empty IP packet")
	}
	version := packet[0] >> 4
	switch version {
	case 4:
		return parseIPv4Packet(packet)
	case 6:
		return parseIPv6Packet(packet)
	default:
		return PacketInfo{}, E.New("unsupported IP version: ", version)
	}
}

func parseIPv4Packet(packet []byte) (PacketInfo, error) {
	if len(packet) < 20 {
		return PacketInfo{}, E.New("IPv4 packet too short")
	}
	headerLen := int(packet[0]&0x0F) * 4
	if headerLen < 20 || len(packet) < headerLen+8 {
		return PacketInfo{}, E.New("invalid IPv4 header length")
	}
	if packet[9] != 1 {
		return PacketInfo{}, E.New("IPv4 packet is not ICMP")
	}
	sourceIP, ok := netip.AddrFromSlice(packet[12:16])
	if !ok {
		return PacketInfo{}, E.New("invalid IPv4 source address")
	}
	destinationIP, ok := netip.AddrFromSlice(packet[16:20])
	if !ok {
		return PacketInfo{}, E.New("invalid IPv4 destination address")
	}
	return PacketInfo{
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

func parseIPv6Packet(packet []byte) (PacketInfo, error) {
	if len(packet) < 48 {
		return PacketInfo{}, E.New("IPv6 packet too short")
	}
	if packet[6] != 58 {
		return PacketInfo{}, E.New("IPv6 packet is not ICMP")
	}
	sourceIP, ok := netip.AddrFromSlice(packet[8:24])
	if !ok {
		return PacketInfo{}, E.New("invalid IPv6 source address")
	}
	destinationIP, ok := netip.AddrFromSlice(packet[24:40])
	if !ok {
		return PacketInfo{}, E.New("invalid IPv6 destination address")
	}
	return PacketInfo{
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

func MaxEncodedPacketLen(WireVersion WireVersion, traceContext TraceContext) int {
	limit := protocol.MaxV3UDPPayloadLen
	switch WireVersion {
	case WireV2:
		limit -= protocol.TypeIDLength
		if traceContext.Traced {
			limit -= len(traceContext.Identity)
		}
	case WireV3:
		limit -= 1
	default:
		return 0
	}
	if limit < 0 {
		return 0
	}
	return limit
}

func BuildTTLExceededPacket(packetInfo PacketInfo) ([]byte, error) {
	switch packetInfo.IPVersion {
	case 4:
		return buildIPv4TTLExceededPacket(packetInfo)
	case 6:
		return buildIPv6TTLExceededPacket(packetInfo)
	default:
		return nil, E.New("unsupported IP version: ", packetInfo.IPVersion)
	}
}

func buildIPv4TTLExceededPacket(packetInfo PacketInfo) ([]byte, error) {
	const headerLen = 20
	if !packetInfo.SourceIP.Is4() || !packetInfo.Destination.Is4() {
		return nil, E.New("TTL exceeded packet requires IPv4 addresses")
	}

	quotedLength := min(len(packetInfo.RawPacket), IPv4TTLExceededQuoteLen)
	packet := make([]byte, headerLen+ErrorHeaderLen+quotedLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = defaultPacketTTL
	packet[9] = 1
	copy(packet[12:16], packetInfo.Destination.AsSlice())
	copy(packet[16:20], packetInfo.SourceIP.AsSlice())
	packet[20] = V4TypeTimeExceeded
	packet[21] = 0
	copy(packet[headerLen+ErrorHeaderLen:], packetInfo.RawPacket[:quotedLength])
	binary.BigEndian.PutUint16(packet[22:24], checksum(packet[20:], 0))
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerLen], 0))
	return packet, nil
}

func buildIPv6TTLExceededPacket(packetInfo PacketInfo) ([]byte, error) {
	const headerLen = 40
	if !packetInfo.SourceIP.Is6() || !packetInfo.Destination.Is6() {
		return nil, E.New("TTL exceeded packet requires IPv6 addresses")
	}

	quotedLength := min(len(packetInfo.RawPacket), IPv6TTLExceededQuoteLen)
	packet := make([]byte, headerLen+ErrorHeaderLen+quotedLength)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(ErrorHeaderLen+quotedLength))
	packet[6] = 58
	packet[7] = defaultPacketTTL
	copy(packet[8:24], packetInfo.Destination.AsSlice())
	copy(packet[24:40], packetInfo.SourceIP.AsSlice())
	packet[40] = V6TypeTimeExceeded
	packet[41] = 0
	copy(packet[headerLen+ErrorHeaderLen:], packetInfo.RawPacket[:quotedLength])
	binary.BigEndian.PutUint16(packet[42:44], checksum(packet[40:], ipv6PseudoHeaderChecksum(packetInfo.Destination, packetInfo.SourceIP, uint32(ErrorHeaderLen+quotedLength), 58)))
	return packet, nil
}

func EncodeDatagram(packet []byte, WireVersion WireVersion, traceContext TraceContext) ([]byte, error) {
	switch WireVersion {
	case WireV2:
		return encodeV2Datagram(packet, traceContext)
	case WireV3:
		return EncodeV3Datagram(packet)
	default:
		return nil, E.New("unsupported icmp wire version: ", WireVersion)
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

func encodeV2Datagram(packet []byte, _ TraceContext) ([]byte, error) {
	data := make([]byte, 0, len(packet)+1)
	data = append(data, packet...)
	data = append(data, byte(protocol.DatagramV2TypeIP))
	return data, nil
}

func EncodeV3Datagram(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, E.New("icmp payload is missing")
	}
	if len(packet) > MaxPayloadLen {
		return nil, E.New("icmp payload is too large")
	}
	data := make([]byte, 0, len(packet)+1)
	data = append(data, byte(protocol.DatagramV3TypeICMP))
	data = append(data, packet...)
	return data, nil
}
