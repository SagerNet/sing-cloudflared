package cloudflared

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	edgeSRVService = "v2-origintunneld"
	edgeSRVProto   = "tcp"
	edgeSRVName    = "argotunnel.com"

	dotServerName = "cloudflare-dns.com"
	dotServerAddr = "1.1.1.1:853"
	dotTimeout    = 15 * time.Second
)

var (
	lookupEdgeSRVFn        = lookupEdgeSRV
	lookupEdgeSRVWithDoTFn = lookupEdgeSRVWithDoT
	edgeLookupSRV          = net.LookupSRV
	edgeLookupIP           = net.LookupIP
)

func getRegionalServiceName(region string) string {
	if region == "" {
		return edgeSRVService
	}
	return region + "-" + edgeSRVService
}

type EdgeAddr struct {
	TCP       *net.TCPAddr
	UDP       *net.UDPAddr
	IPVersion int // 4 or 6
}

func DiscoverEdge(ctx context.Context, region string, controlDialer N.Dialer) ([][]*EdgeAddr, error) {
	regions, err := lookupEdgeSRVFn(region)
	if err != nil {
		regions, err = lookupEdgeSRVWithDoTFn(ctx, region, controlDialer)
		if err != nil {
			return nil, E.Cause(err, "edge discovery")
		}
	}
	if len(regions) == 0 {
		return nil, E.New("edge discovery: no edge addresses found")
	}
	return regions, nil
}

func lookupEdgeSRV(region string) ([][]*EdgeAddr, error) {
	_, addrs, err := edgeLookupSRV(getRegionalServiceName(region), edgeSRVProto, edgeSRVName)
	if err != nil {
		return nil, err
	}
	return resolveSRVRecords(addrs)
}

func lookupEdgeSRVWithDoT(ctx context.Context, region string, controlDialer N.Dialer) ([][]*EdgeAddr, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := controlDialer.DialContext(ctx, "tcp", M.ParseSocksaddr(dotServerAddr))
			if err != nil {
				return nil, err
			}
			return tls.Client(conn, &tls.Config{ServerName: dotServerName}), nil
		},
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dotTimeout)
	defer cancel()
	_, addrs, err := resolver.LookupSRV(lookupCtx, getRegionalServiceName(region), edgeSRVProto, edgeSRVName)
	if err != nil {
		return nil, err
	}
	return resolveSRVRecords(addrs)
}

func resolveSRVRecords(records []*net.SRV) ([][]*EdgeAddr, error) {
	var regions [][]*EdgeAddr
	for _, record := range records {
		ips, err := edgeLookupIP(record.Target)
		if err != nil {
			return nil, E.Cause(err, "resolve SRV target: ", record.Target)
		}
		if len(ips) == 0 {
			continue
		}
		edgeAddrs := make([]*EdgeAddr, 0, len(ips))
		for _, ip := range ips {
			ipVersion := 6
			if ip.To4() != nil {
				ipVersion = 4
			}
			edgeAddrs = append(edgeAddrs, &EdgeAddr{
				TCP:       &net.TCPAddr{IP: ip, Port: int(record.Port)},
				UDP:       &net.UDPAddr{IP: ip, Port: int(record.Port)},
				IPVersion: ipVersion,
			})
		}
		regions = append(regions, edgeAddrs)
	}
	return regions, nil
}

func FilterByIPVersion(regions [][]*EdgeAddr, version int) [][]*EdgeAddr {
	if version == 0 {
		return regions
	}
	var filtered [][]*EdgeAddr
	for _, region := range regions {
		var addrs []*EdgeAddr
		for _, addr := range region {
			if addr.IPVersion == version {
				addrs = append(addrs, addr)
			}
		}
		if len(addrs) > 0 {
			filtered = append(filtered, addrs)
		}
	}
	return filtered
}
