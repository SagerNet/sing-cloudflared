package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/dns/dnsmessage"
)

func restoreEdgeDiscoveryHooks(t *testing.T) {
	t.Helper()

	originalLookup := LookupEdgeSRVFn
	originalLookupDoT := LookupEdgeSRVWithDoTFn
	originalNetLookupSRV := EdgeLookupSRV
	originalNetLookupIP := EdgeLookupIP
	originalDoTDestination := EdgeDoTDestination
	originalDoTTLSClient := EdgeDoTTLSClient
	t.Cleanup(func() {
		LookupEdgeSRVFn = originalLookup
		LookupEdgeSRVWithDoTFn = originalLookupDoT
		EdgeLookupSRV = originalNetLookupSRV
		EdgeLookupIP = originalNetLookupIP
		EdgeDoTDestination = originalDoTDestination
		EdgeDoTTLSClient = originalDoTTLSClient
	})
}

func startTestDoTServer(t *testing.T, answers []*net.SRV) (string, []byte, <-chan string, <-chan string, func() error) {
	t.Helper()

	caCertificate, caPrivateKey, caPEM := createTestCertificateAuthority(t, "test dot root")
	serverCertificate := createTestServerCertificate(t, caCertificate, caPrivateKey, DotServerName)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	serverNameCh := make(chan string, 1)
	questionNameCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		defer close(errCh)

		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{serverCertificate},
		})
		defer tlsConn.Close()

		err = tlsConn.Handshake()
		if err != nil {
			errCh <- err
			return
		}

		serverNameCh <- tlsConn.ConnectionState().ServerName

		request, err := readDNSMessageOverTCP(tlsConn)
		if err != nil {
			errCh <- err
			return
		}

		var parser dnsmessage.Parser
		header, err := parser.Start(request)
		if err != nil {
			errCh <- err
			return
		}
		questions, err := parser.AllQuestions()
		if err != nil {
			errCh <- err
			return
		}
		if len(questions) != 1 {
			errCh <- errors.New("unexpected DNS question count")
			return
		}
		questionNameCh <- questions[0].Name.String()

		response, err := buildTestSRVResponse(header, questions[0], answers)
		if err != nil {
			errCh <- err
			return
		}
		_, err = tlsConn.Write(response)
		if err != nil {
			errCh <- err
			return
		}

		errCh <- nil
	}()

	return listener.Addr().String(), caPEM, serverNameCh, questionNameCh, func() error {
		_ = listener.Close()
		return <-errCh
	}
}

func readDNSMessageOverTCP(conn net.Conn) ([]byte, error) {
	var sizeBytes [2]byte
	_, err := io.ReadFull(conn, sizeBytes[:])
	if err != nil {
		return nil, err
	}
	message := make([]byte, binary.BigEndian.Uint16(sizeBytes[:]))
	_, err = io.ReadFull(conn, message)
	if err != nil {
		return nil, err
	}
	return message, nil
}

func buildTestSRVResponse(header dnsmessage.Header, question dnsmessage.Question, answers []*net.SRV) ([]byte, error) {
	builder := dnsmessage.NewBuilder(make([]byte, 2), dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: true,
	})
	builder.EnableCompression()

	err := builder.StartQuestions()
	if err != nil {
		return nil, err
	}
	err = builder.Question(question)
	if err != nil {
		return nil, err
	}
	err = builder.StartAnswers()
	if err != nil {
		return nil, err
	}

	for _, answer := range answers {
		target, err := dnsmessage.NewName(answer.Target)
		if err != nil {
			return nil, err
		}
		err = builder.SRVResource(dnsmessage.ResourceHeader{
			Name:  question.Name,
			Type:  dnsmessage.TypeSRV,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		}, dnsmessage.SRVResource{
			Priority: answer.Priority,
			Weight:   answer.Weight,
			Port:     answer.Port,
			Target:   target,
		})
		if err != nil {
			return nil, err
		}
	}

	message, err := builder.Finish()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(message[:2], uint16(len(message)-2))
	return message, nil
}

type testDialer struct {
	dialContext func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
}

func (d *testDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dialContext(ctx, network, destination)
}

func (d *testDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestDiscoverEdgeFallsBackToDoT(t *testing.T) {
	restoreEdgeDiscoveryHooks(t)

	expected := [][]*EdgeAddr{{
		{TCP: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7844}, UDP: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7844}, IPVersion: 4},
	}}
	LookupEdgeSRVFn = func(region string) ([][]*EdgeAddr, error) {
		return nil, errors.New("system dns failed")
	}
	LookupEdgeSRVWithDoTFn = func(ctx context.Context, region string, controlDialer N.Dialer) ([][]*EdgeAddr, error) {
		if region != "us" {
			t.Fatalf("unexpected region %q", region)
		}
		return expected, nil
	}

	regions, err := DiscoverEdge(context.Background(), "us", N.SystemDialer)
	if err != nil {
		t.Fatal(err)
	}
	if len(regions) != 1 || len(regions[0]) != 1 || regions[0][0].IPVersion != 4 {
		t.Fatalf("unexpected regions %#v", regions)
	}
}

func TestLookupEdgeSRVWithDoTUsesTLSAndResolvesSRVRecords(t *testing.T) {
	restoreEdgeDiscoveryHooks(t)

	serverAddr, caPEM, serverNameCh, questionNameCh, shutdown := startTestDoTServer(t, []*net.SRV{{
		Target:   "edge.example.com.",
		Port:     7844,
		Priority: 1,
		Weight:   1,
	}})
	t.Cleanup(func() {
		err := shutdown()
		if err != nil {
			t.Error(err)
		}
	})

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("expected test CA to parse")
	}
	EdgeDoTTLSClient = func(conn net.Conn) net.Conn {
		return tls.Client(conn, &tls.Config{
			ServerName: DotServerName,
			RootCAs:    pool,
		})
	}

	var dialedDestination M.Socksaddr
	dialer := &testDialer{
		dialContext: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			dialedDestination = destination
			var d net.Dialer
			return d.DialContext(ctx, "tcp", serverAddr)
		},
	}

	EdgeLookupIP = func(host string) ([]net.IP, error) {
		if host != "edge.example.com." {
			t.Fatalf("unexpected lookup host %q", host)
		}
		return []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("2001:db8::1")}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	regions, err := lookupEdgeSRVWithDoT(ctx, "us", dialer)
	if err != nil {
		t.Fatal(err)
	}

	if dialedDestination.String() != DotServerAddr {
		t.Fatalf("unexpected DoT destination %s", dialedDestination)
	}

	select {
	case serverName := <-serverNameCh:
		if serverName != DotServerName {
			t.Fatalf("unexpected DoT TLS server name %q", serverName)
		}
	case <-time.After(time.Second):
		t.Fatal("expected DoT server name to be captured")
	}

	select {
	case questionName := <-questionNameCh:
		if questionName != "_us-v2-origintunneld._tcp.argotunnel.com." {
			t.Fatalf("unexpected SRV lookup name %q", questionName)
		}
	case <-time.After(time.Second):
		t.Fatal("expected DoT question name to be captured")
	}

	if len(regions) != 1 || len(regions[0]) != 2 {
		t.Fatalf("unexpected resolved regions %#v", regions)
	}
	if regions[0][0].TCP.Port != 7844 || regions[0][1].UDP.Port != 7844 {
		t.Fatalf("unexpected resolved ports %#v", regions[0])
	}
	if regions[0][0].IPVersion != 4 || regions[0][1].IPVersion != 6 {
		t.Fatalf("unexpected resolved IP versions %#v", regions[0])
	}
}

func TestDiscoverEdgeReturnsFallbackError(t *testing.T) {
	restoreEdgeDiscoveryHooks(t)

	LookupEdgeSRVFn = func(region string) ([][]*EdgeAddr, error) {
		return nil, errors.New("system dns failed")
	}
	LookupEdgeSRVWithDoTFn = func(ctx context.Context, region string, controlDialer N.Dialer) ([][]*EdgeAddr, error) {
		return nil, errors.New("dot failed")
	}

	_, err := DiscoverEdge(context.Background(), "", N.SystemDialer)
	if err == nil || err.Error() != "edge discovery: dot failed" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestDiscoverEdgeRejectsEmptyRegions(t *testing.T) {
	restoreEdgeDiscoveryHooks(t)

	LookupEdgeSRVFn = func(region string) ([][]*EdgeAddr, error) {
		return nil, nil
	}

	_, err := DiscoverEdge(context.Background(), "", N.SystemDialer)
	if err == nil || err.Error() != "edge discovery: no edge addresses found" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestResolveSRVRecordsPropagatesLookupError(t *testing.T) {
	restoreEdgeDiscoveryHooks(t)

	EdgeLookupIP = func(host string) ([]net.IP, error) {
		return nil, errors.New("lookup ip failed")
	}

	_, err := ResolveSRVRecords([]*net.SRV{{Target: "edge.example.com", Port: 7844}})
	if err == nil || err.Error() != "resolve SRV target: edge.example.com: lookup ip failed" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestResolveSRVRecordsSkipsEmptyTargets(t *testing.T) {
	restoreEdgeDiscoveryHooks(t)

	EdgeLookupIP = func(host string) ([]net.IP, error) {
		switch host {
		case "empty.example.com":
			return nil, nil
		case "edge.example.com":
			return []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("2001:db8::1")}, nil
		default:
			t.Fatalf("unexpected host %q", host)
			return nil, nil
		}
	}

	regions, err := ResolveSRVRecords([]*net.SRV{
		{Target: "empty.example.com", Port: 7844},
		{Target: "edge.example.com", Port: 7844},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(regions) != 1 || len(regions[0]) != 2 {
		t.Fatalf("unexpected resolved regions %#v", regions)
	}
	if regions[0][0].IPVersion != 4 || regions[0][1].IPVersion != 6 {
		t.Fatalf("unexpected IP versions %#v", regions[0])
	}
}
