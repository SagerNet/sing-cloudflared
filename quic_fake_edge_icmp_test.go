package cloudflared

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-cloudflared/internal/transport"
	"github.com/sagernet/sing-cloudflared/internal/tunnelrpc"
	pkgicmp "github.com/sagernet/sing-cloudflared/pkg/icmp"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

type fakeQUICEdge struct {
	listener *quic.Listener
	server   *registrationTestServer
	caPEM    []byte

	ctx    context.Context
	cancel context.CancelFunc

	connAccess sync.Mutex
	conn       *quic.Conn

	connCh chan *quic.Conn
	errCh  chan error
}

func newFakeQUICEdge(t *testing.T) *fakeQUICEdge {
	t.Helper()

	caCertificate, caPrivateKey, caPEM := createTestCertificateAuthority(t, "fake quic edge root")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{createTestServerCertificate(t, caCertificate, caPrivateKey, transport.QuicEdgeSNI)},
		NextProtos:   []string{transport.QuicEdgeALPN},
	}, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	edge := &fakeQUICEdge{
		listener: listener,
		server: &registrationTestServer{
			registerCalls: make(chan registrationCall, 1),
			unregisterCh:  make(chan struct{}, 1),
			result: &RegistrationResult{
				ConnectionID:            uuid.New(),
				Location:                "TEST",
				TunnelIsRemotelyManaged: true,
			},
		},
		caPEM:  caPEM,
		ctx:    ctx,
		cancel: cancel,
		connCh: make(chan *quic.Conn, 1),
		errCh:  make(chan error, 1),
	}
	go edge.serve()
	t.Cleanup(func() {
		edge.Close()
	})
	return edge
}

func (e *fakeQUICEdge) serve() {
	conn, err := e.listener.Accept(e.ctx)
	if err != nil {
		select {
		case e.errCh <- err:
		default:
		}
		return
	}

	e.connAccess.Lock()
	e.conn = conn
	e.connAccess.Unlock()

	select {
	case e.connCh <- conn:
	default:
	}

	stream, err := conn.AcceptStream(e.ctx)
	if err != nil {
		select {
		case e.errCh <- err:
		default:
		}
		return
	}

	rpcTransport := safeTransport(newStreamReadWriteCloser(stream))
	rpcConn := newRPCServerConn(rpcTransport, tunnelrpc.RegistrationServer_ServerToClient(e.server).Client)
	defer rpcConn.Close()
	defer rpcTransport.Close()

	<-e.ctx.Done()
}

func (e *fakeQUICEdge) waitForConn(t *testing.T) *quic.Conn {
	t.Helper()
	conn, err := e.waitForConnWithTimeout(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func (e *fakeQUICEdge) waitForConnWithTimeout(timeout time.Duration) (*quic.Conn, error) {
	e.connAccess.Lock()
	if e.conn != nil {
		conn := e.conn
		e.connAccess.Unlock()
		return conn, nil
	}
	e.connAccess.Unlock()

	select {
	case conn := <-e.connCh:
		e.connAccess.Lock()
		e.conn = conn
		e.connAccess.Unlock()
		return conn, nil
	case err := <-e.errCh:
		return nil, err
	case <-time.After(timeout):
		return nil, context.DeadlineExceeded
	}
}

func (e *fakeQUICEdge) waitForRegistration(t *testing.T) registrationCall {
	t.Helper()
	select {
	case call := <-e.server.registerCalls:
		return call
	case err := <-e.errCh:
		t.Fatalf("fake edge failed before registration: %v", err)
		return registrationCall{}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for registration call")
		return registrationCall{}
	}
}

func (e *fakeQUICEdge) sendDatagram(t *testing.T, data []byte) {
	t.Helper()
	if err := e.waitForConn(t).SendDatagram(data); err != nil {
		t.Fatalf("send datagram from fake edge: %v", err)
	}
}

func (e *fakeQUICEdge) receiveDatagram(timeout time.Duration) ([]byte, error) {
	conn, err := e.waitForConnWithTimeout(timeout)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return conn.ReceiveDatagram(ctx)
}

func (e *fakeQUICEdge) Close() {
	e.cancel()
	e.connAccess.Lock()
	if e.conn != nil {
		_ = e.conn.CloseWithError(0, "")
	}
	e.connAccess.Unlock()
	_ = e.listener.Close()
}

func withFakeQUICEdgeDiscovery(t *testing.T, edge *fakeQUICEdge) {
	t.Helper()

	originalDiscoverEdge := discoverEdge
	originalRootCertPool := transport.CloudflareRootCertPool
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(edge.caPEM) {
		t.Fatal("failed to append fake edge CA")
	}

	edgeAddr := edge.listener.Addr().(*net.UDPAddr)
	discoverEdge = func(ctx context.Context, region string, controlDialer N.Dialer) ([][]*EdgeAddr, error) {
		return [][]*EdgeAddr{{
			{
				TCP:       &net.TCPAddr{IP: edgeAddr.IP, Port: edgeAddr.Port},
				UDP:       edgeAddr,
				IPVersion: 4,
			},
		}}, nil
	}
	transport.CloudflareRootCertPool = func() (*x509.CertPool, error) {
		return pool, nil
	}

	t.Cleanup(func() {
		discoverEdge = originalDiscoverEdge
		transport.CloudflareRootCertPool = originalRootCertPool
	})
}

func newFakeEdgeQUICService(t *testing.T, version string, icmpHandler ICMPHandler) *Service {
	t.Helper()

	serviceInstance, err := NewService(ServiceOptions{
		Logger:           logger.NOP(),
		ConnectionDialer: N.SystemDialer,
		TunnelDialer:     N.SystemDialer,
		ICMPHandler:      icmpHandler,
		Token:            testToken(t),
		HAConnections:    1,
		Protocol:         protocolQUIC,
		EdgeIPVersion:    4,
		DatagramVersion:  version,
		GracePeriod:      time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = serviceInstance.Close()
	})
	return serviceInstance
}

func TestServiceQUICFakeEdgeICMPRoundTrip(t *testing.T) {
	source := netip.MustParseAddr("127.0.0.2")
	destination := netip.MustParseAddr("127.0.0.1")
	requireDirectHandlerLoopbackCapability(t, source, destination)

	testCases := []struct {
		name            string
		version         string
		traced          bool
		handler         ICMPHandler
		expectReply     bool
		expectV3Feature bool
	}{
		{
			name:        "v2",
			version:     defaultDatagramVersion,
			handler:     pkgicmp.NewDirectHandler(logger.NOP()),
			expectReply: true,
		},
		{
			name:            "v3",
			version:         datagramVersionV3,
			handler:         pkgicmp.NewDirectHandler(logger.NOP()),
			expectReply:     true,
			expectV3Feature: true,
		},
		{
			name:        "v2 traced",
			version:     defaultDatagramVersion,
			traced:      true,
			handler:     pkgicmp.NewDirectHandler(logger.NOP()),
			expectReply: true,
		},
		{
			name:        "nil handler drops request",
			version:     defaultDatagramVersion,
			handler:     nil,
			expectReply: false,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			edge := newFakeQUICEdge(t)
			withFakeQUICEdgeDiscovery(t, edge)

			serviceInstance := newFakeEdgeQUICService(t, testCase.version, testCase.handler)
			if err := serviceInstance.Start(); err != nil {
				t.Fatal(err)
			}

			registerCall := edge.waitForRegistration(t)
			hasV3Feature := false
			for _, feature := range registerCall.options.Client.Features {
				if feature == "support_datagram_v3_2" {
					hasV3Feature = true
					break
				}
			}
			if hasV3Feature != testCase.expectV3Feature {
				t.Fatalf("unexpected v3 feature flag state %v for features %#v", hasV3Feature, registerCall.options.Client.Features)
			}

			request := buildLoopbackICMPRequest(source, destination, 0x301, 7)
			edge.sendDatagram(t, encodeInboundICMPDatagram(t, testCase.version, request, testCase.traced))

			reply, err := edge.receiveDatagram(1500 * time.Millisecond)
			if !testCase.expectReply {
				if err == nil {
					t.Fatalf("expected no ICMP reply datagram, got %x", reply)
				}
				return
			}
			if err != nil {
				t.Fatalf("receive ICMP reply datagram: %v", err)
			}

			v2Type, v3Type, info := parseICMPReplyDatagram(t, testCase.version, reply)
			switch testCase.version {
			case datagramVersionV3:
				if v3Type != DatagramV3TypeICMP {
					t.Fatalf("expected V3 ICMP datagram, got %d", v3Type)
				}
			default:
				if v2Type != DatagramV2TypeIP {
					t.Fatalf("expected V2 IP datagram, got %d", v2Type)
				}
			}
			if !info.IsEchoReply() {
				t.Fatalf("expected echo reply, got type=%d code=%d", info.ICMPType, info.ICMPCode)
			}
			if info.SourceIP != destination || info.Destination != source {
				t.Fatalf("unexpected reply routing src=%s dst=%s", info.SourceIP, info.Destination)
			}
			if info.Identifier != 0x301 || info.Sequence != 7 {
				t.Fatalf("unexpected reply id/seq %d/%d", info.Identifier, info.Sequence)
			}
		})
	}
}
