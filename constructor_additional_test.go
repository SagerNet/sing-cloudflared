package cloudflared

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/google/uuid"
)

type constructorDialer struct {
	dialContext  func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	listenPacket func(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
}

func (d *constructorDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if d.dialContext == nil {
		return nil, errors.New("unexpected dial")
	}
	return d.dialContext(ctx, network, destination)
}

func (d *constructorDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if d.listenPacket == nil {
		return nil, errors.New("unexpected listen packet")
	}
	return d.listenPacket(ctx, destination)
}

func createTestCertificateAuthority(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, privateKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func createTestServerCertificate(t *testing.T, caCertificate *x509.Certificate, caPrivateKey *rsa.PrivateKey, commonName string) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:              []string{commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &privateKey.PublicKey, caPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}
}

func TestNewHTTP2ConnectionDialError(t *testing.T) {
	t.Parallel()

	serviceInstance := &Service{
		tunnelDialer: &constructorDialer{
			dialContext: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
				return nil, errors.New("dial failed")
			},
		},
	}

	_, err := NewHTTP2Connection(
		context.Background(),
		&EdgeAddr{TCP: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7844}},
		0,
		Credentials{TunnelID: uuid.New()},
		uuid.New(),
		nil,
		0,
		time.Second,
		serviceInstance,
		nil,
	)
	if err == nil || err.Error() != "dial edge TCP: dial failed" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestNewHTTP2ConnectionTLSHandshakeFailure(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("not tls"))
	}()

	serviceInstance := &Service{
		tunnelDialer: &constructorDialer{
			dialContext: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
				var netDialer net.Dialer
				return netDialer.DialContext(ctx, "tcp", listener.Addr().String())
			},
		},
	}

	_, err = NewHTTP2Connection(
		context.Background(),
		&EdgeAddr{TCP: listener.Addr().(*net.TCPAddr)},
		0,
		Credentials{TunnelID: uuid.New()},
		uuid.New(),
		nil,
		0,
		time.Second,
		serviceInstance,
		nil,
	)
	if err == nil || len(err.Error()) < len("TLS handshake:") || err.Error()[:len("TLS handshake:")] != "TLS handshake:" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestNewHTTP2ConnectionSuccess(t *testing.T) {
	originalLoader := loadCloudflareRootCertPool
	defer func() {
		loadCloudflareRootCertPool = originalLoader
	}()

	caCertificate, caPrivateKey, caPEM := createTestCertificateAuthority(t, "test edge root")
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPEM)
	loadCloudflareRootCertPool = func() (*x509.CertPool, error) {
		return certPool, nil
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{createTestServerCertificate(t, caCertificate, caPrivateKey, h2EdgeSNI)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			accepted <- conn
		}
	}()

	serviceInstance := &Service{
		tunnelDialer: &constructorDialer{
			dialContext: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
				var netDialer net.Dialer
				return netDialer.DialContext(ctx, "tcp", listener.Addr().String())
			},
		},
	}

	connection, err := NewHTTP2Connection(
		context.Background(),
		&EdgeAddr{TCP: listener.Addr().(*net.TCPAddr)},
		1,
		Credentials{TunnelID: uuid.New()},
		uuid.New(),
		[]string{"serialized_headers"},
		2,
		5*time.Second,
		serviceInstance,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
	})

	if connection.server == nil || connection.server.MaxConcurrentStreams != math.MaxUint32 {
		t.Fatalf("unexpected http2 server %#v", connection.server)
	}

	select {
	case conn := <-accepted:
		t.Cleanup(func() { _ = conn.Close() })
	case <-time.After(time.Second):
		t.Fatal("expected TLS listener accept")
	}
}

func TestNewQUICConnectionListenPacketError(t *testing.T) {
	t.Parallel()

	_, err := NewQUICConnection(
		context.Background(),
		&EdgeAddr{UDP: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7844}, IPVersion: 4},
		0,
		Credentials{TunnelID: uuid.New()},
		uuid.New(),
		defaultDatagramVersion,
		nil,
		0,
		time.Second,
		&constructorDialer{
			listenPacket: func(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
				return nil, errors.New("listen failed")
			},
		},
		nil,
		nil,
	)
	if err == nil || err.Error() != "listen UDP for QUIC edge: listen failed" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestNewQUICConnectionDialError(t *testing.T) {
	t.Parallel()

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)
	_ = serverConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = NewQUICConnection(
		ctx,
		&EdgeAddr{UDP: serverAddr, IPVersion: 4},
		0,
		Credentials{TunnelID: uuid.New()},
		uuid.New(),
		defaultDatagramVersion,
		nil,
		0,
		time.Second,
		&constructorDialer{
			listenPacket: func(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
				return net.ListenPacket("udp", "127.0.0.1:0")
			},
		},
		nil,
		nil,
	)
	if err == nil || err.Error()[:15] != "dial QUIC edge:" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestNewQUICConnectionSuccess(t *testing.T) {
	originalLoader := loadCloudflareRootCertPool
	defer func() {
		loadCloudflareRootCertPool = originalLoader
	}()

	caCertificate, caPrivateKey, caPEM := createTestCertificateAuthority(t, "test edge root")
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPEM)
	loadCloudflareRootCertPool = func() (*x509.CertPool, error) {
		return certPool, nil
	}

	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	transport := &quic.Transport{Conn: udpListener, ConnectionIDLength: 8}
	listener, err := transport.Listen(&tls.Config{
		Certificates: []tls.Certificate{createTestServerCertificate(t, caCertificate, caPrivateKey, quicEdgeSNI)},
		NextProtos:   []string{quicEdgeALPN},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer udpListener.Close()

	shutdown := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept(context.Background())
		if acceptErr == nil {
			<-shutdown
			_ = conn.CloseWithError(0, "server shutdown")
		}
	}()

	connection, err := NewQUICConnection(
		context.Background(),
		&EdgeAddr{UDP: udpListener.LocalAddr().(*net.UDPAddr), IPVersion: 4},
		1,
		Credentials{TunnelID: uuid.New()},
		uuid.New(),
		datagramVersionV3,
		[]string{"support_datagram_v3_2"},
		2,
		5*time.Second,
		&constructorDialer{
			listenPacket: func(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
				return net.ListenPacket("udp", "127.0.0.1:0")
			},
		},
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if connection.conn == nil || connection.datagramVersion != datagramVersionV3 {
		t.Fatalf("unexpected quic connection %#v", connection)
	}
	_ = connection.Close()
	close(shutdown)
}

func TestNewQUICConnectionAppliesPostQuantumCurvePreferences(t *testing.T) {
	originalLoader := loadCloudflareRootCertPool
	originalDialQUIC := dialQUIC
	defer func() {
		loadCloudflareRootCertPool = originalLoader
		dialQUIC = originalDialQUIC
	}()

	loadCloudflareRootCertPool = func() (*x509.CertPool, error) {
		return x509.NewCertPool(), nil
	}

	var capturedCurves []tls.CurveID
	dialQUIC = func(ctx context.Context, udpConn *net.UDPConn, addr *net.UDPAddr, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
		capturedCurves = append([]tls.CurveID(nil), tlsConfig.CurvePreferences...)
		_ = udpConn.Close()
		return nil, errors.New("dial failed")
	}

	_, err := NewQUICConnection(
		context.Background(),
		&EdgeAddr{UDP: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7844}, IPVersion: 4},
		0,
		Credentials{TunnelID: uuid.New()},
		uuid.New(),
		defaultDatagramVersion,
		[]string{featurePostQuantum},
		0,
		time.Second,
		&constructorDialer{
			listenPacket: func(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
				return net.ListenPacket("udp", "127.0.0.1:0")
			},
		},
		nil,
		nil,
	)
	if err == nil || err.Error()[:15] != "dial QUIC edge:" {
		t.Fatalf("unexpected error %v", err)
	}
	if len(capturedCurves) != 1 || capturedCurves[0] != x25519MLKEM768PQKex {
		t.Fatalf("unexpected captured post-quantum curves %#v", capturedCurves)
	}
}
