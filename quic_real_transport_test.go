package cloudflared

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"

	"github.com/sagernet/sing-cloudflared/tunnelrpc"
	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"
)

func newTestQUICEdgeListener(t *testing.T) (*quic.Listener, []byte) {
	t.Helper()

	caCertificate, caPrivateKey, caPEM := createTestCertificateAuthority(t, "test quic edge root")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{createTestServerCertificate(t, caCertificate, caPrivateKey, quicEdgeSNI)},
		NextProtos:   []string{quicEdgeALPN},
	}, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return listener, caPEM
}

func readConnectResponseFromStream(t *testing.T, stream io.Reader) *ConnectResponse {
	t.Helper()

	streamType, err := ReadStreamSignature(stream)
	if err != nil {
		t.Fatal(err)
	}
	if streamType != StreamTypeData {
		t.Fatalf("unexpected stream type %v", streamType)
	}
	version := make([]byte, len(protocolVersion))
	if _, err := io.ReadFull(stream, version); err != nil {
		t.Fatal(err)
	}
	if string(version) != protocolVersion {
		t.Fatalf("unexpected protocol version %q", version)
	}
	message, err := capnp.NewDecoder(stream).Decode()
	if err != nil {
		t.Fatal(err)
	}
	root, err := tunnelrpc.ReadRootConnectResponse(message)
	if err != nil {
		t.Fatal(err)
	}
	var response ConnectResponse
	if err := pogs.Extract(&response, tunnelrpc.ConnectResponse_TypeID, root.Struct); err != nil {
		t.Fatal(err)
	}
	return &response
}

func writeConnectRequestToStream(t *testing.T, stream io.Writer, request *ConnectRequest) {
	t.Helper()

	if _, err := stream.Write(encodeConnectRequestForTest(t, request)); err != nil {
		t.Fatal(err)
	}
}

func responseMetadataValue(metadata []Metadata, key string) string {
	for _, entry := range metadata {
		if entry.Key == key {
			return entry.Val
		}
	}
	return ""
}

func TestQUICConnectionRealTransportEndToEnd(t *testing.T) {
	originalLoader := loadCloudflareRootCertPool
	defer func() {
		loadCloudflareRootCertPool = originalLoader
	}()

	listener, caPEM := newTestQUICEdgeListener(t)
	defer listener.Close()

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caPEM)
	loadCloudflareRootCertPool = func() (*x509.CertPool, error) {
		return certPool, nil
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/http":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			w.Header().Set("X-Origin", "quic")
			_, _ = w.Write(body)
		case "/ws":
			conn, _, _, err := ws.UpgradeHTTP(r, w)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			for {
				payload, opCode, err := wsutil.ReadClientData(conn)
				if err != nil {
					return
				}
				if err := wsutil.WriteServerMessage(conn, opCode, payload); err != nil {
					return
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer origin.Close()

	tcpListener := startEchoListener(t)
	defer tcpListener.Close()

	serviceInstance := newSpecialService(t)
	serviceInstance.configManager.activeConfig = RuntimeConfig{
		Ingress: []compiledIngressRule{{
			Service: mustResolvedService(t, origin.URL),
		}},
	}

	registrationServer := &registrationTestServer{
		registerCalls: make(chan registrationCall, 1),
		unregisterCh:  make(chan struct{}, 1),
		result: &RegistrationResult{
			ConnectionID:            uuid.New(),
			Location:                "SIN",
			TunnelIsRemotelyManaged: true,
		},
	}

	edgeDone := make(chan error, 1)
	unregisterDone := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			edgeDone <- err
			return
		}
		defer conn.CloseWithError(0, "")

		controlStream, err := conn.AcceptStream(ctx)
		if err != nil {
			edgeDone <- err
			return
		}
		controlTransport := safeTransport(newStreamReadWriteCloser(controlStream))
		controlConn := newRPCServerConn(controlTransport, tunnelrpc.RegistrationServer_ServerToClient(registrationServer).Client)
		defer func() {
			_ = controlConn.Close()
			_ = controlTransport.Close()
		}()

		select {
		case <-registrationServer.registerCalls:
		case <-ctx.Done():
			edgeDone <- ctx.Err()
			return
		}

		httpStream, err := conn.OpenStream()
		if err != nil {
			edgeDone <- err
			return
		}
		httpBody := []byte("quic-http-body")
		writeConnectRequestToStream(t, httpStream, &ConnectRequest{
			Dest: "http://edge.example/http",
			Type: ConnectionTypeHTTP,
			Metadata: []Metadata{
				{Key: metadataHTTPMethod, Val: http.MethodPost},
				{Key: metadataHTTPHost, Val: "edge.example"},
				{Key: metadataHTTPHeader + ":Content-Length", Val: "14"},
			},
		})
		if _, err := httpStream.Write(httpBody); err != nil {
			edgeDone <- err
			return
		}
		httpResponse := readConnectResponseFromStream(t, httpStream)
		if httpResponse.Error != "" {
			edgeDone <- io.ErrUnexpectedEOF
			return
		}
		if got := responseMetadataValue(httpResponse.Metadata, metadataHTTPStatus); got != "200" {
			edgeDone <- io.ErrUnexpectedEOF
			return
		}
		if got := responseMetadataValue(httpResponse.Metadata, metadataHTTPHeader+":X-Origin"); got != "quic" {
			edgeDone <- io.ErrUnexpectedEOF
			return
		}
		readHTTPBody := make([]byte, len(httpBody))
		if _, err := io.ReadFull(httpStream, readHTTPBody); err != nil {
			edgeDone <- err
			return
		}
		if !bytes.Equal(readHTTPBody, httpBody) {
			edgeDone <- io.ErrUnexpectedEOF
			return
		}
		_ = httpStream.Close()

		websocketStream, err := conn.OpenStream()
		if err != nil {
			edgeDone <- err
			return
		}
		writeConnectRequestToStream(t, websocketStream, &ConnectRequest{
			Dest: "http://edge.example/ws",
			Type: ConnectionTypeWebsocket,
			Metadata: []Metadata{
				{Key: metadataHTTPMethod, Val: http.MethodGet},
				{Key: metadataHTTPHost, Val: "edge.example"},
				{Key: metadataHTTPHeader + ":Sec-WebSocket-Key", Val: "dGhlIHNhbXBsZSBub25jZQ=="},
			},
		})
		websocketResponse := readConnectResponseFromStream(t, websocketStream)
		if websocketResponse.Error != "" || responseMetadataValue(websocketResponse.Metadata, metadataHTTPStatus) != "101" {
			edgeDone <- io.ErrUnexpectedEOF
			return
		}
		if err := wsutil.WriteClientMessage(websocketStream, ws.OpBinary, []byte("ws-payload")); err != nil {
			edgeDone <- err
			return
		}
		websocketPayload, opCode, err := wsutil.ReadServerData(websocketStream)
		if err != nil {
			edgeDone <- err
			return
		}
		if opCode != ws.OpBinary || string(websocketPayload) != "ws-payload" {
			edgeDone <- io.ErrUnexpectedEOF
			return
		}
		_ = websocketStream.Close()

		tcpStream, err := conn.OpenStream()
		if err != nil {
			edgeDone <- err
			return
		}
		writeConnectRequestToStream(t, tcpStream, &ConnectRequest{
			Dest: tcpListener.Addr().String(),
			Type: ConnectionTypeTCP,
		})
		tcpResponse := readConnectResponseFromStream(t, tcpStream)
		if tcpResponse.Error != "" {
			edgeDone <- io.ErrUnexpectedEOF
			return
		}
		tcpPayload := []byte("tcp-payload")
		if _, err := tcpStream.Write(tcpPayload); err != nil {
			edgeDone <- err
			return
		}
		readTCPPayload := make([]byte, len(tcpPayload))
		if _, err := io.ReadFull(tcpStream, readTCPPayload); err != nil {
			edgeDone <- err
			return
		}
		if !bytes.Equal(readTCPPayload, tcpPayload) {
			edgeDone <- io.ErrUnexpectedEOF
			return
		}
		_ = tcpStream.Close()

		edgeDone <- nil
		select {
		case <-registrationServer.unregisterCh:
			unregisterDone <- nil
		case <-ctx.Done():
			unregisterDone <- ctx.Err()
		}
	}()

	onConnected := make(chan struct{}, 1)
	connection, err := NewQUICConnection(
		ctx,
		&EdgeAddr{UDP: listener.Addr().(*net.UDPAddr), IPVersion: 4},
		0,
		Credentials{TunnelID: uuid.New(), AccountTag: "test-account", TunnelSecret: []byte("secret")},
		uuid.New(),
		defaultDatagramVersion,
		DefaultFeatures(defaultDatagramVersion),
		0,
		20*time.Millisecond,
		&constructorDialer{
			listenPacket: func(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
				return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
			},
		},
		func() {
			onConnected <- struct{}{}
		},
		logger.NOP(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	serveCtx, serveCancel := context.WithCancel(ctx)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- connection.Serve(serveCtx, serviceInstance)
	}()

	select {
	case <-onConnected:
	case <-time.After(2 * time.Second):
		t.Fatal("expected QUIC connection to register")
	}

	select {
	case err := <-edgeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for edge-side assertions")
	}

	serveCancel()
	select {
	case err := <-serveDone:
		if err == nil || err != context.Canceled {
			t.Fatalf("unexpected serve result %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected QUIC serve loop to exit")
	}
	select {
	case err := <-unregisterDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected unregister to reach edge")
	}
}

func TestStreamReadWriteCloserClosePreservesOtherStreams(t *testing.T) {
	listener, _ := newTestQUICEdgeListener(t)
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverConnCh := make(chan *quic.Conn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErrCh <- err
			return
		}
		serverConnCh <- conn
	}()

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	clientConn, err := quic.Dial(ctx, udpConn, listener.Addr().(*net.UDPAddr), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		NextProtos:         []string{quicEdgeALPN},
	}, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.CloseWithError(0, "")

	var serverConn *quic.Conn
	select {
	case serverConn = <-serverConnCh:
	case err := <-serverErrCh:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("expected server-side QUIC accept")
	}
	defer serverConn.CloseWithError(0, "")

	const (
		exchanges       = 24
		msgsPerExchange = 4
		testMessage     = "stream-close-ok"
	)

	readDone := make([]chan struct{}, exchanges)
	for index := range readDone {
		readDone[index] = make(chan struct{})
	}

	var serverWG sync.WaitGroup
	for index := range exchanges {
		stream, err := serverConn.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		serverWG.Add(1)
		go func(iter int, stream quicStreamHandle) {
			defer serverWG.Done()
			rwc := newStreamReadWriteCloser(stream)
			defer rwc.Close()

			for range msgsPerExchange {
				if _, err := rwc.Write([]byte(testMessage)); err != nil {
					t.Errorf("server write failed on stream %d: %v", iter, err)
					return
				}
			}
			if iter%2 == 0 {
				<-readDone[iter]
				_, _ = rwc.Write([]byte(testMessage))
			}
		}(index, stream)
	}

	var clientWG sync.WaitGroup
	for index := range exchanges {
		stream, err := clientConn.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		clientWG.Add(1)
		go func(iter int, stream quicStreamHandle) {
			defer clientWG.Done()
			rwc := newStreamReadWriteCloser(stream)
			defer rwc.Close()
			if iter%2 == 0 {
				defer closeOnce(readDone[iter])
			}

			buffer := make([]byte, len(testMessage))
			for range msgsPerExchange {
				if _, err := io.ReadFull(rwc, buffer); err != nil {
					t.Errorf("client read failed on stream %d: %v", iter, err)
					return
				}
				if string(buffer) != testMessage {
					t.Errorf("unexpected payload on stream %d: %q", iter, buffer)
					return
				}
			}
			if iter%2 == 0 {
				closeOnce(readDone[iter])
				_ = rwc.Close()
			}
		}(index, stream)
	}

	serverWG.Wait()
	clientWG.Wait()
}
