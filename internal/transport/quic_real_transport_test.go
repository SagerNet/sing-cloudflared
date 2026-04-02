package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

func newTestQUICEdgeListener(t *testing.T) (*quic.Listener, []byte) {
	t.Helper()

	caCertificate, caPrivateKey, caPEM := createTestCertificateAuthority(t, "test quic edge root")
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{createTestServerCertificate(t, caCertificate, caPrivateKey, QuicEdgeSNI)},
		NextProtos:   []string{QuicEdgeALPN},
	}, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return listener, caPEM
}

func closeOnce(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
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
		NextProtos:         []string{QuicEdgeALPN},
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
		go func(iter int, stream *quic.Stream) {
			defer serverWG.Done()
			rwc := NewStreamReadWriteCloser(stream)
			defer rwc.Close()

			for range msgsPerExchange {
				_, err := rwc.Write([]byte(testMessage))
				if err != nil {
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
		go func(iter int, stream *quic.Stream) {
			defer clientWG.Done()
			rwc := NewStreamReadWriteCloser(stream)
			defer rwc.Close()
			if iter%2 == 0 {
				defer closeOnce(readDone[iter])
			}

			buffer := make([]byte, len(testMessage))
			for range msgsPerExchange {
				_, err := io.ReadFull(rwc, buffer)
				if err != nil {
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
