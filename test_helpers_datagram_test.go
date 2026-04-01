package cloudflared

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"testing"
	"time"
)

type captureDatagramSender struct {
	sent [][]byte
}

func (s *captureDatagramSender) SendDatagram(data []byte) error {
	copied := append([]byte(nil), data...)
	s.sent = append(s.sent, copied)
	return nil
}

func createTestCertificateAuthority(t *testing.T, commonName string) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
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
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
}

type requestResponseStream struct {
	reader *bytes.Reader
	writes bytes.Buffer
	closed bool
}

func newRequestResponseStream(body string) *requestResponseStream {
	return &requestResponseStream{reader: bytes.NewReader([]byte(body))}
}

func (s *requestResponseStream) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *requestResponseStream) Write(p []byte) (int, error) {
	return s.writes.Write(p)
}

func (s *requestResponseStream) Close() error {
	s.closed = true
	return nil
}

func newBlockingRPCStream() *blockingRPCStream {
	return &blockingRPCStream{done: make(chan struct{})}
}

type blockingRPCStream struct {
	done chan struct{}
}

func (s *blockingRPCStream) Read(_ []byte) (int, error) {
	<-s.done
	return 0, io.EOF
}

func (s *blockingRPCStream) Write(p []byte) (int, error) {
	return len(p), nil
}

func (s *blockingRPCStream) Close() error {
	closeOnce(s.done)
	return nil
}
