package cloudflared

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestNewEdgeTLSConfigUsesP256(t *testing.T) {
	t.Parallel()
	rootCAs := x509.NewCertPool()
	config := newEdgeTLSConfig(rootCAs, h2EdgeSNI, nil)

	if config.RootCAs != rootCAs {
		t.Fatal("expected root CA pool to be preserved")
	}
	if config.ServerName != h2EdgeSNI {
		t.Fatalf("expected server name %q, got %q", h2EdgeSNI, config.ServerName)
	}
	if len(config.CurvePreferences) != 1 || config.CurvePreferences[0] != tls.CurveP256 {
		t.Fatalf("unexpected curve preferences: %#v", config.CurvePreferences)
	}
}

func TestNewEdgeTLSConfigPreservesNextProtos(t *testing.T) {
	t.Parallel()
	config := newEdgeTLSConfig(x509.NewCertPool(), quicEdgeSNI, []string{quicEdgeALPN})
	if len(config.NextProtos) != 1 || config.NextProtos[0] != quicEdgeALPN {
		t.Fatalf("unexpected next protos: %#v", config.NextProtos)
	}
}
