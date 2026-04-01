package cloudflared

import (
	"crypto/tls"
	"crypto/x509"
)

const x25519MLKEM768PQKex = tls.CurveID(0x11ec)

func newEdgeTLSConfig(rootCAs *x509.CertPool, serverName string, nextProtos []string) *tls.Config {
	return &tls.Config{
		RootCAs:          rootCAs,
		ServerName:       serverName,
		NextProtos:       nextProtos,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}
}

func applyPostQuantumCurvePreferences(config *tls.Config, features []string) {
	if config == nil || !hasFeature(features, featurePostQuantum) {
		return
	}
	config.CurvePreferences = []tls.CurveID{x25519MLKEM768PQKex}
}

func hasFeature(features []string, target string) bool {
	for _, feature := range features {
		if feature == target {
			return true
		}
	}
	return false
}
