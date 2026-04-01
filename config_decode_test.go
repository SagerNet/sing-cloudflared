package cloudflared

import (
	"testing"
	"time"
)

func TestNewServiceRequiresToken(t *testing.T) {
	t.Parallel()
	_, err := NewService(ServiceOptions{})
	if err == nil {
		t.Fatal("expected missing token error")
	}
}

func TestValidateRegistrationResultRejectsNonRemoteManaged(t *testing.T) {
	t.Parallel()
	err := validateRegistrationResult(&RegistrationResult{TunnelIsRemotelyManaged: false})
	if err == nil {
		t.Fatal("expected unsupported tunnel error")
	}
	if err != ErrNonRemoteManagedTunnelUnsupported {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizeProtocolAutoUsesTokenStyleSentinel(t *testing.T) {
	t.Parallel()
	protocol, err := normalizeProtocol("auto")
	if err != nil {
		t.Fatal(err)
	}
	if protocol != "" {
		t.Fatalf("expected auto protocol to normalize to token-style empty sentinel, got %q", protocol)
	}
}

func TestNormalizeProtocolH2MUXUsesHTTP2(t *testing.T) {
	t.Parallel()

	protocol, err := normalizeProtocol(protocolH2MUX)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != protocolHTTP2 {
		t.Fatalf("expected h2mux to normalize to http2, got %q", protocol)
	}
}

func TestNewServiceRejectsPostQuantumWithHTTP2(t *testing.T) {
	t.Parallel()

	_, err := NewService(ServiceOptions{
		Token:       testToken(t),
		Protocol:    protocolHTTP2,
		PostQuantum: true,
	})
	if err == nil || err.Error() != "post-quantum is only supported with quic transport" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestNewServiceAutoPostQuantumUsesQUICOnlySelector(t *testing.T) {
	t.Parallel()

	service, err := NewService(ServiceOptions{
		Token:       testToken(t),
		Protocol:    "auto",
		PostQuantum: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if service.currentProtocol() != protocolQUIC {
		t.Fatalf("unexpected current protocol %q", service.currentProtocol())
	}
	if fallback, ok := service.fallbackProtocol(); ok {
		t.Fatalf("expected no fallback for post-quantum selector, got %q", fallback)
	}
}

func TestExplicitZeroGracePeriod(t *testing.T) {
	t.Parallel()
	service, err := NewService(ServiceOptions{
		Token:       testToken(t),
		GracePeriod: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if service.gracePeriod != 30*time.Second {
		t.Fatalf("expected zero to use default 30s, got %s", service.gracePeriod)
	}
}
