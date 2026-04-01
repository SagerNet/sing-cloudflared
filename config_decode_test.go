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
