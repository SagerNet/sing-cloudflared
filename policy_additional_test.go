package cloudflared

import (
	"context"
	"crypto/x509"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestIPRulePolicyAllowsResolvedDomain(t *testing.T) {
	t.Parallel()

	policy, err := newIPRulePolicy([]IPRule{{
		Prefix: "::/0",
		Ports:  []int{80},
		Allow:  true,
	}})
	if err != nil {
		t.Fatal(err)
	}

	allowed, err := policy.Allow(context.Background(), M.ParseSocksaddr("localhost:80"))
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("expected localhost to match 127.0.0.0/8 allow rule")
	}
}

func TestResolvePolicyDestinationRejectsInvalidHost(t *testing.T) {
	t.Parallel()

	_, err := resolvePolicyDestination(context.Background(), M.Socksaddr{Fqdn: "bad host"})
	if err == nil {
		t.Fatal("expected invalid host error")
	}
}

func TestNewEdgeTLSConfigUsesInputs(t *testing.T) {
	t.Parallel()

	pool := x509.NewCertPool()
	config := newEdgeTLSConfig(pool, "quic.cftunnel.com", []string{"argotunnel"})
	if config.RootCAs != pool {
		t.Fatal("expected root CA pool to be preserved")
	}
	if config.ServerName != "quic.cftunnel.com" {
		t.Fatalf("unexpected server name %q", config.ServerName)
	}
	if len(config.NextProtos) != 1 || config.NextProtos[0] != "argotunnel" {
		t.Fatalf("unexpected next protos %#v", config.NextProtos)
	}
	if len(config.CurvePreferences) != 1 {
		t.Fatalf("unexpected curve preferences %#v", config.CurvePreferences)
	}
}

func TestGetRegionalServiceName(t *testing.T) {
	t.Parallel()

	if got := getRegionalServiceName(""); got != edgeSRVService {
		t.Fatalf("unexpected default service name %q", got)
	}
	if got := getRegionalServiceName("us"); got != "us-"+edgeSRVService {
		t.Fatalf("unexpected regional service name %q", got)
	}
}

func TestFilterByIPVersionDropsMismatchedRegions(t *testing.T) {
	t.Parallel()

	regions := [][]*EdgeAddr{
		{{IPVersion: 4}, {IPVersion: 6}},
		{{IPVersion: 6}},
	}
	filtered := FilterByIPVersion(regions, 4)
	if len(filtered) != 1 || len(filtered[0]) != 1 || filtered[0][0].IPVersion != 4 {
		t.Fatalf("unexpected filtered regions %#v", filtered)
	}
}
