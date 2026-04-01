package cloudflared

import (
	"reflect"
	"testing"
	"time"
)

func TestRemoteConfigFieldCountsStayInSync(t *testing.T) {
	t.Parallel()

	if got, want := reflect.TypeOf(remoteOriginRequestJSON{}).NumField(), reflect.TypeOf(OriginRequestConfig{}).NumField(); got != want {
		t.Fatalf("remote origin request field count mismatch: got %d want %d", got, want)
	}
	if got, want := reflect.TypeOf(remoteAccessJSON{}).NumField(), reflect.TypeOf(AccessConfig{}).NumField(); got != want {
		t.Fatalf("remote access field count mismatch: got %d want %d", got, want)
	}
	if got, want := reflect.TypeOf(remoteIPRuleJSON{}).NumField(), reflect.TypeOf(IPRule{}).NumField(); got != want {
		t.Fatalf("remote ip rule field count mismatch: got %d want %d", got, want)
	}
}

func TestMergeRemoteOriginRequestOverridesEverySupportedField(t *testing.T) {
	t.Parallel()

	base := OriginRequestConfig{
		ConnectTimeout:         time.Second,
		TLSTimeout:             2 * time.Second,
		TCPKeepAlive:           3 * time.Second,
		NoHappyEyeballs:        false,
		KeepAliveTimeout:       4 * time.Second,
		KeepAliveConnections:   5,
		HTTPHostHeader:         "old-host",
		OriginServerName:       "old-sni",
		MatchSNIToHost:         false,
		CAPool:                 "old.pem",
		NoTLSVerify:            false,
		DisableChunkedEncoding: false,
		BastionMode:            false,
		ProxyAddress:           "old-proxy",
		ProxyPort:              100,
		ProxyType:              "http",
		IPRules: []IPRule{{
			Prefix: "10.0.0.0/8",
			Ports:  []int{80},
			Allow:  true,
		}},
		HTTP2Origin: false,
		Access: AccessConfig{
			Required:    false,
			TeamName:    "old-team",
			AudTag:      []string{"old-aud"},
			Environment: "",
		},
	}

	result := mergeRemoteOriginRequest(base, remoteOriginRequestJSON{
		ConnectTimeout:         11,
		TLSTimeout:             12,
		TCPKeepAlive:           13,
		NoHappyEyeballs:        boolPtr(true),
		KeepAliveTimeout:       14,
		KeepAliveConnections:   intPtr(15),
		HTTPHostHeader:         "origin.example.com",
		OriginServerName:       "sni.example.com",
		MatchSNIToHost:         boolPtr(true),
		CAPool:                 "custom.pem",
		NoTLSVerify:            boolPtr(true),
		DisableChunkedEncoding: boolPtr(true),
		BastionMode:            boolPtr(true),
		ProxyAddress:           "127.0.0.1",
		ProxyPort:              uintPtr(1080),
		ProxyType:              "socks5",
		IPRules: []remoteIPRuleJSON{{
			Prefix: "127.0.0.0/8",
			Ports:  []int{443, 8443},
			Allow:  false,
		}},
		HTTP2Origin: boolPtr(true),
		Access: &remoteAccessJSON{
			Required:    true,
			TeamName:    "team",
			AudTag:      []string{"aud-1", "aud-2"},
			Environment: "fed",
		},
	})

	if result.ConnectTimeout != 11*time.Second {
		t.Fatalf("unexpected connect timeout %v", result.ConnectTimeout)
	}
	if result.TLSTimeout != 12*time.Second {
		t.Fatalf("unexpected tls timeout %v", result.TLSTimeout)
	}
	if result.TCPKeepAlive != 13*time.Second {
		t.Fatalf("unexpected tcp keepalive %v", result.TCPKeepAlive)
	}
	if !result.NoHappyEyeballs {
		t.Fatal("expected no happy eyeballs override")
	}
	if result.KeepAliveTimeout != 14*time.Second {
		t.Fatalf("unexpected keepalive timeout %v", result.KeepAliveTimeout)
	}
	if result.KeepAliveConnections != 15 {
		t.Fatalf("unexpected keepalive connections %d", result.KeepAliveConnections)
	}
	if result.HTTPHostHeader != "origin.example.com" {
		t.Fatalf("unexpected http host header %q", result.HTTPHostHeader)
	}
	if result.OriginServerName != "sni.example.com" {
		t.Fatalf("unexpected origin server name %q", result.OriginServerName)
	}
	if !result.MatchSNIToHost {
		t.Fatal("expected match sni to host override")
	}
	if result.CAPool != "custom.pem" {
		t.Fatalf("unexpected ca pool %q", result.CAPool)
	}
	if !result.NoTLSVerify {
		t.Fatal("expected no tls verify override")
	}
	if !result.DisableChunkedEncoding {
		t.Fatal("expected disable chunked encoding override")
	}
	if !result.BastionMode {
		t.Fatal("expected bastion mode override")
	}
	if result.ProxyAddress != "127.0.0.1" {
		t.Fatalf("unexpected proxy address %q", result.ProxyAddress)
	}
	if result.ProxyPort != 1080 {
		t.Fatalf("unexpected proxy port %d", result.ProxyPort)
	}
	if result.ProxyType != "socks5" {
		t.Fatalf("unexpected proxy type %q", result.ProxyType)
	}
	if len(result.IPRules) != 1 || result.IPRules[0].Prefix != "127.0.0.0/8" || result.IPRules[0].Allow {
		t.Fatalf("unexpected ip rules %#v", result.IPRules)
	}
	if len(result.IPRules[0].Ports) != 2 || result.IPRules[0].Ports[0] != 443 || result.IPRules[0].Ports[1] != 8443 {
		t.Fatalf("unexpected ip rule ports %#v", result.IPRules[0].Ports)
	}
	if !result.HTTP2Origin {
		t.Fatal("expected http2 origin override")
	}
	if !result.Access.Required || result.Access.TeamName != "team" || result.Access.Environment != "fed" {
		t.Fatalf("unexpected access override %#v", result.Access)
	}
	if len(result.Access.AudTag) != 2 || result.Access.AudTag[0] != "aud-1" || result.Access.AudTag[1] != "aud-2" {
		t.Fatalf("unexpected access audience %#v", result.Access.AudTag)
	}
}

func intPtr(value int) *int {
	return &value
}

func uintPtr(value uint) *uint {
	return &value
}
