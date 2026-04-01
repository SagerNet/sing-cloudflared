package cloudflared

import (
	"net/http"
	"regexp"
	"testing"
	"time"
)

func TestConfigManagerCurrentVersionTracksApply(t *testing.T) {
	t.Parallel()

	manager, err := NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	if manager.CurrentVersion() != -1 {
		t.Fatalf("unexpected initial version %d", manager.CurrentVersion())
	}

	result := manager.Apply(2, []byte(`{"ingress":[{"service":"http_status:503"}]}`))
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if manager.CurrentVersion() != 2 {
		t.Fatalf("unexpected current version %d", manager.CurrentVersion())
	}
}

func TestCompileIngressRulesDefaultsToCatchAll503(t *testing.T) {
	t.Parallel()

	rules, err := compileIngressRules(defaultOriginRequestConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("unexpected compiled rules %#v", rules)
	}
	if rules[0].Service.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unexpected default status %d", rules[0].Service.StatusCode)
	}
}

func TestBuildRemoteRuntimeConfigCompilesPunycodePathAndAccess(t *testing.T) {
	t.Parallel()

	config, err := buildRemoteRuntimeConfig([]byte(`{
		"originRequest": {"http2Origin": true},
		"ingress": [
			{
				"hostname": "môô.cloudflare.com",
				"path": "^/api",
				"service": "http://127.0.0.1:8080",
				"originRequest": {
					"access": {"required": true, "teamName": "team", "audTag": ["aud-1"], "environment": "fed"}
				}
			},
			{"service":"http_status:404"}
		],
		"warp-routing": {"maxActiveFlows": 9}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	if len(config.Ingress) != 2 {
		t.Fatalf("unexpected ingress rules %#v", config.Ingress)
	}
	if got := config.Ingress[0].PunycodeHostname; got == "" {
		t.Fatal("expected punycode hostname to be populated")
	}
	if config.Ingress[0].Path == nil || !config.Ingress[0].Path.MatchString("/api/test") {
		t.Fatalf("unexpected path matcher %#v", config.Ingress[0].Path)
	}
	if !config.Ingress[0].Service.OriginRequest.Access.Required {
		t.Fatal("expected access config to be required")
	}
	if config.Ingress[0].Service.OriginRequest.Access.Environment != "fed" {
		t.Fatalf("unexpected access environment %q", config.Ingress[0].Service.OriginRequest.Access.Environment)
	}
	if !config.OriginRequest.HTTP2Origin {
		t.Fatal("expected default origin request to enable HTTP/2 origin")
	}
	if config.WarpRouting.MaxActiveFlows != 9 {
		t.Fatalf("unexpected max active flows %d", config.WarpRouting.MaxActiveFlows)
	}
}

func TestMergeRemoteOriginRequestOverridesAccessHTTP2AndIPRules(t *testing.T) {
	t.Parallel()

	base := OriginRequestConfig{
		HTTP2Origin: true,
		Access: AccessConfig{
			Required: true,
			TeamName: "old-team",
			AudTag:   []string{"old-aud"},
		},
		IPRules: []IPRule{{Prefix: "10.0.0.0/8", Ports: []int{80}, Allow: true}},
	}
	result := mergeRemoteOriginRequest(base, remoteOriginRequestJSON{
		HTTP2Origin: boolPtr(false),
		Access: &remoteAccessJSON{
			Required:    true,
			TeamName:    "team",
			AudTag:      []string{"aud-1", "aud-2"},
			Environment: "fed",
		},
		IPRules: []remoteIPRuleJSON{{
			Prefix: "127.0.0.0/8",
			Ports:  []int{443},
			Allow:  false,
		}},
	})

	if result.HTTP2Origin {
		t.Fatal("expected HTTP/2 origin override to disable value")
	}
	if result.Access.TeamName != "team" || len(result.Access.AudTag) != 2 || result.Access.Environment != "fed" {
		t.Fatalf("unexpected access override %#v", result.Access)
	}
	if len(result.IPRules) != 1 || result.IPRules[0].Prefix != "127.0.0.0/8" || result.IPRules[0].Allow {
		t.Fatalf("unexpected ip rules %#v", result.IPRules)
	}
}

func TestWarpRoutingFromRemoteUsesDefaultsAndOverrides(t *testing.T) {
	t.Parallel()

	defaults := warpRoutingFromRemote(remoteWarpRoutingJSON{})
	if defaults.ConnectTimeout != defaultWarpRoutingConnectTime {
		t.Fatalf("unexpected default connect timeout %v", defaults.ConnectTimeout)
	}
	if defaults.TCPKeepAlive != defaultWarpRoutingTCPKeepAlive {
		t.Fatalf("unexpected default keepalive %v", defaults.TCPKeepAlive)
	}

	overridden := warpRoutingFromRemote(remoteWarpRoutingJSON{
		ConnectTimeout: 12,
		TCPKeepAlive:   99,
		MaxActiveFlows: 11,
	})
	if overridden.ConnectTimeout != 12*time.Second || overridden.TCPKeepAlive != 99*time.Second || overridden.MaxActiveFlows != 11 {
		t.Fatalf("unexpected warp routing override %#v", overridden)
	}
}

func TestValidateHostnameRejectsPortsAndInvalidWildcards(t *testing.T) {
	t.Parallel()

	testCases := []string{
		"example.com:443",
		"exa*mple.com",
		"*example.com",
		"foo.*.example.com",
	}
	for _, testCase := range testCases {
		if err := validateHostname(testCase, false); err == nil {
			t.Fatalf("expected hostname %q to be rejected", testCase)
		}
	}
}

func TestParseResolvedServiceAdditionalCases(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		raw     string
		cfg     OriginRequestConfig
		check   func(*testing.T, ResolvedService)
		wantErr bool
	}{
		{
			name: "bastion from empty service",
			cfg:  OriginRequestConfig{BastionMode: true},
			check: func(t *testing.T, service ResolvedService) {
				if service.Kind != ResolvedServiceBastion {
					t.Fatalf("unexpected kind %v", service.Kind)
				}
			},
		},
		{
			name: "unix tls",
			raw:  "unix+tls:/tmp/test.sock",
			check: func(t *testing.T, service ResolvedService) {
				if service.Kind != ResolvedServiceUnixTLS || service.BaseURL.Scheme != "https" {
					t.Fatalf("unexpected service %#v", service)
				}
			},
		},
		{
			name: "ws default port",
			raw:  "ws://127.0.0.1",
			check: func(t *testing.T, service ResolvedService) {
				if got := service.Destination.Port; got != 80 {
					t.Fatalf("unexpected port %d", got)
				}
			},
		},
		{
			name:    "hello world unsupported",
			raw:     "hello-world",
			wantErr: true,
		},
		{
			name:    "service path rejected",
			raw:     "http://127.0.0.1:8080/path",
			wantErr: true,
		},
		{
			name:    "missing scheme rejected",
			raw:     "127.0.0.1:8080",
			wantErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			service, err := parseResolvedService(testCase.raw, testCase.cfg)
			if testCase.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			testCase.check(t, service)
		})
	}
}

func TestMatchIngressRuleWithCompiledRegex(t *testing.T) {
	t.Parallel()

	rule := compiledIngressRule{
		Hostname: "example.com",
		Path:     regexp.MustCompile(`^/api/`),
	}
	if !matchIngressRule(rule, "example.com", "/api/test") {
		t.Fatal("expected ingress rule to match")
	}
	if matchIngressRule(rule, "example.com", "/other") {
		t.Fatal("expected ingress rule path mismatch")
	}
}

func boolPtr(value bool) *bool {
	return &value
}
