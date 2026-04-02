package cloudflared

import (
	"context"
	"net/http"
	"testing"

	"github.com/sagernet/sing-cloudflared/internal/config"
	"github.com/sagernet/sing-cloudflared/internal/protocol"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type fakeAccessValidator struct {
	err error
}

func (v *fakeAccessValidator) Validate(ctx context.Context, request *http.Request) error {
	return v.err
}

func newAccessTestService(t *testing.T) *Service {
	t.Helper()
	return &Service{
		logger:        logger.NOP(),
		accessCache:   &accessValidatorCache{values: make(map[string]accessValidator), dialer: N.SystemDialer},
		handler:       &testHandler{},
		controlDialer: N.SystemDialer,
	}
}

func TestValidateAccessConfigurationViaApply(t *testing.T) {
	t.Parallel()
	configManager, err := config.NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	result := configManager.Apply(1, []byte(`{"ingress":[{"service":"http_status:200","originRequest":{"access":{"required":true,"audTag":["aud"]}}}]}`))
	if result.Err == nil {
		t.Fatal("expected access config validation error")
	}
}

func TestAccessTokenAudienceAllowed(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name           string
		tokenAudience  []string
		configuredTags []string
		expected       bool
	}{
		{
			name:           "matching audience",
			tokenAudience:  []string{"aud-1", "aud-2"},
			configuredTags: []string{"aud-2"},
			expected:       true,
		},
		{
			name:           "empty configured tags rejected",
			tokenAudience:  []string{"aud-1"},
			configuredTags: nil,
			expected:       false,
		},
		{
			name:           "non matching audience rejected",
			tokenAudience:  []string{"aud-1"},
			configuredTags: []string{"aud-2"},
			expected:       false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			allowed := accessTokenAudienceAllowed(testCase.tokenAudience, testCase.configuredTags)
			if allowed != testCase.expected {
				t.Fatalf("accessTokenAudienceAllowed(%v, %v) = %v, want %v", testCase.tokenAudience, testCase.configuredTags, allowed, testCase.expected)
			}
		})
	}
}

func TestRoundTripHTTPAccessDenied(t *testing.T) {
	t.Parallel()
	originalFactory := newAccessValidator
	defer func() {
		newAccessValidator = originalFactory
	}()
	newAccessValidator = func(access config.AccessConfig, dialer N.Dialer) (accessValidator, error) {
		return &fakeAccessValidator{err: E.New("forbidden")}, nil
	}

	serviceInstance := newAccessTestService(t)
	respWriter := &fakeConnectResponseWriter{}
	request := &protocol.ConnectRequest{
		Type: protocol.ConnectionTypeHTTP,
		Dest: "http://127.0.0.1:8083/test",
		Metadata: []protocol.Metadata{
			{Key: protocol.MetadataHTTPMethod, Val: http.MethodGet},
			{Key: protocol.MetadataHTTPHost, Val: "example.com"},
		},
	}
	serviceInstance.handleHTTPService(context.Background(), nil, respWriter, request, config.ResolvedService{
		Kind:        config.ResolvedServiceHTTP,
		Destination: M.ParseSocksaddr("127.0.0.1:8083"),
		OriginRequest: config.OriginRequestConfig{
			Access: config.AccessConfig{
				Required: true,
				TeamName: "team",
			},
		},
	})
	if respWriter.status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", respWriter.status)
	}
}

func TestHandleHTTPServiceStatusAccessDenied(t *testing.T) {
	t.Parallel()
	originalFactory := newAccessValidator
	defer func() {
		newAccessValidator = originalFactory
	}()
	newAccessValidator = func(access config.AccessConfig, dialer N.Dialer) (accessValidator, error) {
		return &fakeAccessValidator{err: E.New("forbidden")}, nil
	}

	serviceInstance := newAccessTestService(t)
	respWriter := &fakeConnectResponseWriter{}
	request := &protocol.ConnectRequest{
		Type: protocol.ConnectionTypeHTTP,
		Dest: "https://example.com/status",
		Metadata: []protocol.Metadata{
			{Key: protocol.MetadataHTTPMethod, Val: http.MethodGet},
			{Key: protocol.MetadataHTTPHost, Val: "example.com"},
		},
	}
	serviceInstance.handleHTTPService(context.Background(), nil, respWriter, request, config.ResolvedService{
		Kind: config.ResolvedServiceStatus,
		OriginRequest: config.OriginRequestConfig{
			Access: config.AccessConfig{
				Required: true,
				TeamName: "team",
			},
		},
		StatusCode: 404,
	})
	if respWriter.status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", respWriter.status)
	}
}

func TestHandleHTTPServiceStreamAccessDenied(t *testing.T) {
	t.Parallel()
	originalFactory := newAccessValidator
	defer func() {
		newAccessValidator = originalFactory
	}()
	newAccessValidator = func(access config.AccessConfig, dialer N.Dialer) (accessValidator, error) {
		return &fakeAccessValidator{err: E.New("forbidden")}, nil
	}

	serviceInstance := newAccessTestService(t)
	respWriter := &fakeConnectResponseWriter{}
	request := &protocol.ConnectRequest{
		Type: protocol.ConnectionTypeWebsocket,
		Dest: "https://example.com/ws",
		Metadata: []protocol.Metadata{
			{Key: protocol.MetadataHTTPMethod, Val: http.MethodGet},
			{Key: protocol.MetadataHTTPHost, Val: "example.com"},
			{Key: protocol.MetadataHTTPHeader + ":Sec-WebSocket-Key", Val: "dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}
	serviceInstance.handleHTTPService(context.Background(), nil, respWriter, request, config.ResolvedService{
		Kind:        config.ResolvedServiceStream,
		Destination: M.ParseSocksaddr("127.0.0.1:8080"),
		OriginRequest: config.OriginRequestConfig{
			Access: config.AccessConfig{
				Required: true,
				TeamName: "team",
			},
		},
	})
	if respWriter.status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", respWriter.status)
	}
}
