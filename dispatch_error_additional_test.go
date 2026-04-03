package cloudflared

import (
	"context"
	"net/http"
	"testing"

	"github.com/sagernet/sing/common/logger"
)

func TestHandleHTTPServiceRequiresWebsocketForSpecialServices(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		service ResolvedService
		wantErr string
	}{
		{
			name:    "stream service",
			service: ResolvedService{Kind: ResolvedServiceStream},
			wantErr: "stream service requires websocket request type",
		},
		{
			name:    "bastion service",
			service: ResolvedService{Kind: ResolvedServiceBastion},
			wantErr: "bastion service requires websocket request type",
		},
		{
			name:    "socks proxy service",
			service: ResolvedService{Kind: ResolvedServiceSocksProxy},
			wantErr: "socks-proxy service requires websocket request type",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			respWriter := &fakeConnectResponseWriter{}
			(&Service{logger: logger.NOP()}).handleHTTPService(context.Background(), nil, respWriter, &ConnectRequest{
				Type: ConnectionTypeHTTP,
				Dest: "http://example.com/test",
				Metadata: []Metadata{
					{Key: metadataHTTPMethod, Val: http.MethodGet},
					{Key: metadataHTTPHost, Val: "example.com"},
				},
			}, testCase.service)
			if respWriter.err == nil || respWriter.err.Error() != testCase.wantErr {
				t.Fatalf("unexpected error %v", respWriter.err)
			}
		})
	}
}

func TestHandleHTTPServiceRejectsUnsupportedKind(t *testing.T) {
	t.Parallel()

	respWriter := &fakeConnectResponseWriter{}
	(&Service{logger: logger.NOP()}).handleHTTPService(context.Background(), nil, respWriter, &ConnectRequest{
		Type: ConnectionTypeHTTP,
		Dest: "http://example.com/test",
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: "example.com"},
		},
	}, ResolvedService{Kind: ResolvedServiceKind(99)})
	if respWriter.err == nil || respWriter.err.Error() != "unsupported service kind for HTTP/WebSocket request" {
		t.Fatalf("unexpected error %v", respWriter.err)
	}
}
