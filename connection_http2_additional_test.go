package cloudflared

import (
	"testing"
)

func TestHTTP2HandlerAdapterDelegates(t *testing.T) {
	t.Parallel()

	serviceInstance := newTestService(t, testToken(t), "http2", 1)
	adapter := &http2HandlerAdapter{service: serviceInstance}
	result := adapter.ApplyConfig(1, []byte(`{"ingress":[{"service":"http_status:503"}]}`))
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if result.LastAppliedVersion != 1 {
		t.Fatalf("unexpected last applied version %d", result.LastAppliedVersion)
	}
}
