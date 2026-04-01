package cloudflared

import (
	"testing"
)

func closeOnce(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func TestCloseOnceIdempotent(t *testing.T) {
	t.Parallel()

	ch := make(chan struct{})
	closeOnce(ch)
	closeOnce(ch)
}
