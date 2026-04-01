package cloudflared

import (
	"errors"
	"strings"

	"github.com/sagernet/quic-go"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	protocolH2MUX        = "h2mux"
	defaultProtocolRetry = 5
)

type protocolSelector interface {
	Current() string
	Fallback() (string, bool)
}

type staticProtocolSelector struct {
	current     string
	fallback    string
	hasFallback bool
}

func (s staticProtocolSelector) Current() string {
	return s.current
}

func (s staticProtocolSelector) Fallback() (string, bool) {
	if !s.hasFallback {
		return "", false
	}
	return s.fallback, true
}

func newProtocolSelector(protocol string, postQuantum bool) (protocolSelector, error) {
	switch protocol {
	case "", protocolQUIC:
		if postQuantum {
			return staticProtocolSelector{current: protocolQUIC}, nil
		}
	case protocolHTTP2:
		if postQuantum {
			return nil, E.New("post-quantum is only supported with quic transport")
		}
	default:
		return nil, E.New("unsupported protocol: ", protocol, ", expected auto, quic, http2 or h2mux")
	}

	switch protocol {
	case "":
		return staticProtocolSelector{
			current:     protocolQUIC,
			fallback:    protocolHTTP2,
			hasFallback: true,
		}, nil
	case protocolQUIC:
		return staticProtocolSelector{current: protocolQUIC}, nil
	case protocolHTTP2:
		return staticProtocolSelector{current: protocolHTTP2}, nil
	default:
		return nil, E.New("unsupported protocol: ", protocol, ", expected auto, quic, http2 or h2mux")
	}
}

func normalizeProtocol(protocol string) (string, error) {
	switch protocol {
	case "", "auto":
		return "", nil
	case protocolQUIC, protocolHTTP2:
		return protocol, nil
	case protocolH2MUX:
		return protocolHTTP2, nil
	default:
		return "", E.New("unsupported protocol: ", protocol, ", expected auto, quic, http2 or h2mux")
	}
}

func isQUICBroken(err error) bool {
	var idleTimeoutError *quic.IdleTimeoutError
	if errors.As(err, &idleTimeoutError) {
		return true
	}

	var transportError *quic.TransportError
	if errors.As(err, &transportError) && strings.Contains(err.Error(), "operation not permitted") {
		return true
	}

	return false
}
