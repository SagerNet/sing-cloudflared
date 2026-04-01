package cloudflared

import (
	"encoding/base64"
	"net/http"
	"strings"
)

const (
	h2HeaderUpgrade        = "Cf-Cloudflared-Proxy-Connection-Upgrade"
	h2HeaderTCPSrc         = "Cf-Cloudflared-Proxy-Src"
	h2HeaderResponseMeta   = "Cf-Cloudflared-Response-Meta"
	h2HeaderResponseUser   = "Cf-Cloudflared-Response-Headers"
	h2UpgradeControlStream = "control-stream"
	h2UpgradeWebsocket     = "websocket"
	h2UpgradeConfiguration = "update-configuration"
	h2ResponseMetaOrigin   = `{"src":"origin"}`
)

var headerEncoding = base64.RawStdEncoding

// SerializeHeaders encodes HTTP/1 headers into base64 pairs: base64(name):base64(value);...
func SerializeHeaders(header http.Header) string {
	var builder strings.Builder
	for name, values := range header {
		for _, value := range values {
			if builder.Len() > 0 {
				builder.WriteByte(';')
			}
			builder.WriteString(headerEncoding.EncodeToString([]byte(name)))
			builder.WriteByte(':')
			builder.WriteString(headerEncoding.EncodeToString([]byte(value)))
		}
	}
	return builder.String()
}

// isControlResponseHeader returns true for headers that are internal control headers.
func isControlResponseHeader(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, ":") ||
		strings.HasPrefix(lower, "cf-int-") ||
		strings.HasPrefix(lower, "cf-cloudflared-") ||
		strings.HasPrefix(lower, "cf-proxy-")
}

// isWebsocketClientHeader returns true for headers needed by the client for WebSocket upgrade.
func isWebsocketClientHeader(name string) bool {
	lower := strings.ToLower(name)
	return lower == "sec-websocket-accept" ||
		lower == "connection" ||
		lower == "upgrade"
}
