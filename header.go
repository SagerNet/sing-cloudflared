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

func isControlResponseHeader(name string) bool {
	return strings.HasPrefix(name, ":") ||
		strings.HasPrefix(name, "cf-int-") ||
		strings.HasPrefix(name, "cf-cloudflared-") ||
		strings.HasPrefix(name, "cf-proxy-")
}

func isWebsocketClientHeader(name string) bool {
	return name == "sec-websocket-accept" ||
		name == "connection" ||
		name == "upgrade"
}
