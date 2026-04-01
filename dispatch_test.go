package cloudflared

import (
	"net/http"
	"testing"
)

func TestParseHTTPDestination(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		dest     string
		expected string
	}{
		{"http with port", "http://127.0.0.1:8083/path", "127.0.0.1:8083"},
		{"https default port", "https://example.com", "example.com:443"},
		{"http default port", "http://example.com", "example.com:80"},
		{"wss default port", "wss://example.com/ws", "example.com:443"},
		{"explicit port", "https://example.com:9443/api", "example.com:9443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := parseHTTPDestination(tt.dest)
			if result.String() != tt.expected {
				t.Errorf("parseHTTPDestination(%q) = %q, want %q", tt.dest, result.String(), tt.expected)
			}
		})
	}
}

func TestSerializeHeaders(t *testing.T) {
	t.Parallel()
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	header.Set("X-Foo", "bar")

	serialized := SerializeHeaders(header)
	if serialized == "" {
		t.Fatal("expected non-empty serialized headers")
	}

	decoded := make(map[string]string)
	for _, pair := range splitNonEmpty(serialized, ";") {
		parts := splitNonEmpty(pair, ":")
		if len(parts) != 2 {
			t.Fatalf("malformed pair: %q", pair)
		}
		name, err := headerEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal("decode name: ", err)
		}
		value, err := headerEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal("decode value: ", err)
		}
		decoded[string(name)] = string(value)
	}

	if decoded["Content-Type"] != "text/html" {
		t.Error("expected Content-Type=text/html, got ", decoded["Content-Type"])
	}
	if decoded["X-Foo"] != "bar" {
		t.Error("expected X-Foo=bar, got ", decoded["X-Foo"])
	}
}

func splitNonEmpty(s string, sep string) []string {
	var result []string
	for _, part := range splitString(s, sep) {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func splitString(s string, sep string) []string {
	if len(sep) == 0 {
		return []string{s}
	}
	var result []string
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func TestIsControlResponseHeader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		expected bool
	}{
		{":status", true},
		{"cf-int-foo", true},
		{"cf-cloudflared-response-meta", true},
		{"cf-proxy-src", true},
		{"content-type", false},
		{"x-custom", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isControlResponseHeader(tt.name)
			if result != tt.expected {
				t.Errorf("isControlResponseHeader(%q) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

func TestIsWebsocketClientHeader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		expected bool
	}{
		{"sec-websocket-accept", true},
		{"connection", true},
		{"upgrade", true},
		{"content-type", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isWebsocketClientHeader(tt.name)
			if result != tt.expected {
				t.Errorf("isWebsocketClientHeader(%q) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}
