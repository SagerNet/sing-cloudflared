package cloudflared

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestBuildHTTPRequestFromMetadataUsesNoBodyWhenLengthZeroWithoutChunked(t *testing.T) {
	t.Parallel()
	request, err := buildHTTPRequestFromMetadata(context.Background(), &ConnectRequest{
		Dest: "http://example.com",
		Type: ConnectionTypeHTTP,
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: "cf.host"},
		},
	}, io.NopCloser(bytes.NewBuffer(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if request.Body != http.NoBody {
		t.Fatalf("expected http.NoBody, got %#v", request.Body)
	}
}

func TestBuildHTTPRequestFromMetadataPreservesBodyWhenTransferEncodingChunked(t *testing.T) {
	t.Parallel()
	request, err := buildHTTPRequestFromMetadata(context.Background(), &ConnectRequest{
		Dest: "http://example.com",
		Type: ConnectionTypeHTTP,
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodPost},
			{Key: metadataHTTPHost, Val: "cf.host"},
			{Key: metadataHTTPHeader + ":Transfer-Encoding", Val: "chunked"},
		},
	}, io.NopCloser(bytes.NewBufferString("payload")))
	if err != nil {
		t.Fatal(err)
	}
	if request.Body == http.NoBody {
		t.Fatal("expected request body to be preserved")
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "payload" {
		t.Fatalf("unexpected body %q", body)
	}
}

func TestBuildHTTPRequestFromMetadataPreservesBodyWhenTransferEncodingContainsChunked(t *testing.T) {
	t.Parallel()
	request, err := buildHTTPRequestFromMetadata(context.Background(), &ConnectRequest{
		Dest: "http://example.com",
		Type: ConnectionTypeHTTP,
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodPost},
			{Key: metadataHTTPHost, Val: "cf.host"},
			{Key: metadataHTTPHeader + ":Transfer-Encoding", Val: "gzip,chunked"},
		},
	}, io.NopCloser(bytes.NewBufferString("payload")))
	if err != nil {
		t.Fatal(err)
	}
	if request.Body == http.NoBody {
		t.Fatal("expected request body to be preserved")
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "payload" {
		t.Fatalf("unexpected body %q", body)
	}
}
