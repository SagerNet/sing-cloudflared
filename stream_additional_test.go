package cloudflared

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing-cloudflared/tunnelrpc"

	capnp "zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/pogs"
)

func encodeConnectRequestForTest(t *testing.T, request *ConnectRequest) []byte {
	t.Helper()

	message, segment, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatal(err)
	}
	root, err := tunnelrpc.NewRootConnectRequest(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := pogs.Insert(tunnelrpc.ConnectRequest_TypeID, root.Struct, request); err != nil {
		t.Fatal(err)
	}

	var payload bytes.Buffer
	payload.Write(dataStreamSignature[:])
	payload.WriteString(protocolVersion)
	if err := capnp.NewEncoder(&payload).Encode(message); err != nil {
		t.Fatal(err)
	}
	return payload.Bytes()
}

func TestReadConnectRequestRoundTrip(t *testing.T) {
	t.Parallel()

	encoded := encodeConnectRequestForTest(t, &ConnectRequest{
		Dest: "https://example.com/test",
		Type: ConnectionTypeHTTP,
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: "GET"},
			{Key: metadataHTTPHost, Val: "example.com"},
		},
	})
	streamType, err := ReadStreamSignature(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if streamType != StreamTypeData {
		t.Fatalf("unexpected stream type %v", streamType)
	}

	request, err := ReadConnectRequest(bytes.NewReader(encoded[len(dataStreamSignature):]))
	if err != nil {
		t.Fatal(err)
	}
	if request.Dest != "https://example.com/test" {
		t.Fatalf("unexpected destination %q", request.Dest)
	}
	if request.Type != ConnectionTypeHTTP {
		t.Fatalf("unexpected type %v", request.Type)
	}
	if request.MetadataMap()[metadataHTTPMethod] != "GET" {
		t.Fatalf("unexpected metadata %#v", request.Metadata)
	}
}

func TestWriteRPCStreamSignatureWritesExpectedBytes(t *testing.T) {
	t.Parallel()

	var payload bytes.Buffer
	if err := WriteRPCStreamSignature(&payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload.Bytes(), rpcStreamSignature[:]) {
		t.Fatalf("unexpected rpc signature %x", payload.Bytes())
	}
}
