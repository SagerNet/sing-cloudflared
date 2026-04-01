package cloudflared

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReadStreamSignatureData(t *testing.T) {
	t.Parallel()
	buf := bytes.NewBuffer(dataStreamSignature[:])
	streamType, err := ReadStreamSignature(buf)
	if err != nil {
		t.Fatal("ReadStreamSignature: ", err)
	}
	if streamType != StreamTypeData {
		t.Error("expected StreamTypeData, got ", streamType)
	}
}

func TestReadStreamSignatureRPC(t *testing.T) {
	t.Parallel()
	buf := bytes.NewBuffer(rpcStreamSignature[:])
	streamType, err := ReadStreamSignature(buf)
	if err != nil {
		t.Fatal("ReadStreamSignature: ", err)
	}
	if streamType != StreamTypeRPC {
		t.Error("expected StreamTypeRPC, got ", streamType)
	}
}

func TestReadStreamSignatureUnknown(t *testing.T) {
	t.Parallel()
	buf := bytes.NewBuffer([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	_, err := ReadStreamSignature(buf)
	if err == nil {
		t.Fatal("expected error for unknown signature")
	}
}

func TestReadStreamSignatureTooShort(t *testing.T) {
	t.Parallel()
	buf := bytes.NewBuffer([]byte{0x0A, 0x36, 0xCD})
	_, err := ReadStreamSignature(buf)
	if err == nil {
		t.Fatal("expected error for short input")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Error("expected ErrUnexpectedEOF, got ", err)
	}
}

func TestWriteConnectResponseSuccess(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	metadata := Metadata{Key: "testKey", Val: "testVal"}
	err := WriteConnectResponse(&buf, nil, metadata)
	if err != nil {
		t.Fatal("WriteConnectResponse: ", err)
	}

	data := buf.Bytes()
	if len(data) < 8 {
		t.Fatal("response too short: ", len(data))
	}

	var signature [6]byte
	copy(signature[:], data[:6])
	if signature != dataStreamSignature {
		t.Error("expected data stream signature")
	}

	version := string(data[6:8])
	if version != "01" {
		t.Error("expected version 01, got ", version)
	}
}

func TestWriteConnectResponseError(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	err := WriteConnectResponse(&buf, errors.New("test failure"))
	if err != nil {
		t.Fatal("WriteConnectResponse: ", err)
	}

	data := buf.Bytes()
	if len(data) < 8 {
		t.Fatal("response too short")
	}

	var signature [6]byte
	copy(signature[:], data[:6])
	if signature != dataStreamSignature {
		t.Error("expected data stream signature")
	}
}
