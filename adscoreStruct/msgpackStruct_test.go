package adscoreStruct

import (
	"reflect"
	"testing"
)

func TestMsgpackStructDecode(t *testing.T) {
	input := map[string]interface{}{
		"result":  int64(0),
		"ipv4.ip": "192.168.1.1",
		"b.ua":    "Mozilla/5.0",
	}

	encoded, err := EncodeMsgpack(input)
	if err != nil {
		t.Fatalf("failed to encode msgpack: %v", err)
	}

	// Test DecodeStruct directly with 'M'
	decoded, err := DecodeStruct("M", encoded)
	if err != nil {
		t.Fatalf("failed to decode msgpack: %v", err)
	}

	if decoded["ipv4.ip"] != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %v", decoded["ipv4.ip"])
	}
	if decoded["b.ua"] != "Mozilla/5.0" {
		t.Errorf("expected Mozilla/5.0, got %v", decoded["b.ua"])
	}

	// Test DecodeStructFromPayload with 'M' header prefix
	payloadWithHeader := append([]byte("M"), encoded...)
	decodedFromPayload, err := DecodeStructFromPayload(payloadWithHeader)
	if err != nil {
		t.Fatalf("failed to decode from payload: %v", err)
	}

	if !reflect.DeepEqual(decoded, decodedFromPayload) {
		t.Fatalf("expected %v, got %v", decoded, decodedFromPayload)
	}
}

func TestMsgpackInvalidPayload(t *testing.T) {
	invalidData := []byte{0xC1} // 0xC1 is never used in MessagePack spec
	_, err := DecodeStruct("M", invalidData)
	if err == nil {
		t.Fatal("expected error on invalid msgpack bytes, got nil")
	}
}
