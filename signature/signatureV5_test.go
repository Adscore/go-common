package adscoreSignature

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	adscoreStruct "github.com/Adscore/go-common/adscoreStruct"
	crypt "github.com/Adscore/go-common/crypt"
)

func TestSignatureV5SodiumMsgpack(t *testing.T) {
	cryptKey := make([]byte, 32)
	copy(cryptKey, []byte("01234567890123456789012345678901")) // 32 bytes

	zoneId := uint64(12345678)
	ip := "192.168.1.50"
	ua := "Mozilla/5.0 (Custom Test Agent)"

	payloadMap := map[string]interface{}{
		"ipv4.ip": ip,
		"b.ua":    ua,
		"result":  int64(0),
	}

	msgpackBytes, err := adscoreStruct.EncodeMsgpack(payloadMap)
	if err != nil {
		t.Fatalf("failed to encode msgpack payload: %v", err)
	}

	// Payload inside encryption has struct type prefix 'M'
	structData := append([]byte("M"), msgpackBytes...)

	encryptedPayload, err := crypt.EncryptSymmetricSodium(structData, cryptKey)
	if err != nil {
		t.Fatalf("failed to encrypt sodium payload: %v", err)
	}

	// Build envelope: Cversion (1 byte) + nlength (2 bytes) + Jzone_id (8 bytes) + encryptedPayload
	header := make([]byte, 11)
	header[0] = 5                                                          // version 5
	binary.BigEndian.PutUint16(header[1:3], uint16(len(encryptedPayload))) // length
	binary.BigEndian.PutUint64(header[3:11], zoneId)                       // zone_id

	envelope := append(header, encryptedPayload...)
	signatureString := base64.RawURLEncoding.EncodeToString(envelope)

	// Test GetZoneId
	extractedZoneId, err := GetZoneId(signatureString, "BASE64_VARIANT_URLSAFE_NO_PADDING")
	if err != nil {
		t.Fatalf("GetZoneId failed: %v", err)
	}
	if extractedZoneId != int64(zoneId) {
		t.Errorf("expected zoneId %d, got %d", zoneId, extractedZoneId)
	}

	// Test CreateSignatureV5FromRequest
	sig, err := CreateSignatureV5FromRequest(
		signatureString,
		[]string{"10.0.0.1", ip},
		ua,
		cryptKey,
	)
	if err != nil {
		t.Fatalf("CreateSignatureV5FromRequest failed: %v", err)
	}

	if sig.ZoneId != int64(zoneId) {
		t.Errorf("expected zoneId %d, got %d", zoneId, sig.ZoneId)
	}
	if sig.Result != 0 {
		t.Errorf("expected result 0, got %d", sig.Result)
	}
	if sig.Payload["ipv4.ip"] != ip {
		t.Errorf("expected ip %s, got %v", ip, sig.Payload["ipv4.ip"])
	}
	if sig.Payload["b.ua"] != ua {
		t.Errorf("expected ua %s, got %v", ua, sig.Payload["b.ua"])
	}

	// Test IP mismatch verification error
	_, err = CreateSignatureV5FromRequest(
		signatureString,
		[]string{"1.2.3.4"},
		ua,
		cryptKey,
	)
	if err == nil {
		t.Errorf("expected error for mismatched IP, got nil")
	}

	// Test UA mismatch verification error
	_, err = CreateSignatureV5FromRequest(
		signatureString,
		[]string{ip},
		"Different User Agent",
		cryptKey,
	)
	if err == nil {
		t.Errorf("expected error for mismatched UA, got nil")
	}
}

func TestSignatureV5SodiumJson(t *testing.T) {
	cryptKey := make([]byte, 32)
	copy(cryptKey, []byte("01234567890123456789012345678901"))

	zoneId := uint64(87654321)
	ip := "10.10.10.10"
	ua := "Mozilla/5.0 (JSON Agent)"

	jsonPayload := []byte(`{"ipv4.ip":"10.10.10.10","b.ua":"Mozilla/5.0 (JSON Agent)","result":1}`)
	structData := append([]byte("J"), jsonPayload...)

	encryptedPayload, err := crypt.EncryptSymmetricSodium(structData, cryptKey)
	if err != nil {
		t.Fatalf("failed to encrypt sodium payload: %v", err)
	}

	header := make([]byte, 11)
	header[0] = 5
	binary.BigEndian.PutUint16(header[1:3], uint16(len(encryptedPayload)))
	binary.BigEndian.PutUint64(header[3:11], zoneId)

	envelope := append(header, encryptedPayload...)
	signatureString := base64.RawURLEncoding.EncodeToString(envelope)

	sig, err := CreateSignatureV5FromRequest(
		signatureString,
		[]string{ip},
		ua,
		cryptKey,
	)
	if err != nil {
		t.Fatalf("CreateSignatureV5FromRequest failed: %v", err)
	}

	if sig.ZoneId != int64(zoneId) {
		t.Errorf("expected zoneId %d, got %d", zoneId, sig.ZoneId)
	}
	if sig.Result != 1 {
		t.Errorf("expected result 1, got %d", sig.Result)
	}
}

// buildJSONSignatureV5 wraps a raw JSON payload in a sodium-encrypted V5 envelope.
func buildJSONSignatureV5(t *testing.T, jsonPayload string, zoneId uint64, cryptKey []byte) string {
	t.Helper()

	structData := append([]byte("J"), []byte(jsonPayload)...)

	encryptedPayload, err := crypt.EncryptSymmetricSodium(structData, cryptKey)
	if err != nil {
		t.Fatalf("failed to encrypt sodium payload: %v", err)
	}

	header := make([]byte, 11)
	header[0] = 5
	binary.BigEndian.PutUint16(header[1:3], uint16(len(encryptedPayload)))
	binary.BigEndian.PutUint64(header[3:11], zoneId)

	envelope := append(header, encryptedPayload...)
	return base64.RawURLEncoding.EncodeToString(envelope)
}

func TestSignatureV5IPv6OnlyMatch(t *testing.T) {
	cryptKey := make([]byte, 32)
	copy(cryptKey, []byte("01234567890123456789012345678901"))

	ipv6 := "2001:db8::1"
	ua := "Mozilla/5.0 (IPv6 Agent)"

	signatureString := buildJSONSignatureV5(t,
		`{"ipv6.ip":"2001:db8::1","b.ua":"Mozilla/5.0 (IPv6 Agent)","result":1}`,
		11223344, cryptKey)

	sig, err := CreateSignatureV5FromRequest(signatureString, []string{ipv6}, ua, cryptKey)
	if err != nil {
		t.Fatalf("expected IPv6-only signature to match IPv6 request IP, got error: %v", err)
	}
	if sig.Result != 1 {
		t.Errorf("expected result 1, got %d", sig.Result)
	}

	// A different IPv6 address must still be rejected.
	_, err = CreateSignatureV5FromRequest(signatureString, []string{"2001:db8::2"}, ua, cryptKey)
	if err == nil {
		t.Errorf("expected error for mismatched IPv6, got nil")
	}
}

func TestSignatureV5MissingUserAgentNoPanic(t *testing.T) {
	cryptKey := make([]byte, 32)
	copy(cryptKey, []byte("01234567890123456789012345678901"))

	ip := "10.20.30.40"

	signatureString := buildJSONSignatureV5(t,
		`{"ipv4.ip":"10.20.30.40","result":1}`,
		11223344, cryptKey)

	_, err := CreateSignatureV5FromRequest(signatureString, []string{ip}, "Some UA", cryptKey)
	if err == nil {
		t.Fatalf("expected error for payload without b.ua, got nil")
	}
	if err.Error() != "signature contains no user agent" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSignatureV5NonStringUserAgentNoPanic(t *testing.T) {
	cryptKey := make([]byte, 32)
	copy(cryptKey, []byte("01234567890123456789012345678901"))

	ip := "10.20.30.40"

	signatureString := buildJSONSignatureV5(t,
		`{"ipv4.ip":"10.20.30.40","b.ua":12345,"result":1}`,
		11223344, cryptKey)

	_, err := CreateSignatureV5FromRequest(signatureString, []string{ip}, "Some UA", cryptKey)
	if err == nil {
		t.Fatalf("expected error for non-string b.ua, got nil")
	}
	if err.Error() != "signature contains no user agent" {
		t.Errorf("unexpected error: %v", err)
	}
}
