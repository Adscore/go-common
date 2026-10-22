package crypt

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSodiumSecretboxRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	plaintext := []byte("M{\"test\":\"message\", \"result\": 0}")

	encrypted, err := EncryptSymmetricSodium(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptSymmetricSodium failed: %v", err)
	}

	// Test direct decryption
	decrypted, err := DecryptSymmetricSodium(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptSymmetricSodium failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("expected decrypted %s, got %s", string(plaintext), string(decrypted))
	}

	// Test unified DecryptSymmetric dispatcher
	decryptedDispatcher, err := DecryptSymmetric(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptSymmetric failed: %v", err)
	}

	if !bytes.Equal(decryptedDispatcher, plaintext) {
		t.Fatalf("expected dispatcher decrypted %s, got %s", string(plaintext), string(decryptedDispatcher))
	}
}

func TestSodiumSecretboxInvalidKeyLength(t *testing.T) {
	shortKey := make([]byte, 16)
	plaintext := []byte("hello")

	_, err := EncryptSymmetricSodium(plaintext, shortKey)
	if err == nil {
		t.Fatal("expected error for short key in encryption, got nil")
	}

	_, err = DecryptSymmetricSodium([]byte("dummy payload here that is long enough"), shortKey)
	if err == nil {
		t.Fatal("expected error for short key in decryption, got nil")
	}
}

func TestSodiumSecretboxCorruptedData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("hello world")

	encrypted, err := EncryptSymmetricSodium(plaintext, key)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	// Corrupt a byte in the ciphertext
	encrypted[len(encrypted)-1] ^= 0xFF

	_, err = DecryptSymmetricSodium(encrypted, key)
	if err == nil {
		t.Fatal("expected decryption error on corrupted ciphertext, got nil")
	}
}

func TestSodiumSecretboxTruncatedPayload(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	shortPayload := []byte{0x01, 0x01, 0x00}
	_, err := DecryptSymmetricSodium(shortPayload, key)
	if err == nil {
		t.Fatal("expected error for truncated payload, got nil")
	}
}
