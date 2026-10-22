package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

func TestCbcDecryptRejectsInvalidLength(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)

	for _, size := range []int{0, 1, 15, 17, 31} {
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("failed to generate random data: %v", err)
		}
		original := append([]byte(nil), data...)

		var (
			result []byte
			err    error
		)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("cbcDecrypt panicked with input size %d: %v", size, r)
				}
			}()
			result, err = cbcDecrypt(data, key, iv)
		}()

		if err == nil {
			t.Fatalf("expected error for ciphertext size %d, got nil", size)
		}
		if result != nil {
			t.Fatalf("expected nil result for ciphertext size %d, got %d bytes", size, len(result))
		}
		if !bytes.Equal(data, original) {
			t.Fatalf("cbcDecrypt mutated input for ciphertext size %d", size)
		}
	}
}

func TestCbcDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("failed to generate random iv: %v", err)
	}

	plaintext := []byte("0123456789abcdef0123456789abcdef")

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	ciphertextCopy := append([]byte(nil), ciphertext...)

	decrypted, err := cbcDecrypt(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("cbcDecrypt failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, decrypted)
	}
	if !bytes.Equal(ciphertext, ciphertextCopy) {
		t.Fatalf("cbcDecrypt mutated input ciphertext")
	}
}
