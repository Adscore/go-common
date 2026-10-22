package crypt

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	adscoreErrors "github.com/Adscore/go-common/adscoreErrors"
	utils "github.com/Adscore/go-common/utils"
	"golang.org/x/crypto/nacl/secretbox"
)

var SodiumSecretboxMethod = 0x0101
var sodiumNonceLength = 24

func parseSodium(payload []byte) (method int, nonce []byte, data []byte, err error) {
	offset := 0

	if len(payload) < 2 {
		return -1, nil, nil, adscoreErrors.NewParseError("premature end of signature")
	}

	methodUnpacked, err := utils.Unpack("vmethod", payload[0:2])
	if err != nil {
		return -1, nil, nil, err
	}

	offset += 2
	method = *methodUnpacked["method"]

	if len(payload) < offset+sodiumNonceLength {
		return -1, nil, nil, adscoreErrors.NewParseError("premature end of signature")
	}

	nonce = payload[offset : offset+sodiumNonceLength]
	offset += sodiumNonceLength

	data = payload[offset:]
	return method, nonce, data, nil
}

func DecryptSymmetricSodium(payload []byte, encryptionKey []byte) ([]byte, error) {
	method, nonceBytes, data, err := parseSodium(payload)
	if err != nil {
		return nil, err
	}

	if method != SodiumSecretboxMethod {
		return nil, adscoreErrors.NewParseError("unrecognized payload method")
	}

	if len(encryptionKey) != 32 {
		return nil, adscoreErrors.NewParseError("encryption key must be 32 bytes for sodium secretbox")
	}

	var nonce [24]byte
	copy(nonce[:], nonceBytes)

	var key [32]byte
	copy(key[:], encryptionKey)

	decrypted, ok := secretbox.Open(nil, data, &nonce, &key)
	if !ok {
		return nil, adscoreErrors.NewParseError("failed to decrypt sodium secretbox payload")
	}

	return decrypted, nil
}

func EncryptSymmetricSodium(data []byte, encryptionKey []byte) ([]byte, error) {
	if len(encryptionKey) != 32 {
		return nil, adscoreErrors.NewParseError("encryption key must be 32 bytes for sodium secretbox")
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	var key [32]byte
	copy(key[:], encryptionKey)

	encrypted := secretbox.Seal(nil, data, &nonce, &key)

	methodBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(methodBytes, uint16(SodiumSecretboxMethod))

	var payload []byte
	payload = append(payload, methodBytes...)
	payload = append(payload, nonce[:]...)
	payload = append(payload, encrypted...)

	return payload, nil
}
