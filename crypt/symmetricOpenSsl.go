package crypt

import (
	"crypto/aes"
	"crypto/cipher"

	utils "github.com/Adscore/go-common/utils"
)

var OpenSSLAEADMethod = 0x0201
var OpenSSLMethod = 0x0200
var tagLength = 16

func parse(payload []byte) (method int, iv []byte, tag []byte, data []byte, err error) {
	offset := 0

	methodUnpacked, err := utils.Unpack("vmethod", payload[0:2])

	if err != nil {
		return -1, nil, nil, nil, err
	}

	offset += 2
	method = *methodUnpacked["method"]

	ivLength := 16

	if method == OpenSSLAEADMethod {
		ivLength = 12
	}

	iv = payload[offset : offset+ivLength]

	offset += ivLength

	if method == OpenSSLAEADMethod {
		tag = payload[offset : offset+tagLength]
		offset += tagLength
	}

	data = payload[offset:]

	return method, iv, tag, data, nil

}

func DecryptSymmetricOpenSsl(payload []byte, encryptionKey []byte) ([]byte, error) {
	var method, iv, tag, data, err = parse(payload)

	if err != nil {
		return nil, err
	}

	if method == OpenSSLAEADMethod {
		return gcmDecrypt(data, encryptionKey, iv, tag)
	} else {
		return cbcDecrypt(data, encryptionKey, iv)
	}
}

func cbcDecrypt(data []byte, encryptionKey []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	return data, nil
}

func gcmDecrypt(data []byte, encryptionKey []byte, iv []byte, tag []byte) ([]byte, error) {

	cipherText := append(data, tag...)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	mode, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}

	result, err := mode.Open(nil, iv, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}
