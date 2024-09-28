package crypt

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
)

func VerifyAsymmetric(data []byte, signature []byte, cryptKey []byte) bool {

	publicKeyInterface, _ := x509.ParsePKIXPublicKey(cryptKey)
	publicKeyECDSA, _ := publicKeyInterface.(*ecdsa.PublicKey)

	hash := sha256.Sum256(data)

	return ecdsa.VerifyASN1(publicKeyECDSA, hash[:], signature)

}
