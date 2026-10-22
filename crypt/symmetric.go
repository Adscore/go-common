package crypt

import (
	adscoreErrors "github.com/Adscore/go-common/adscoreErrors"
	utils "github.com/Adscore/go-common/utils"
)

func DecryptSymmetric(payload []byte, encryptionKey []byte) ([]byte, error) {
	if len(payload) < 2 {
		return nil, adscoreErrors.NewParseError("premature end of signature")
	}

	methodUnpacked, err := utils.Unpack("vmethod", payload[0:2])
	if err != nil {
		return nil, err
	}

	method := *methodUnpacked["method"]

	switch method {
	case SodiumSecretboxMethod:
		return DecryptSymmetricSodium(payload, encryptionKey)
	case OpenSSLMethod, OpenSSLAEADMethod:
		return DecryptSymmetricOpenSsl(payload, encryptionKey)
	default:
		return nil, adscoreErrors.NewParseError("unsupported encryption method")
	}
}
