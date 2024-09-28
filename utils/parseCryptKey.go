package utils

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func ParseCryptKey(probablyPemKey string) ([]byte, error) {
	pemBlock, rest := pem.Decode([]byte(probablyPemKey))

	if pemBlock != nil {
		if len(rest) > 0 {
			return nil, errors.New("failed to parse PEM block: expected public key content, found additional data after key")
		}

		return pemBlock.Bytes, nil
	}

	return base64.StdEncoding.DecodeString(probablyPemKey)
}
