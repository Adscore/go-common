package formatter

import (
	"encoding/base64"
	"errors"
)

func Parse(input string, format string) ([]byte, error) {

	switch format {
	case "BASE64_VARIANT_ORIGINAL":
		return base64.StdEncoding.DecodeString(input)
	case "BASE64_VARIANT_ORIGINAL_NO_PADDING":
		return base64.RawStdEncoding.DecodeString(input)
	case "BASE64_VARIANT_URLSAFE":
		return base64.URLEncoding.DecodeString(input)
	case "BASE64_VARIANT_URLSAFE_NO_PADDING":
		return base64.RawURLEncoding.DecodeString(input)

	}

	return nil, errors.New("unsupported base64 format")
}
