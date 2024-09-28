package adscoreStruct

import (
	adscoreErrors "github.com/Adscore/go-common/adscoreErrors"
)

func DecodeStructFromPayload(payload []byte) (map[string]interface{}, error) {
	header := payload[0:1]
	data := payload[1:]

	return DecodeStruct(string(header), data)
}

func DecodeStruct(structType string, data []byte) (map[string]interface{}, error) {
	switch structType {
	case "J":
		fallthrough
	case "Json":
		fallthrough
	case "json":
		return decodeJson(data)

	case "H":
		fallthrough
	case "Rfc3986":
		fallthrough
	case "rfc3986":
		return decodeRFC3986Struct(data)
	}

	return nil, adscoreErrors.NewParseError("unsupported struct type")

}
