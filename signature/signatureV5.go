package adscoreSignature

import (
	"errors"
	"net"
	"strconv"

	adscoreErrors "github.com/Adscore/go-common/adscoreErrors"
	adscoreStruct "github.com/Adscore/go-common/adscoreStruct"
	crypt "github.com/Adscore/go-common/crypt"
	formatter "github.com/Adscore/go-common/formatter"
	utils "github.com/Adscore/go-common/utils"
)

const SUPPORTED_VERSION_V5 = 5
const HEADER_LENGTH = 11

type SignaturePayload map[string]interface{}

type Signature5 struct {
	VERSION int
	ZoneId  int64
	Payload SignaturePayload
	Result  int
}

func CreateSignatureV5FromRequest(signature string, ipAddresses []string, userAgent string, cryptKey []byte) (*Signature5, error) {
	obj := &Signature5{
		VERSION: SUPPORTED_VERSION_V5,
	}

	if len(signature) == 0 {
		return nil, adscoreErrors.NewParseError("premature end of signature")
	}

	err := obj.Parse(signature, cryptKey, "BASE64_VARIANT_URLSAFE_NO_PADDING")

	if err != nil {
		return nil, err
	}

	err = obj.Verify(ipAddresses, userAgent)

	if err != nil {
		return nil, err
	}

	return obj, nil
}

func (s *Signature5) Verify(ipAddresses []string, userAgent string) error {

	var matchingIp net.IP = nil

	for _, ipAddress := range ipAddresses {

		providedIpAddress := net.ParseIP(ipAddress)

		if providedIpAddress == nil {
			continue
		}

		if ipV4FromSignature, ok := s.Payload["ipv4.ip"].(string); ok {
			if net.IP.Equal(providedIpAddress, net.ParseIP(ipV4FromSignature)) {
				matchingIp = providedIpAddress
				break
			}
		}

		if ipV6FromSignature, ok := s.Payload["ipv6.ip"].(string); ok {
			if net.IP.Equal(providedIpAddress, net.ParseIP(ipV6FromSignature)) {
				matchingIp = providedIpAddress
				break
			}
		}
	}

	if matchingIp == nil {
		return adscoreErrors.NewVerifyError("signature IP mismatch")
	}

	signatureUserAgent, ok := s.Payload["b.ua"].(string)

	if !ok || signatureUserAgent == "" {
		return adscoreErrors.NewVerifyError("signature contains no user agent")
	}

	if signatureUserAgent != userAgent {
		return adscoreErrors.NewVerifyError("signature user agent mismatch")
	}

	switch v := s.Payload["result"].(type) {
	case string:
		result, err := strconv.ParseInt(v, 10, 8)
		s.Result = int(result)
		if err != nil {
			return err
		}
	case float64:
		s.Result = int(v)
	case float32:
		s.Result = int(v)
	case int:
		s.Result = v
	case int8:
		s.Result = int(v)
	case int16:
		s.Result = int(v)
	case int32:
		s.Result = int(v)
	case int64:
		s.Result = int(v)
	case uint:
		s.Result = int(v)
	case uint8:
		s.Result = int(v)
	case uint16:
		s.Result = int(v)
	case uint32:
		s.Result = int(v)
	case uint64:
		s.Result = int(v)
	default:
		return errors.New("invalid result type, expected integer, float or string")
	}

	return nil
}

func (s *Signature5) Parse(signature string, cryptKey []byte, format string) error {

	encryptedPayload, payloadDecodeError := formatter.Parse(signature, format)

	if payloadDecodeError != nil {
		return payloadDecodeError
	}

	var data, payloadUnpackError = utils.Unpack("Cversion/nlength/Jzone_id", encryptedPayload)

	if payloadUnpackError != nil {
		return payloadUnpackError
	}

	var version = *data["version"]
	var length = *data["length"]

	if version != SUPPORTED_VERSION_V5 {
		return adscoreErrors.NewVersionError("invalid signature version")
	}

	if len(encryptedPayload) < length+HEADER_LENGTH {
		return adscoreErrors.NewParseError("premature end of signature")
	}

	encryptedPayload = encryptedPayload[HEADER_LENGTH : length+HEADER_LENGTH]

	if len(encryptedPayload) < length {
		return adscoreErrors.NewParseError("truncated signature payload")
	}

	result, err := decryptPayload(encryptedPayload, cryptKey)

	s.ZoneId = int64(*data["zone_id"])
	s.Payload = result

	return err
}

func GetZoneId(signature string, format string) (int64, error) {
	encryptedPayload, payloadDecodeError := formatter.Parse(signature, format)

	if payloadDecodeError != nil {
		return -1, payloadDecodeError
	}

	var data, payloadUnpackError = utils.Unpack("Cversion/nlength/Jzone_id", encryptedPayload)

	if payloadUnpackError != nil {
		return -1, payloadUnpackError
	}

	var version = *data["version"]

	if version != SUPPORTED_VERSION_V5 {
		return -1, adscoreErrors.NewVersionError("invalid signature version")
	}

	zoneId := int64(*data["zone_id"])

	return zoneId, nil
}

func decryptPayload(encryptedPayload []byte, cryptKey []byte) (map[string]interface{}, error) {
	decryptedPayload, err := crypt.DecryptSymmetric(encryptedPayload, cryptKey)

	if err != nil {
		return nil, err
	}

	return adscoreStruct.DecodeStructFromPayload(decryptedPayload)
}
