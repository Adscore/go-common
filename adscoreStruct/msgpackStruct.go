package adscoreStruct

import (
	adscoreErrors "github.com/Adscore/go-common/adscoreErrors"
	"github.com/vmihailenco/msgpack/v5"
)

func decodeMsgpack(payload []byte) (map[string]interface{}, error) {
	data := map[string]interface{}{}
	err := msgpack.Unmarshal(payload, &data)
	if err != nil {
		return nil, adscoreErrors.NewParseError("failed to decode msgpack payload: " + err.Error())
	}
	return data, nil
}

func EncodeMsgpack(data map[string]interface{}) ([]byte, error) {
	return msgpack.Marshal(data)
}
