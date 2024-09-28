package adscoreStruct

import (
	"encoding/json"
)

func decodeJson(payload []byte) (map[string]interface{}, error) {
	data := map[string]interface{}{}

	err := json.Unmarshal(trimPayload(payload), &data)

	return data, err
}

func trimPayload(payload []byte) []byte {

	result := []byte{}

	for _, v := range payload {
		// trim end of transmission ASCII char
		if v != 0x4 {
			result = append(result, v)
		}
	}

	return result

}
