package adscoreStruct

import (
	"net/url"
)

func decodeRFC3986Struct(payload []byte) (map[string]interface{}, error) {
	queryValues, err := url.ParseQuery(string(payload))

	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{}

	for key, value := range queryValues {

		if len(value) == 1 {
			result[key] = value[0]
		} else {
			result[key] = value
		}

	}

	return result, nil
}
