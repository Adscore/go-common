package utils

import (
	"encoding/binary"
	"errors"
	"strings"
)

func Unpack(format string, input []byte) (map[string]*int, error) {

	var instructions = strings.Split(format, "/")

	var currentBytesOffset int = 0

	var result = map[string]*int{}

	for _, instruction := range instructions {

		var code, name = getCodeAndName(instruction)

		var bytesOffset, decodedData, err = decode(input, code, currentBytesOffset)

		if err != nil {
			return nil, err
		}

		currentBytesOffset += bytesOffset

		result[name] = &decodedData

	}

	return result, nil

}

func getCodeAndName(instruction string) (code string, name string) {

	return instruction[0:1], instruction[1:]

}

func decode(input []byte, code string, offset int) (bytesOffset int, decodedData int, err error) {

	var data = input[offset:]

	if offset > len(input) {
		return 0, 0, errors.New("buffer overflow during unpack")
	}

	switch code {
	// signed char
	case "c":
		return 1, int(int8(data[0])), nil

	// unsigned char
	case "C":
		return 1, int(uint8(data[0])), nil

	// unsigned short (always 16 bit, big endian byte order)
	case "n":
		return 2, int(binary.BigEndian.Uint16(data)), nil

	// 	unsigned long (always 32 bit, big endian byte order)
	case "N":
		return 4, int(binary.BigEndian.Uint32(data)), nil

	// unsigned long long (always 64 bit, big endian byte order)
	case "J":
		return 8, int(binary.BigEndian.Uint64(data)), nil

	// 	unsigned short (always 16 bit, little endian byte order)
	case "v":
		return 2, int(binary.LittleEndian.Uint16(data)), nil
	}

	return 0, 0, errors.New("unrecognized instruction: " + code)

}
