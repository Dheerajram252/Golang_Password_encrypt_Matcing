package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"strings"
	"unicode"
)

const (
	emptySeparator = ""
	radix          = 16
	r              = 8
	saltLength     = 8
)

var (
	HEX = []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"}
)

func main() {
	fmt.Println(encode("hello"))
	fmt.Println(matches("hello", "7196f3f4a1a487cc79c2e51c49d1f5e0f3e9a4798a9750b9d687a585edd947759aa64c0a2953d737"))
}

func encode(rawPassword string) string {
	encodedPassword := hexEncode(digest(rawPassword, saltGenerator()))
	return strings.Join(encodedPassword, emptySeparator)
}

func hexEncode(encodedValue []byte) []string {
	var encodedPassword []string
	for i := 0; i < len(encodedValue); i = i + 1 {
		encodedPassword = append(encodedPassword, HEX[(240&encodedValue[i])>>4])
		encodedPassword = append(encodedPassword, HEX[15&encodedValue[i]])
	}
	return encodedPassword
}

func digest(rawPassword string, salt []byte) []byte {
	checksum := append(salt, utfEncode(rawPassword)...)
	checksum32 := sha256.Sum256(checksum)
	for i := 0; i < 1023; i++ {
		checksum32 = sha256.Sum256(checksum32[:])
	}
	return append(salt, checksum32[:]...)
}

func saltGenerator() []byte {
	buf := make([]byte, saltLength)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		log.Println("random read failed: " + err.Error())
	}
	return buf
}

func utfEncode(rawPassword string) []byte {
	buf := make([]byte, len(rawPassword))

	for i := 0; i < len(rawPassword); i++ {
		buf[i] = byte(rawPassword[i])
	}
	return buf
}

func matches(rawPassword string, encodedPassword string) bool {
	if strings.TrimSpace(encodedPassword) == "" {
		return false
	}
	hd := hexDecode(encodedPassword)
	if len(hd) < r {
		return false
	}
	salt := hexDecode(encodedPassword)[0:saltLength]
	return bytes.Equal(hd, digest(rawPassword, salt))
}

func hexDecode(encodedPassword string) []byte {
	var strLength = len(encodedPassword)
	if strLength%2 != 0 {
		return nil
	}
	result := make([]byte, strLength/2)
	for i := 0; i < strLength; i += 2 {
		msb := digit(rune(encodedPassword[i]))
		lsb := digit(rune(encodedPassword[i+1]))
		result[i/2] = byte(msb<<4 | lsb)
	}
	return result
}

func digit(value rune) int32 {
	if unicode.IsDigit(value) {
		return value - []rune("0")[0]
	}
	if value >= 0 && value <= 9 {
		return value - 0
	} else if value >= []rune("a")[0] && value < []rune("a")[0]+radix-10 {
		return value - []rune("a")[0] + 10
	} else if value >= []rune("A")[0] && value < []rune("A")[0]+radix-10 {
		return value - []rune("A")[0] + 10
	}
	return -1
}
