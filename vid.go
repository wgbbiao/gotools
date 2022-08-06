package gotools

import (
	"bytes"
	"crypto/rc4"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"math"
	"strconv"
	"strings"
)

const tolerance = 0.00000001
const code62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const codeLength = 62

var edoc = map[string]int{"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9, "a": 10, "b": 11, "c": 12, "d": 13, "e": 14, "f": 15, "g": 16, "h": 17, "i": 18, "j": 19, "k": 20, "l": 21, "m": 22, "n": 23, "o": 24, "p": 25, "q": 26, "r": 27, "s": 28, "t": 29, "u": 30, "v": 31, "w": 32, "x": 33, "y": 34, "z": 35, "A": 36, "B": 37, "C": 38, "D": 39, "E": 40, "F": 41, "G": 42, "H": 43, "I": 44, "J": 45, "K": 46, "L": 47, "M": 48, "N": 49, "O": 50, "P": 51, "Q": 52, "R": 53, "S": 54, "T": 55, "U": 56, "V": 57, "W": 58, "X": 59, "Y": 60, "Z": 61}

type Crypto struct {
	Vid string
	Rid string
}

var CryptoClient *Crypto = &Crypto{}

func SetCrypto(vid, rid string) {
	CryptoClient.Vid = vid
	CryptoClient.Rid = rid
}
func CacheEncode(data interface{}) ([]byte, error) {
	return GobEncode(data)
}

func CacheDecode(data []byte, to interface{}) error {
	return GobDecode(data, to)
}

func GobEncode(data interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(&data)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func GobDecode(data []byte, to interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(to)
}

func B62Encode(number int) string {
	if number == 0 {
		return "0"
	}
	result := make([]byte, 0)
	for number > 0 {
		round := number / codeLength
		remain := number % codeLength
		result = append(result, code62[remain])
		number = round
	}
	return string(result)
}

func B62Decode(str string) int {
	str = strings.TrimSpace(str)
	var result int
	for index, char := range []byte(str) {
		result += edoc[string(char)] * int(math.Pow(codeLength, float64(index)))
	}
	return result
}

//IDToVid id转vid
func IDToVid(id int) (vid string, err error) {
	dst, err := AesEncrypt([]byte(strconv.Itoa(id)), []byte(CryptoClient.Vid))
	if err == nil {
		vid = base64.RawURLEncoding.EncodeToString(dst)
	}
	return
}

//IDToRid id转rid
func IDToRid(id int) (rid string, err error) {
	rc, err := rc4.NewCipher([]byte(CryptoClient.Rid))
	if err == nil {
		src := []byte(strconv.Itoa(id))
		rc.XORKeyStream(src, src)
		rid = fmt.Sprintf("%x", src)
	}
	return
}

//VidToID vid转id
func VidToID(vid string) (id int, err error) {
	dst, err := base64.RawURLEncoding.DecodeString(vid)
	if err == nil {
		t, err := AesDecrypt(dst, []byte(CryptoClient.Vid))
		if err == nil {
			return strconv.Atoi(string(t))
		}
	}
	return
}

func round(num float64) int {
	return int(num + math.Copysign(0.5, num))
}

//ToFixed 四舍五入
func ToFixed(num float64, precision int) float64 {
	output := math.Pow(10, float64(precision))
	return float64(round(num*output)) / output
}

//IsEqual 判定浮点数相等
func IsEqual(f1, f2 float64) bool {
	return math.Dim(f1, f2) < tolerance
}
