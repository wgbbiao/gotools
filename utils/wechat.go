package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
)

//WXBizDataCrypt 解码配置
type WXBizDataCrypt struct {
	AppID      string
	SessionKey string
}

//PhoneNumber 电话号码
type PhoneNumber struct {
	PhoneNumber     string `json:"phoneNumber"`
	PurePhoneNumber string `json:"purePhoneNumber"`
	CountryCode     string `json:"countryCode"`
}

//Decrypt 解码
func (o *WXBizDataCrypt) Decrypt(encryptedData, iv string) (decrypted []byte) {
	_encryptedData, _ := base64.StdEncoding.DecodeString(encryptedData)
	_iv, _ := base64.StdEncoding.DecodeString(iv)
	sessionKey, _ := base64.StdEncoding.DecodeString(o.SessionKey)

	block, _ := aes.NewCipher(sessionKey)
	blockMode := cipher.NewCBCDecrypter(block, _iv)
	decrypted = make([]byte, len(_encryptedData))
	blockMode.CryptBlocks(decrypted, _encryptedData) // 解密
	decrypted = pkcs5UnPadding(decrypted)            // 去除补全码
	return decrypted
}

//GetPhoneNumber 取得电话号码
func (o *WXBizDataCrypt) GetPhoneNumber(encryptedData, iv string) (phoneNumber *PhoneNumber, err error) {
	j := o.Decrypt(encryptedData, iv)
	err = json.Unmarshal(j, &phoneNumber)
	return
}

func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}
