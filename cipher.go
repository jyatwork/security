package security

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"errors"
)

//encrypt:
//*********先判断用AES-128 AES-192 AES-256哪种块大小，用pcks7方式填充。
//*********填充后，AES加密
//*********base64编码
const (
	//`互联网通讯统一密钥`
	UNIFORM_AES_KEY_COMM = "XXXXXXXXXXXXXXXX"
)

const (
	EncryptKey_Uniform = 1 //1
)

func GetKey(encryptKeyType int) string {
	var key string
	switch encryptKeyType {
	case 1:
		key = UNIFORM_AES_KEY_COMM
	default:
		key = ""
	}
	return key
}

//AesEncrypt 把二进制 data用key加密,然后转为base64字符串
func AesEncrypt(data []byte, key string) string {
	return base64.StdEncoding.EncodeToString(AesEncryptNonBase64(data, key))
}

func AesEncryptNonBase64(data []byte, key string) []byte {

	aesCipher, _ := aes.NewCipher([]byte(key))
	encrypter := NewECBEncrypter(aesCipher)

	blockSize := aesCipher.BlockSize()
	origData := PKCS7Padding(data, blockSize)

	dest := make([]byte, len(origData))

	encrypter.CryptBlocks(dest, origData)

	return dest
}

//AesEncryptString 把字符串data用key加密,然后转为base64字符串
func AesEncryptString(data string, key string) string {

	return AesEncrypt([]byte(data), key)
}

//AesDecryptNonBase64 使用encryptKeyType 类型密钥 解密二进制data(二进制格式)
func AesDecryptNonBase64(data []byte, encryptKeyType int) ([]byte, error) {
	//创建一个cipher.Block接口。参数key为密钥，长度只能是16、24、32字节(128\192\256位)，用以选择AES-128、AES-192、AES-256。
	aesCipher, _ := aes.NewCipher([]byte(GetKey(encryptKeyType)))
	decrypter := NewECBDecrypter(aesCipher)

	if len(data)%decrypter.BlockSize() != 0 {
		return nil, errors.New("数据长度错误.")
	}
	//blockSize := aesCipher.BlockSize()

	dest := make([]byte, len(data))

	decrypter.CryptBlocks(dest, data)

	dest = PKCS7UnPadding(dest)

	return dest, nil

}

//AesDecrypt2 使用 key 密钥 解密 data(base64格式 string)
func AesDecrypt(data string, key string) ([]byte, error) {

	dataBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	aesCipher, _ := aes.NewCipher([]byte(key))
	decrypter := NewECBDecrypter(aesCipher)

	//blockSize := aesCipher.BlockSize()

	dest := make([]byte, len(dataBytes))

	decrypter.CryptBlocks(dest, dataBytes)

	dest = PKCS7UnPadding(dest)

	return dest, nil
}

//填充 PKCS7 Padding
// 在数据包末尾填充.
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//解除填充 PKCS7
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)

	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])

	//如果最后一位是0或者填充值>=长度, 说明不符合pkcs7填充,属于非法填充的数据包,
	//直接返回原始数据, 避免crash
	if unpadding == 0 || unpadding >= length {
		return origData
	}

	//返回解除填充后的数据.
	return origData[:(length - unpadding)]
}
