package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:length-unpadding]
}

func PKCS7Padding(origData []byte, blockSize int) []byte {
	padding := blockSize - len(origData)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(origData, padText...)
}

func UnPadding(origData []byte) []byte {
	length := len(origData)
	paddingChar := int(origData[length-1])
	paddingCount := 0
	for {
		if paddingChar != 0 {
			break
		} else {
			paddingCount++
			paddingChar = int(origData[length-(paddingCount+1)])
		}
	}
	return origData[:length-paddingCount]
}

func Padding(origData []byte, blockSize int) []byte {
	padding := blockSize - len(origData)%blockSize
	padText := bytes.Repeat([]byte{byte(0)}, padding)
	return append(origData, padText...)
}

func AESEcbEncrypt(origData []byte, key []byte) string {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	encryptData := make([]byte, len(origData))
	for index := 0; index < len(origData); index += blockSize {
		block.Encrypt(encryptData[index:index+blockSize], origData[index:index+blockSize])
	}
	encodeString := hex.EncodeToString(encryptData)
	return encodeString
}

func AESEcbDecrypt(encryptData string, key []byte) []byte {
	decodeData, _ := hex.DecodeString(encryptData)
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	origData := make([]byte, len(decodeData))
	for index := 0; index < len(decodeData); index += blockSize {
		block.Decrypt(origData[index:index+blockSize], decodeData[index:index+blockSize])
	}
	origData = PKCS7UnPadding(origData)
	return origData
}

func AESCbcEncrypt(origData []byte, key []byte, iv []byte) string {
	block, _ := aes.NewCipher(key)
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	encryptData := make([]byte, len(origData))
	blockMode.CryptBlocks(encryptData, origData)
	encodeString := hex.EncodeToString(encryptData)
	return encodeString
}

func AESCbcDecrypt(encryptData string, key []byte, iv []byte) []byte {
	decodeData, _ := hex.DecodeString(encryptData)
	block, _ := aes.NewCipher(key)
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(decodeData))
	blockMode.CryptBlocks(origData, decodeData)
	origData = PKCS7UnPadding(origData)
	return origData
}

func AESCtrEncrypt(origData []byte, key []byte, iv []byte) string {
	block, _ := aes.NewCipher(key)
	blockMode := cipher.NewCTR(block, iv)
	message := make([]byte, len(origData))
	blockMode.XORKeyStream(message, origData)
	encodeString := hex.EncodeToString(message)
	return encodeString
}

func AESCtrDecrypt(encryptData string, key []byte, iv []byte) []byte {
	cryptData, _ := hex.DecodeString(encryptData)
	block, _ := aes.NewCipher(key)
	blockMode := cipher.NewCTR(block, iv)
	origData := make([]byte, len(cryptData))
	blockMode.XORKeyStream(origData, cryptData)
	return origData
}

func AESCfbEncrypt(origData []byte, key []byte, iv []byte) string {
	block, _ := aes.NewCipher(key)
	origData = PKCS7Padding(origData, block.BlockSize())
	blockMode := cipher.NewCFBEncrypter(block, iv)
	encryptData := make([]byte, len(origData))
	blockMode.XORKeyStream(encryptData, origData)
	encodeString := hex.EncodeToString(encryptData)
	return encodeString
}

func AESCfbDecrypt(encryptData string, key []byte, iv []byte) []byte {
	decodeData, _ := hex.DecodeString(encryptData)
	block, _ := aes.NewCipher(key)
	blockMode := cipher.NewCFBDecrypter(block, iv)
	origData := make([]byte, len(decodeData))
	blockMode.XORKeyStream(origData, decodeData)
	origData = PKCS7UnPadding(origData)
	return origData
}

func AESOfbEncrypt(origData []byte, key []byte, iv []byte) string {
	block, _ := aes.NewCipher(key)
	origData = PKCS7Padding(origData, block.BlockSize())
	blockMode := cipher.NewOFB(block, iv)
	encryptData := make([]byte, len(origData))
	blockMode.XORKeyStream(encryptData, origData)
	encodeString := hex.EncodeToString(encryptData)
	return encodeString
}

func AESOfbDecrypt(encryptData string, key []byte, iv []byte) []byte {
	decodeData, _ := hex.DecodeString(encryptData)
	block, _ := aes.NewCipher(key)
	blockMode := cipher.NewOFB(block, iv)
	origData := make([]byte, len(decodeData))
	blockMode.XORKeyStream(origData, decodeData)
	origData = PKCS7UnPadding(origData)
	return origData
}
