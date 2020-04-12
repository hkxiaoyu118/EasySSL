package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

func HmacMd5(data []byte, key []byte) string {
	hash := hmac.New(md5.New, key)
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

func HmacSha1(data []byte, key []byte) string {
	hash := hmac.New(sha1.New, key)
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

func HmacSha256(data []byte, key []byte) string {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

func HmacSha512(data []byte, key []byte) string {
	hash := hmac.New(sha512.New, key)
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

func HmacTest() {
	str := "住宿的房间绿色科技sdfasdf"
	key := "123123"
	fmt.Println(HmacMd5([]byte(str), []byte(key)))
	fmt.Println(HmacSha1([]byte(str), []byte(key)))
	fmt.Println(HmacSha256([]byte(str), []byte(key)))
	fmt.Println(HmacSha512([]byte(str), []byte(key)))
}
