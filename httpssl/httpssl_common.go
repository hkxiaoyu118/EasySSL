package httpssl

import (
	"encoding/hex"
	"math/rand"
	"time"
)

func StrGetRandString(length int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	bytes := []byte(str)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

func RandHexString(length int) string {
	r := make([]byte, length)
	_, _ = rand.Read(r)
	return hex.EncodeToString(r)
}

type Package struct {
	AesKey  string `json:"aes_key"`
	Content string `json:"content"`
}

// 生成随机的AES密钥
func GenRandAesKey() string {
	return StrGetRandString(16)
}
