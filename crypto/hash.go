package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash/crc32"
)

func MD5(data []byte) string {
	c := md5.New()
	c.Write(data)
	return hex.EncodeToString(c.Sum(nil))
}

func SHA1(data []byte) string {
	c := sha1.New()
	c.Write(data)
	return hex.EncodeToString(c.Sum(nil))
}

func SHA256(data []byte) string {
	c := sha256.New()
	c.Write(data)
	return hex.EncodeToString(c.Sum(nil))
}

func SHA512(data []byte) string {
	c := sha512.New()
	c.Write(data)
	return hex.EncodeToString(c.Sum(nil))
}

func CRC32(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}

func HashTest() {
	str := "住宿的房间绿色科技sdfasdf"
	fmt.Println(MD5([]byte(str)))
	fmt.Println(SHA1([]byte(str)))
	fmt.Println(SHA256([]byte(str)))
	fmt.Println(SHA512([]byte(str)))
	fmt.Println(CRC32([]byte(str)))
}
