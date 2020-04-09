package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
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
