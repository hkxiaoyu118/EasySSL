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

//比较两个hash值是否相同，而不会泄露对比时间信息。
//（以避免时间侧信道攻击：指通过计算比较hash值花费的时间的长短来获取密码的信息，用于密码破解），
//这个方法只要传入的数据长短相同，那么比较的时间就是一样的，举个栗子：比较[1,2,3],[1,2,2]与[1,2,3],[3,4,5]，这个方法执行的时间都是一样的，
//比较的时候不会因为后面一组数据第一个值不同就立即返回而使得后面一组数据的比较时间比前面一组的比较时间段。
//这样做是为了防止黑客用暴力破解的方式不断收集每个hash与正确hash的比较时间，从而来逐步确定正确hash的值，从而达到破解hash密文的目的。
func CheckMac(mac1 []byte, mac2 []byte) bool {
	return hmac.Equal(mac1, mac2)
}

func HmacTest() {
	str := "住宿的房间绿色科技sdfasdf"
	key := "123123"
	fmt.Println(HmacMd5([]byte(str), []byte(key)))
	fmt.Println(HmacSha1([]byte(str), []byte(key)))
	fmt.Println(HmacSha256([]byte(str), []byte(key)))
	fmt.Println(HmacSha512([]byte(str), []byte(key)))
}
