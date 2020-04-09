package httpssl

import "fmt"

var Pubkey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCroDvs9YJJWK9QaQ6JRnSWh4EI
DqAYhtLFyZsk4Dr5AA47Rj6IiPqEGucUVd9zGSl2s5d9GyDN44auxUllEJHY3Lhq
QfQWmtzWbn6RtqEAyQH9SI2vK0U8XOgdJEN7kD/9Xdeu3C3Hzz2drF27c56ffeoi
lYGB2OdBUXHO8TNt/QIDAQAB
-----END PUBLIC KEY-----
`

var Pirvatekey = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCroDvs9YJJWK9QaQ6JRnSWh4EIDqAYhtLFyZsk4Dr5AA47Rj6I
iPqEGucUVd9zGSl2s5d9GyDN44auxUllEJHY3LhqQfQWmtzWbn6RtqEAyQH9SI2v
K0U8XOgdJEN7kD/9Xdeu3C3Hzz2drF27c56ffeoilYGB2OdBUXHO8TNt/QIDAQAB
AoGATibaAu5NFL84neIpB2O45W7w181pI6IJSp2icylUUVywHle/VAckJJHnlgAA
j3XuxqnDGuoGhxrLkrwtzsK71ogrY2HqbAIod0xa/Gf+QY2ZR6N3qZ2Y2PmM87zr
urtlbxuzJndA4uzId3epd+R1kKWzRuhl42rsM2JI9loFgcECQQDjZc0TMdwsKTxJ
hOeQU/gWI2Gp4jtDPiLlX6bPqzTA33Sraq8l1ik/VpaTdLxWc+uvuQFJuWfTy3zm
7imNt3XNAkEAwTaVjdMEOL2OunT8va8LSmNhL+WCbVRTCDA0+4yAbc6SNYZLbcap
uahr803CnMFi9kLu6QoYc6aYObfj++uo8QJBALjy2IvPFssYMr99CDX8BaBD4LAi
n56+T/WNCYiIMBza4fJ1j8TPXbb1PvzpijEqkTvX1fNXh9nb/Fd6x3NLDtUCQGeQ
EmmKieC/+hkHS9GAWdTtn9JEeryPTlI9RKjwjoZNCyGVcijNK3xQQkyPiZjsL1dA
WT6gIqsayM1nO9R0ZIECQQClN4D6Bu+z+45I9hLC0XNJ8qT5jsMJzqwwev3MFtMV
yARvxykHbHTSlGGaS8J3aoq97lmyXnJwYNl2qZ+iYpeR
-----END RSA PRIVATE KEY-----
`

func HttpsslTest() {

	str := "你好，世界"
	c, err := EncodePackageWithPub(Pubkey, str)
	if err == nil {
		fmt.Println(c)
		d, err := DecodePackageWithPri(Pirvatekey, c)
		if err == nil {
			fmt.Println(d)
		} else {
			fmt.Println("DecodePackageWithPri 发生了错误:" + err.Error())
			return
		}
	} else {
		fmt.Println("EncodePackageWithPub 发生了错误:" + err.Error())
		return
	}

	//私钥加密,公钥解密
	c, err = EncodePackageWithPri(Pirvatekey, str)
	if err == nil {
		fmt.Println(c)
		d, err := DecodePackageWithPub(Pubkey, c)
		if err == nil {
			fmt.Println(d)
		} else {
			fmt.Println("DecodePackageWithPub 发生了错误:" + err.Error())
			return
		}
	} else {
		fmt.Println("EncodePackageWithPri 发生了错误:" + err.Error())
		return
	}

	fmt.Println("完成")
}
