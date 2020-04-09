package httpssl

import (
	"EasySSL/crypto"
	"encoding/hex"
	"encoding/json"
)

func EncodePackageWithPub(pubkey string, content string) (string, error) {
	aesKey := GenRandAesKey()
	cryptContent := crypto.AESEcbEncrypt([]byte(content), []byte(aesKey))
	cryptKey, err := crypto.RsaEncryptPublic([]byte(pubkey), []byte(aesKey))
	if err == nil {
		pack := Package{}
		pack.AesKey = hex.EncodeToString(cryptKey)
		pack.Content = cryptContent

		data, err := json.Marshal(pack)
		if err == nil {
			data := hex.EncodeToString(data)
			return data, nil
		} else {
			return "", err
		}
	}
	return "", err
}

func DecodePackageWithPub(pubkey string, data string) (string, error) {
	jsonStr, err := hex.DecodeString(data)
	if err == nil {
		pack := Package{}
		err = json.Unmarshal(jsonStr, &pack)
		if err == nil {
			aesKey, err := hex.DecodeString(pack.AesKey)
			if err == nil {
				aesKey, err = crypto.RsaDecryptPublic([]byte(pubkey), aesKey)
				if err == nil {
					content := crypto.AESEcbDecrypt(pack.Content, aesKey)
					return string(content), nil
				}
			}
			return "", err
		}
	}
	return "", err
}
