package httpssl

import (
	"EasySSL/crypto"
	"encoding/hex"
	"encoding/json"
)

func EncodePackageWithPri(privateKey string, content string) (string, error) {
	aesKey := GenRandAesKey()
	cryptContent := crypto.AESEcbEncrypt([]byte(content), []byte(aesKey))
	cryptAesKey, err := crypto.RsaEncryptPrivate([]byte(privateKey), []byte(aesKey))
	if err == nil {
		pack := Package{}
		pack.AesKey = hex.EncodeToString(cryptAesKey)
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

func DecodePackageWithPri(privateKey string, data string) (string, error) {
	jsonStr, err := hex.DecodeString(data)
	if err == nil {
		pack := Package{}
		err = json.Unmarshal(jsonStr, &pack)
		if err == nil {
			aesKey, err := hex.DecodeString(pack.AesKey)
			if err == nil {
				aesKey, err = crypto.RsaDecryptPrivate([]byte(privateKey), aesKey)
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
