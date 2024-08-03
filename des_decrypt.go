package mysqlfuncs

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"errors"
	"fmt"
	"github.com/rnben/mysql-funcs-go/openssl"
)

// DesDecrypt MySQL DES_DECRYPT
func DesDecrypt(encrypted []byte, plainKey string) (res string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("err: %v", r)
			return
		}
	}()

	length := len(encrypted)

	if length == 0 {
		return "", nil
	}
	if encrypted[0] != 0xff {
		return "", errors.New("invalid encrypted text")
	}

	encrypted = encrypted[1:]
	if len(encrypted)%8 != 0 {
		return "", errors.New("invalid encrypted text")
	}

	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	key, _ := openssl.EVPBytesToKey(24, 8, md5.New(), nil, []byte(plainKey), 1)

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, length-1)
	blockMode.CryptBlocks(decrypted, encrypted)
	return string(unPadding(decrypted)), nil
}

func unPadding(decrypted []byte) []byte {
	length := len(decrypted)
	tail := int(decrypted[length-1])
	return decrypted[:(length - tail)]
}
