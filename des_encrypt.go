package mysqlfuncs

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"fmt"
	"github.com/rnben/mysql-funcs-go/openssl"
)

// DesEncrypt MySQL DES_ENCRYPT
func DesEncrypt(plainText, plainKey string) (res []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			return
		}
	}()

	if plainText == "" {
		return nil, nil
	}

	orgLength := len(plainText)
	resLength := orgLength + (8 - (orgLength % 8))

	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	text := padding([]byte(plainText), 8)
	key, _ := openssl.EVPBytesToKey(24, 8, md5.New(), nil, []byte(plainKey), 1)

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, resLength)
	blockMode.CryptBlocks(cipherText, text)

	cipherText = append([]byte{255}, cipherText...)

	return cipherText, nil
}

func padding(ciphertext []byte, blockSize int) []byte {
	tail := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte("*"), tail)
	padText[len(padText)-1] = byte(tail)
	return append(ciphertext, padText...)
}
