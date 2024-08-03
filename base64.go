package mysqlfuncs

import "encoding/base64"

// ToBase64 MySQL TO_BASE64
func ToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// FromBase64 MySQL FROM_BASE64
func FromBase64(b string) ([]byte, error) {
	if b == "" {
		return nil, nil
	}

	return base64.StdEncoding.DecodeString(b)
}
