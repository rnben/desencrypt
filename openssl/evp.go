package openssl

import "hash"

func EVPBytesToKey(keyLen int, ivLen int, md hash.Hash, salt []byte, data []byte, count int) ([]byte, []byte) {
	key := make([]byte, keyLen)
	keyIx := 0
	iv := make([]byte, ivLen)
	ivIx := 0
	var mdBuf []byte
	nkey := keyLen
	niv := ivLen
	i := 0
	if data == nil {
		return key, iv
	}

	addmd := 0
	for {
		md.Reset()
		if addmd > 0 {
			md.Write(mdBuf)
		}
		addmd++
		md.Write(data)
		if salt != nil {
			md.Write(salt[:8])
		}
		mdBuf = md.Sum(nil)
		for i = 1; i < count; i++ {
			md.Reset()
			md.Write(mdBuf)
			mdBuf = md.Sum(nil)
		}
		i = 0
		if nkey > 0 {
			for {
				if nkey == 0 {
					break
				}
				if i == len(mdBuf) {
					break
				}
				key[keyIx] = mdBuf[i]
				keyIx++
				nkey--
				i++
			}
		}
		if niv > 0 && i != len(mdBuf) {
			for {
				if niv == 0 {
					break
				}
				if i == len(mdBuf) {
					break
				}
				iv[ivIx] = mdBuf[i]
				ivIx++
				niv--
				i++
			}
		}
		if nkey == 0 && niv == 0 {
			break
		}
	}
	for i = 0; i < len(mdBuf); i++ {
		mdBuf[i] = 0
	}

	return key, iv
}
