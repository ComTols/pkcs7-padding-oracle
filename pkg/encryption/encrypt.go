package encryption

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

func Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%16 != 0 {
		return nil, errors.New("length of plaintext must be a multiple of 16")
	}

	cipher, err := aes.NewCipher(Configuration.Key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, 0)
	vector := binary.BigEndian.Uint16(Configuration.Iv)
	for i := 0; i < len(plaintext); i += 16 {
		block := binary.BigEndian.Uint16(plaintext[i : i+16])
		b := make([]byte, 16)
		binary.BigEndian.PutUint16(b, block^vector)

		c := make([]byte, 16)
		cipher.Encrypt(c, b)
		ciphertext = append(ciphertext, c...)
		vector = binary.BigEndian.Uint16(c)
	}

	return ciphertext, nil
}
