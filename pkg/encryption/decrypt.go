package encryption

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

func Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%16 != 0 {
		return nil, errors.New("length of ciphertext must be a multiple of 16")
	}

	cipher, err := aes.NewCipher(Configuration.Key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, 0)
	vector := binary.BigEndian.Uint16(Configuration.Iv)
	for i := 0; i < len(ciphertext); i += 16 {
		block := binary.BigEndian.Uint16(ciphertext[i : i+16])
		b := make([]byte, 16)
		binary.BigEndian.PutUint16(b, block^vector)

		c := make([]byte, 16)
		cipher.Encrypt(c, b)
		plaintext = append(plaintext, c...)
		vector = binary.BigEndian.Uint16(c)
	}

	return plaintext, nil
}
