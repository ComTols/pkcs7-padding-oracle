package encryption

import (
	"crypto/aes"
	"errors"
)

func Encrypt(plain []byte) ([]byte, error) {
	if len(plain) == 0 || len(plain)%16 != 0 {
		return nil, errors.New("length of plaintext must be a multiple of 16")
	}
	plaintext := make([]byte, len(plain))
	copy(plaintext, plain)

	cipher, err := aes.NewCipher(Configuration.Key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, 0)
	vector := Configuration.Iv
	for i := 0; i < len(plaintext); i += 16 {
		block := Bytes(plaintext[i : i+16])

		err = block.Xor(vector)
		if err != nil {
			return nil, err
		}

		c := make([]byte, 16)
		cipher.Encrypt(c, block)
		ciphertext = append(ciphertext, c...)
		vector = c
	}

	return ciphertext, nil
}
