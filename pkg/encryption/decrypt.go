package encryption

import (
	"crypto/aes"
	"errors"
)

func Decrypt(ci Bytes) ([]byte, error) {
	if len(ci) == 0 || len(ci)%16 != 0 {
		return nil, errors.New("length of ciphertext must be a multiple of 16")
	}

	ciphertext := make([]byte, len(ci))
	copy(ciphertext, ci)

	cipher, err := aes.NewCipher(Configuration.Key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, 0)
	vector := Configuration.Iv
	for i := 0; i < len(ciphertext); i += 16 {
		block := ciphertext[i : i+16]

		p := make(Bytes, 16)
		cipher.Decrypt(p, block)

		err = p.Xor(vector)
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, p...)
		vector = block
	}

	return plaintext, nil
}
