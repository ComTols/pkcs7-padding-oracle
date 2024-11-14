package cases

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"pkcs7_padding_oracle/internal/env"
	"pkcs7_padding_oracle/pkg/encryption"
)

type PaddingOracle struct {
	Action    string                 `json:"action"`
	Arguments PaddingOracleArguments `json:"arguments"`
}

type PaddingOracleArguments struct {
	Hostname   string `json:"hostname"`
	Port       int    `json:"port"`
	Iv         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

type Response struct {
	Plaintext string `json:"plaintext"`
}

func ProvideTestcases() error {
	plaintexts, err := loadPlaintext()
	if err != nil {
		return err
	}

	testcases := make(map[string]any)
	responses := make(map[string]any)

	for index, plaintext := range plaintexts {
		p := []byte(plaintext)
		padding := 16 - (len(p) % 16)
		for i := 0; i < padding; i++ {
			p = append(p, byte(padding))
		}
		c, err := encryption.Encrypt(p, encryption.Configuration.Key, encryption.Configuration.Iv)
		if err != nil {
			return err
		}

		id := fmt.Sprintf("padding_oracle_%d", index)
		testcases[id] = PaddingOracle{
			Action: "padding_oracle",
			Arguments: PaddingOracleArguments{
				Hostname:   env.GetEnv(env.Host),
				Port:       env.GetEnv(env.Port),
				Iv:         base64.StdEncoding.EncodeToString(encryption.Configuration.Iv),
				Ciphertext: base64.StdEncoding.EncodeToString(c),
			},
		}
		responses[id] = Response{
			Plaintext: base64.StdEncoding.EncodeToString(p),
		}
	}

	for index, spec := range SpecialCases {
		padding := 16 - (len(spec.Content) % 16)
		for i := 0; i < padding; i++ {
			spec.Content = append(spec.Content, byte(padding))
		}

		c, err := encryption.Encrypt(spec.Content, encryption.Configuration.Key, spec.IV)
		if err != nil {
			return err
		}

		id := fmt.Sprintf("padding_oracle_special_case_%d", index)
		testcases[id] = PaddingOracle{
			Action: "padding_oracle",
			Arguments: PaddingOracleArguments{
				Hostname:   env.GetEnv(env.Host),
				Port:       env.GetEnv(env.PortSpecial),
				Iv:         base64.StdEncoding.EncodeToString(spec.IV),
				Ciphertext: base64.StdEncoding.EncodeToString(c),
			},
		}
		responses[id] = Response{
			Plaintext: base64.StdEncoding.EncodeToString(spec.Content),
		}
	}

	marshal, err := json.Marshal(map[string]map[string]any{
		"testcases": testcases,
		"responses": responses,
	})
	if err != nil {
		return err
	}

	file, err := os.OpenFile("test/padding-oracle-test.json", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Println("Error closing file:", err)
		}
	}(file)

	_, err = file.Write(marshal)
	if err != nil {
		return err
	}

	return nil
}

func loadPlaintext() ([]string, error) {
	file, err := os.Open("test/plaintext.json")
	if err != nil {
		fmt.Println("Error opening test/plaintext.json:", err)
		return nil, err
	}
	defer func(file *os.File) {
		err = file.Close()
		if err != nil {
			fmt.Println("Error closing file test/plaintext.json:", err)
		}
	}(file)

	byteValue, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading test/plaintext.json", err)
		return nil, err
	}

	var plaintexts []string
	err = json.Unmarshal(byteValue, &plaintexts)
	if err != nil {
		fmt.Println("Error unmarshalling test/plaintext.json:", err)
		return nil, err
	}
	return plaintexts, nil
}
