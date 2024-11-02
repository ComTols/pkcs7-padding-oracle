package encryption

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Config struct {
	Key []byte `json:"key"`
	Iv  []byte `json:"iv"`
}

var Configuration *Config

func Load() error {
	conf, err := loadFromFile()
	if err != nil {
		conf, err = createConfigFile()
		if err != nil {
			return err
		}
	}
	Configuration = conf
	return nil
}

func loadFromFile() (*Config, error) {
	file, err := os.OpenFile("encryption_key.json", os.O_RDONLY, 0600)
	if err != nil {
		fmt.Println("Error opening encryption_key.json:", err)
		return nil, err
	}
	defer func(file *os.File) {
		err = file.Close()
		if err != nil {
			fmt.Println("Error closing file encryption_key.json:", err)
		}
	}(file)

	byteValue, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading encryption_key.json", err)
		return nil, err
	}

	var conf struct {
		Key string `json:"key"`
		Iv  string `json:"iv"`
	}
	err = json.Unmarshal(byteValue, &conf)
	if err != nil {
		fmt.Println("Error parsing encryption_key.json:", err)
		return nil, err
	}

	return &Config{
		Key: func() []byte {
			decodeString, err := hex.DecodeString(conf.Key)
			if err != nil {
				fmt.Println("Error decoding encryption_key.json:", err)
				return nil
			}
			return decodeString
		}(),
		Iv: func() []byte {
			decodeString, err := hex.DecodeString(conf.Iv)
			if err != nil {
				fmt.Println("Error decoding encryption_key.json:", err)
				return nil
			}
			return decodeString
		}(),
	}, nil
}

func createConfigFile() (*Config, error) {
	conf := Config{
		Key: make([]byte, 16),
		Iv:  make([]byte, 16),
	}
	_, err := rand.Read(conf.Key)
	if err != nil {
		return nil, err
	}
	_, err = rand.Read(conf.Iv)
	if err != nil {
		return nil, err
	}

	var save struct {
		Key string `json:"key"`
		Iv  string `json:"iv"`
	}
	save.Key = hex.EncodeToString(conf.Key)
	save.Iv = hex.EncodeToString(conf.Iv)

	marshal, err := json.Marshal(&save)
	if err != nil {
		fmt.Println("Error marshalling Configuration:", err)
		return nil, err
	}

	file, err := os.OpenFile("encryption_key.json", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("Error opening encryption_key.json:", err)
		return nil, err
	}
	defer func(file *os.File) {
		err = file.Close()
		if err != nil {
			fmt.Println("Error closing file encryption_key.json:", err)
		}
	}(file)

	_, err = file.Write(marshal)
	if err != nil {
		fmt.Println("Error writing Configuration:", err)
		return nil, err
	}

	return &conf, nil
}
