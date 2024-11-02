package main

import (
	"fmt"
	"os"
	"os/signal"
	"pkcs7_padding_oracle/internal/cases"
	"pkcs7_padding_oracle/internal/env"
	"pkcs7_padding_oracle/pkg/encryption"
	"pkcs7_padding_oracle/pkg/server"
	"syscall"
)

func main() {
	err := encryption.Load()
	if err != nil {
		fmt.Println("Error loading encrypted files:", err)
		return
	}

	err = cases.ProvideTestcases()
	if err != nil {
		fmt.Println("Error providing testcases:", err)
		return
	}

	var server = server.Server{
		Host: env.GetEnv(env.Host),
		Port: env.GetEnv(env.Port),
	}

	go server.Run()

	sigChannel := make(chan os.Signal, 1)

	signal.Notify(sigChannel, syscall.SIGTERM, syscall.SIGINT)
	<-sigChannel

	fmt.Println("Shutting down...")
}
