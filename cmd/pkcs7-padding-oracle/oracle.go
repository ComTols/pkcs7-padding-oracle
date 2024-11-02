package main

import (
	"fmt"
	"os"
	"os/signal"
	"pkcs7_padding_oracle/internal/cases"
	"pkcs7_padding_oracle/internal/env"
	"pkcs7_padding_oracle/pkg/encryption"
	"pkcs7_padding_oracle/pkg/server"
	"runtime"
	"syscall"
)

func main() {
	logPath := "/var/log/padding-oracle/logfile.log"
	if runtime.GOOS == "windows" {
		logPath = "logfile.log"
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Fehler beim Öffnen der Logdatei:", err)
		return
	}
	defer func(logFile *os.File) {
		err := logFile.Close()
		if err != nil {
			fmt.Println("Error closing file:", err)
		}
	}(logFile)

	// Umleitung von stdout und stderr auf die Logdatei
	os.Stdout = logFile
	os.Stderr = logFile

	err = encryption.Load()
	if err != nil {
		fmt.Println("Error loading encrypted files:", err)
		return
	}

	err = cases.ProvideTestcases()
	if err != nil {
		fmt.Println("Error providing testcases:", err)
		return
	}

	var ser = server.Server{
		Host: env.GetEnv(env.Host),
		Port: env.GetEnv(env.Port),
	}

	go ser.Run()

	sigChannel := make(chan os.Signal, 1)

	signal.Notify(sigChannel, syscall.SIGTERM, syscall.SIGINT)
	<-sigChannel

	fmt.Println("Shutting down...")
}
