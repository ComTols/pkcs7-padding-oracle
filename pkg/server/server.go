package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"pkcs7_padding_oracle/pkg/encryption"
	"time"
)

type Server struct {
	Host        string
	Port        int
	PortSpecial int
}

type Client struct {
	conn net.Conn
}

func (server *Server) Run() {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", server.Host, server.Port))
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	defer func(listener net.Listener) {
		err := listener.Close()
		if err != nil {
			fmt.Println("Error closing listener:", err)
		}
	}(listener)
	fmt.Printf("Server listing to %s:%d\n", server.Host, server.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		fmt.Printf("Connection accepted from %s\n", conn.RemoteAddr().String())

		client := &Client{
			conn: conn,
		}
		go client.handleRequest(encryption.Configuration.Key, encryption.Configuration.Iv)
	}
}

func (server *Server) RunSpecial() {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", server.Host, server.PortSpecial))
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	defer func(listener net.Listener) {
		err := listener.Close()
		if err != nil {
			fmt.Println("Error closing listener:", err)
		}
	}(listener)
	fmt.Printf("Server listing to %s:%d\n", server.Host, server.PortSpecial)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		fmt.Printf("Connection accepted from %s\n", conn.RemoteAddr().String())

		client := &Client{
			conn: conn,
		}
		go client.handleRequest(encryption.Configuration.Key, make([]byte, 16))
	}
}

func (client *Client) handleRequest(key, iv []byte) {
	defer func(conn net.Conn) {
		fmt.Println("Closing connection")
		err := conn.Close()
		if err != nil {
			fmt.Println("Error closing connection:", err.Error())
		}
	}(client.conn)

	err := client.conn.SetReadDeadline(time.Now().Add(100 * time.Second))
	if err != nil {
		fmt.Println("Error setting read deadline:", err.Error())
		return
	}
	fmt.Printf("This connection will be open till %s\n", time.Now().Add(100*time.Second).String())

	initialCipherBlock := make([]byte, 16)
	err = client.read(initialCipherBlock)
	if err != nil {
		fmt.Println("Error reading initial block:", err.Error())
		return
	}
	fmt.Printf("Set ciphertext to %0x\n", initialCipherBlock)

	for {
		fmt.Println("next round")
		length := make([]byte, 2)
		err = client.read(length)
		if err != nil {
			fmt.Println("Error reading length block:", err.Error())
			return
		}
		blockCount := binary.LittleEndian.Uint16(length)
		fmt.Printf("Reading %d following blocks...\n", blockCount)

		if blockCount > 256 {
			fmt.Println("Block count too big: max 256 blocks allowed")
			return
		}

		blocksToTest := make([][]byte, blockCount)
		for i := 0; i < int(blockCount); i++ {
			block := make([]byte, 16)
			err = client.read(block)
			if err != nil {
				fmt.Println("Error reading block:", err.Error())
				return
			}
			blocksToTest[i] = block
		}

		fmt.Println("------------ Blocks ------------")
		responses := make([]byte, blockCount)
		correctBlocks := 0
		for i := 0; i < int(blockCount); i++ {
			plaintext, err := encryption.Decrypt(append(blocksToTest[i], initialCipherBlock...), key, iv)
			if err != nil {
				fmt.Println("Error decrypting block:", err.Error())
				return
			}
			if checkPadding(plaintext) {
				responses[i] = 0x01
				correctBlocks++
				fmt.Printf("  -> found correct padding at block %03d: %0x\n", i, plaintext)
			}
			if i%100 == 0 {
				fmt.Printf("  eg. %03d. block: %0x\n", i, plaintext)
			}
		}
		fmt.Println("------------  End   ------------")

		fmt.Printf("Found %d blocks with correct padding\n", correctBlocks)

		_, err = client.conn.Write(responses)
		if err != nil {
			fmt.Println("Error sending response:", err.Error())
			return
		}
	}

}

func (client *Client) read(buf []byte) error {
	totalRead := 0
	for totalRead < len(buf) {
		n, err := client.conn.Read(buf[totalRead:])
		if err != nil {
			return err
		}
		totalRead += n
	}
	return nil
}

func checkPadding(plaintext []byte) bool {
	lastByte := plaintext[len(plaintext)-1]
	if lastByte > 0x10 || lastByte == 0 {
		return false
	}
	for i := len(plaintext) - 1; i > len(plaintext)-1-int(lastByte); i-- {
		if plaintext[i] != lastByte {
			return false
		}
	}
	return true
}
