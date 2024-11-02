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
	Host string
	Port int
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

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		client := &Client{
			conn: conn,
		}
		go client.handleRequest()
	}
}

func (client *Client) handleRequest() {
	defer func(conn net.Conn) {
		fmt.Println("Closing connection")
		err := conn.Close()
		if err != nil {
			fmt.Println("Error closing connection:", err.Error())
		}
	}(client.conn)

	err := client.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		fmt.Println("Error setting read deadline:", err.Error())
		return
	}

	initialCipherBlock := make([]byte, 16)
	err = client.read(initialCipherBlock)
	if err != nil {
		fmt.Println("Error reading initial block:", err.Error())
		return
	}

	for {
		length := make([]byte, 2)
		err = client.read(length)
		if err != nil {
			fmt.Println("Error reading length block:", err.Error())
			return
		}
		fmt.Println(length)
		blockCount := binary.LittleEndian.Uint16(length)
		fmt.Println("Block count:", blockCount)

		if blockCount > 1400 {
			fmt.Println("Block count too big: max 1400 blocks allowed")
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

		responses := make([]byte, blockCount)
		for i := 0; i < int(blockCount); i++ {
			plaintext, err := encryption.Decrypt(append(blocksToTest[i], initialCipherBlock...))
			if err != nil {
				fmt.Println("Error decrypting block:", err.Error())
				return
			}
			if checkPadding(plaintext) {
				responses[i] = 0x01
				fmt.Println("Gefunden:", plaintext)
			}
		}

		fmt.Println(len(responses), responses)
		//client.flush()
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
	fmt.Println(plaintext)
	return true
}
