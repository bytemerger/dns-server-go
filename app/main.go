package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type DNSMessage struct {
	Header   Header
	Question Question
	Answer   []Record
}

type Header struct {
	id uint16
	// QR
	queryResponse bool
	// OPCODE
	operationCode uint8
	// AA
	authoritativeAnswer bool
	// TD
	truncatedMessage bool
	// RD
	recursionDesired bool
	// RA
	recursionAvailable bool
	// reserved bit (Z)
	reserved uint8
	// RCODE
	responseCode uint8
	// QDCOUNT
	questionCount uint16
	// ANCOUNT
	answerCount uint16
	// NSCOUNT
	authorityCount uint16
	// ARCOUNT
	additionalCount uint16
}

func (header *Header) decode(buf *bytes.Buffer) error {
	headerBytes := make([]byte, 12)
	n, err := buf.Read(headerBytes)

	if n < 12 || err != nil {
		return errors.New("Header could not be decoded")
	}

	header.id = uint16(uint16(headerBytes[0])<<8 | uint16(headerBytes[1]))
	flags1 := headerBytes[2]
	flags2 := headerBytes[3] // get response code from here

	header.queryResponse = uint8(flags1>>7) > 0

	header.operationCode = uint8(flags1 << 1 & 0xF0) // also the same with flags >> 3 & 0x0F

	// starting from the back of the byte to get the booleans
	header.recursionDesired = uint8(flags1&1<<0) > 0

	header.truncatedMessage = uint8(flags1&1<<1) > 0

	header.authoritativeAnswer = uint8(flags1&1<<2) > 0

	header.recursionAvailable = uint8(flags2&1<<7) > 0

	// reserved bit Z
	header.reserved = uint8(flags2 << 1 & 0xE0) // 0xE0 keep only the first 3 bits

	header.responseCode = uint8(flags2 & 0x0F)

	header.questionCount = uint16(uint16(headerBytes[4])<<8 | uint16(headerBytes[5]))
	header.answerCount = uint16(uint16(headerBytes[6])<<8 | uint16(headerBytes[7]))
	header.authorityCount = uint16(uint16(headerBytes[8])<<8 | uint16(headerBytes[9]))
	header.additionalCount = uint16(uint16(headerBytes[10])<<8 | uint16(headerBytes[11]))

	return nil

}

func (header *Header) encode(buf *bytes.Buffer) {
	headerBytes := make([]byte, 12)
	headerBytes[0] = byte(header.id >> 8)
	headerBytes[1] = byte(header.id)
	// 10000000
	// 00001011...
	headerBytes[2] = byte(boolToInt(header.queryResponse)<<7 | header.operationCode<<3 | boolToInt(header.authoritativeAnswer)<<2 | boolToInt(header.truncatedMessage)<<1 | boolToInt(header.recursionDesired)<<0)
	headerBytes[3] = byte(boolToInt(header.recursionAvailable)<<7 | header.reserved<<3 | header.responseCode)
	binary.BigEndian.PutUint16(headerBytes[4:6], header.questionCount)
	binary.BigEndian.PutUint16(headerBytes[6:8], header.answerCount)
	binary.BigEndian.PutUint16(headerBytes[8:10], header.authorityCount)
	binary.BigEndian.PutUint16(headerBytes[10:], header.additionalCount)

	buf.Write(headerBytes)
}

type Question struct {
	name  string
	qtype uint16
	class uint16
}

func (question *Question) decode(buf *bytes.Buffer) {

}

type Record struct {
	name   string
	qtype  uint16
	class  uint16
	ttl    uint32
	length uint16
	data   []byte
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
		response := make([]byte, 12)
		appendHeader(response[:])

		fmt.Println(response)

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

func appendHeader(buf []byte) []byte {
	// write the packet ID since this is the only way to maintain state UDP
	binary.BigEndian.PutUint16(buf[:2], 1234)
	buf[2] = 1 << 7
	return buf
}
