package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

type DNSMessage struct {
	header    Header
	questions []Question
	answers   []Record
}

func (dnsMessage *DNSMessage) fromBuffer(buf *bytes.Buffer) {

}

func (dnsMessage *DNSMessage) writeToBuffer(buf *bytes.Buffer) {
	dnsMessage.header.questionCount = uint16(len(dnsMessage.questions))
	dnsMessage.header.answerCount = uint16(len(dnsMessage.answers))
	dnsMessage.header.answerCount = uint16(len(dnsMessage.answers))

	dnsMessage.header.encode(buf)

	for _, question := range dnsMessage.questions {
		question.encode(buf)
	}

	for _, ans := range dnsMessage.answers {
		ans.encode(buf)
	}

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

func (header Header) newEmptyHeader() Header {
	return Header{
		id:                  1234,
		queryResponse:       true,
		operationCode:       0,
		authoritativeAnswer: false,
		truncatedMessage:    false,
		recursionDesired:    false,
		recursionAvailable:  false,
		reserved:            0,
		responseCode:        0,
		questionCount:       0,
		answerCount:         0,
		authorityCount:      0,
		additionalCount:     0,
	}
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

func (question *Question) encode(buf *bytes.Buffer) {
	questionByte := []byte{}

	questionByte = append(questionByte, writeQName(question.name)...)

	questionByte = binary.BigEndian.AppendUint16(questionByte, question.qtype)
	// append the question class
	questionByte = binary.BigEndian.AppendUint16(questionByte, question.class)

	buf.Write(questionByte)
}

func (question *Question) decode(buf *bytes.Buffer) {
	labels := []string{}
	for {
		b, err := buf.ReadByte()
		if err != nil {
			if err.Error() != "EOF" {
				log.Fatal(err)
			}
			break
		}
		if b == 0x00 {
			break
		}
		labelByte := make([]byte, int(b))
		buf.Read(labelByte)
		labels = append(labels, string(labelByte))
	}
	question.name = strings.Join(labels, ".")
	b1, _ := buf.ReadByte()
	b2, _ := buf.ReadByte()
	question.qtype = binary.BigEndian.Uint16([]byte{b1, b2})
	b3, _ := buf.ReadByte()
	b4, _ := buf.ReadByte()
	question.class = binary.BigEndian.Uint16([]byte{b3, b4})
}

type Record struct {
	name   string
	qtype  uint16
	class  uint16
	ttl    uint32
	length uint16
	data   string
}

func (record *Record) encode(buf *bytes.Buffer) {
	recordByte := []byte{}

	recordByte = append(recordByte, writeQName(record.name)...)

	// append the question type
	recordByte = binary.BigEndian.AppendUint16(recordByte, record.qtype)
	// append the question class
	recordByte = binary.BigEndian.AppendUint16(recordByte, record.class)
	recordByte = binary.BigEndian.AppendUint32(recordByte, record.ttl)

	recordByte = append(recordByte, byte(record.length))
	ipNumber, _ := strconv.Atoi(strings.Join(strings.Split(record.data, "."), ""))

	recordByte = binary.BigEndian.AppendUint32(recordByte, uint32(ipNumber))
	buf.Write(recordByte)
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
		//response := make([]byte, 512)
		// you can also use bytes.Buffer{}
		response := bytes.NewBuffer([]byte{})
		dnsMessage := new(DNSMessage)
		dnsMessage.header = dnsMessage.header.newEmptyHeader()
		dnsMessage.questions = append(dnsMessage.questions, Question{
			name:  "codecrafters.io",
			qtype: 1,
			class: 1,
		})

		/* dnsMessage.answers = append(dnsMessage.answers, Record{
			name:   "codecrafter.io",
			qtype:  1,
			class:  1,
			ttl:    60,
			length: 4,
			data:   "8.8.8.8",
		}) */

		dnsMessage.writeToBuffer(response)
		fmt.Println(response)

		_, err = udpConn.WriteToUDP(response.Bytes(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
