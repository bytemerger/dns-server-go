package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type DNSMessage struct {
	header    Header
	questions []Question
	answers   []Record
}

func DnsMessagefromBuffer(buf []byte) *DNSMessage {
	dnsMessage := new(DNSMessage)
	dnsheader := decodeHeaderFromBuffer(buf)
	dnsMessage.header = dnsheader
	// offset for processing
	offset := 12
	for i := 0; i < int(dnsMessage.header.questionCount); i++ {
		question, startProcessingIndex := decodeQuestionFromBuffer(buf, offset)
		offset = offset + startProcessingIndex
		dnsMessage.questions = append(dnsMessage.questions, question)
	}
	return dnsMessage
}

func (dnsMessage *DNSMessage) writeToBuffer(buf *bytes.Buffer) {
	dnsMessage.header.questionCount = uint16(len(dnsMessage.questions))
	dnsMessage.header.answerCount = uint16(len(dnsMessage.answers))

	dnsMessage.header.encode(buf)

	for _, question := range dnsMessage.questions {
		question.encode(buf)
	}

	for _, answer := range dnsMessage.answers {
		answer.encode(buf)
	}

}

type RCODE int

const (
	NO_ERROR RCODE = iota
	FORMERR
	SERVFAIL
	NXDOMAIN
	NOTIMP
	REFUSED
)

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
	responseCode RCODE
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

func decodeHeaderFromBuffer(buf []byte) Header {
	headerBytes := buf[:12]
	header := Header{}

	header.id = uint16(uint16(headerBytes[0])<<8 | uint16(headerBytes[1]))
	flags1 := headerBytes[2]
	flags2 := headerBytes[3] // get response code from here

	header.queryResponse = uint8(flags1>>7) > 0

	header.operationCode = uint8(flags1 >> 3 & 0x0F)

	// starting from the back of the byte to get the booleans
	header.recursionDesired = uint8(flags1&1<<0) > 0

	header.truncatedMessage = uint8(flags1&1<<1) > 0

	header.authoritativeAnswer = uint8(flags1&1<<2) > 0

	header.recursionAvailable = uint8(flags2&1<<7) > 0

	// reserved bit Z
	header.reserved = uint8(flags2 << 1 & 0xE0) // 0xE0 keep only the first 3 bits

	header.responseCode = RCODE(flags2 & 0x0F)

	header.questionCount = uint16(uint16(headerBytes[4])<<8 | uint16(headerBytes[5]))
	header.answerCount = uint16(uint16(headerBytes[6])<<8 | uint16(headerBytes[7]))
	header.authorityCount = uint16(uint16(headerBytes[8])<<8 | uint16(headerBytes[9]))
	header.additionalCount = uint16(uint16(headerBytes[10])<<8 | uint16(headerBytes[11]))

	return header

}

func (header *Header) encode(buf *bytes.Buffer) {
	headerBytes := make([]byte, 12)
	headerBytes[0] = byte(header.id >> 8)
	headerBytes[1] = byte(header.id)
	// 10000000
	// 00001011...
	headerBytes[2] = byte(BoolToInt(header.queryResponse)<<7 | header.operationCode<<3 | BoolToInt(header.authoritativeAnswer)<<2 | BoolToInt(header.truncatedMessage)<<1 | BoolToInt(header.recursionDesired)<<0)
	headerBytes[3] = byte(BoolToInt(header.recursionAvailable)<<7 | header.reserved<<3 | uint8(header.responseCode))
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

	questionByte = append(questionByte, WriteQName(question.name)...)

	questionByte = binary.BigEndian.AppendUint16(questionByte, question.qtype)
	// append the question class
	questionByte = binary.BigEndian.AppendUint16(questionByte, question.class)

	buf.Write(questionByte)
}

func decodeQuestionFromBuffer(buf []byte, offset int) (Question, int) {
	question := Question{}
	closingIndex := bytes.IndexByte(buf[offset:], 0x00)
	question.name = GetDName(buf, offset)
	question.qtype = binary.BigEndian.Uint16(buf[closingIndex+1 : closingIndex+3])
	question.class = binary.BigEndian.Uint16(buf[closingIndex+3 : closingIndex+5])

	return question, int(closingIndex) + 5
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

	recordByte = append(recordByte, WriteQName(record.name)...)

	// append the question type
	recordByte = binary.BigEndian.AppendUint16(recordByte, record.qtype)
	// append the question class
	recordByte = binary.BigEndian.AppendUint16(recordByte, record.class)
	recordByte = binary.BigEndian.AppendUint32(recordByte, record.ttl)

	recordByte = binary.BigEndian.AppendUint16(recordByte, uint16(record.length))
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

		//receivedData := string(buf[:size])
		//fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		requestDNSMessage := DnsMessagefromBuffer(buf[:size])

		// Create an empty response
		//response := make([]byte, 512)
		// you can also use bytes.Buffer{}
		response := bytes.NewBuffer([]byte{})
		responseDNSMessage := new(DNSMessage)
		responseDNSMessage.header = responseDNSMessage.header.newEmptyHeader()
		responseDNSMessage.header.id = requestDNSMessage.header.id
		responseDNSMessage.header.operationCode = requestDNSMessage.header.operationCode
		responseDNSMessage.header.recursionDesired = requestDNSMessage.header.recursionDesired
		// response code not implemented for the response here
		responseDNSMessage.header.responseCode = NOTIMP
		/* responseDNSMessage.questions = append(responseDNSMessage.questions, Question{
			name:  requestDNSMessage.questions[0].name,
			qtype: 1,
			class: 1,
		}) */

		for i := range requestDNSMessage.questions {
			responseDNSMessage.questions = append(responseDNSMessage.questions, Question{
				name:  requestDNSMessage.questions[i].name,
				qtype: 1,
				class: 1,
			})
		}

		for i := range requestDNSMessage.questions {
			responseDNSMessage.answers = append(responseDNSMessage.answers, Record{
				name:   requestDNSMessage.questions[i].name,
				qtype:  1,
				class:  1,
				ttl:    60,
				length: 4,
				data:   "8.8.8.8",
			})
		}

		responseDNSMessage.writeToBuffer(response)

		_, err = udpConn.WriteToUDP(response.Bytes(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
