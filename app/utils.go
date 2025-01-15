package main

import (
	"bytes"
	"fmt"
	"strings"
)

func BoolToInt(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func WriteQName(qname string) []byte {
	bufQname := []byte{}
	for _, name := range strings.Split(qname, ".") {
		nameB := []byte(name)
		bufQname = append(bufQname, byte(len(nameB)))
		bufQname = append(bufQname, nameB...)
	}
	return append(bufQname, 0x00)
}

func GetDName(buf []byte, offset int) string {
	//offsetted the working bytes for the header
	labels := []string{}
	workingBuf := buf[offset:]
	closingIndex := bytes.IndexByte(workingBuf, 0x00)
	currentPosition := 0
	for currentPosition < closingIndex {
		labelChar := workingBuf[currentPosition]
		if labelChar&0xC0 == 0xC0 {
			fmt.Println("yes we have a comppressed hearder")
			offset := uint16(uint16(workingBuf[currentPosition]<<2)<<8 | uint16(workingBuf[currentPosition+1]))
			labels = append(labels, GetDName(buf, int(offset)))

		}
		labels = append(labels, string(workingBuf[currentPosition+1:int(labelChar)+currentPosition+1]))
		currentPosition = currentPosition + int(labelChar) + 1
	}

	return strings.Join(labels, ".")
}
