package main

import "strings"

func boolToInt(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func writeQName(qname string) []byte {
	bufQname := []byte{}
	for _, name := range strings.Split(qname, ".") {
		nameB := []byte(name)
		bufQname = append(bufQname, byte(len(nameB)))
		bufQname = append(bufQname, nameB...)
	}
	return append(bufQname, 0x00)
}
