package main

/*
-- tcp.flags
-- 0x10 = ack
-- 0x02 = syn
-- 0x12 = syn ack
*/

import (
	"encoding/binary"
	"syscall"
)

const (
	tcpHeaderMinLen = 20
	tcpHeaderMaxLen = 60
)

type tcpHeader struct {
	SourcePort		int
	DestPort		int
	SeqNum			int
	AckNum			int
	Len				int
	RSV				int
	Flag 			int
	Window			int
	CheckSum		int
	UrgentPointer	int
	Options			[]byte
}

type pseudoHeader struct {
	// https://www.geeksforgeeks.org/calculation-of-tcp-checksum/
	SourceIp	[4]uint8
	DestIp		[4]uint8
	ProtoType	uint8
	Fixed		uint8
	SegLen		uint16
}

func (header *tcpHeader) Encoding() ([]byte, error) {
	if header == nil {
		return nil, syscall.EINVAL
	}

	headerLen := len(header.Options) + tcpHeaderMinLen
	bytes := make([]byte, headerLen)

	// Setting SRC, DST with those rules:
	// SRC (Source port) 		- 16 bit field
	// DST (Destination port) 	- 16 bit field
	// https://networklessons.com/cisco/ccie-routing-switching-written/tcp-header
	binary.BigEndian.PutUint16(bytes[0:2], uint16(header.SourcePort))
	binary.BigEndian.PutUint16(bytes[2:4], uint16(header.DestPort))

	// Setting SEQ, ACK, DO, RSV, Flag with those rules:
	// SEQ (Sequence Number) 		- 32 bit field
	// ACK (Acknowledgment number)	- 32 bit field
	// DO (header length)			- 4 bit data offset field
	// RSV (reserved field)			- 3 bit for the reserved field
	// Flag							- 9 bit field
	binary.BigEndian.PutUint32(bytes[4:8], uint32(header.SeqNum))
	binary.BigEndian.PutUint32(bytes[8:12], uint32(header.AckNum))

	bytes[12] = uint8(80)
	// RSVD missing, 'cause they are unused and are always set to 0.
	bytes[13] = uint8(header.Flag)

	// Setting WIN, CHS, UP, OPTS with those rules:
	// WIN (Window size)	- 16 bit field
	// CHS (Checksum)		- 16 bit field
	// UP (Urgent pointer) 	- 16 bit field
	// Options 				- Optional. From 0 to 320 bits.
	binary.BigEndian.PutUint16(bytes[14:16], uint16(header.Window))
	binary.BigEndian.PutUint16(bytes[16:18], uint16(header.CheckSum))
	binary.BigEndian.PutUint16(bytes[18:20], uint16(header.UrgentPointer))

	// Setting options if exists
	if len(header.Options) > 0 {
		copy(bytes[tcpHeaderMinLen:], header.Options)
	}

	return bytes, nil
}