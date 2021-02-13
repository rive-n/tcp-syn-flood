package main

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
)

const (
	IpVersion 		= 4
	IpHeaderMinLen 	= 20
	IpHeaderMaxLen 	= 60
)

type ipHeader struct {
	// https://tools.ietf.org/html/rfc2507#section-7.13
	Vers 		int		// 4 bit
	Flags		int		// 3 bit
	HLEN		int		// 8 bit 	-> 1 byte
	TOS			int		// 16 bit 	-> 2 byte
	TLen		int		// 32 bit	-> 4 byte
	PID			int		// 16 bit	-> 2 byte
	FOFF		int		// 13 bit	-> 1 byte 5 bit
	TTL			int		// 8 bit	-> 1 byte
	Proto		int		// 8 bit	-> 1 byte
	HCheckSum	int		// 16 bit	-> 2 byte
	SRCip		net.IP	// 32 bit	-> 4 byte
	DSTip		net.IP	// 32 bit	-> 4 byte
	Data		[]byte	// extension header
}

// Marshal encode ipv4 header
// https://github.com/golang/net/blob/4acb7895a0574887276b79d6c959e9aa3182386d/ipv4/header.go
func (h *ipHeader) Marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}

	hdrlen := IpHeaderMinLen + len(h.Data)
	b := make([]byte, hdrlen)

	b[0] = byte(IpVersion<<4 | (hdrlen >> 2 & 0x0f))
	b[1] = byte(h.TOS)

	binary.BigEndian.PutUint16(b[2:4], uint16(h.TLen))
	binary.BigEndian.PutUint16(b[4:6], uint16(h.PID))

	flagsAndFragOff := (h.FOFF & 0x1fff) | int(h.Flags<<13)
	binary.BigEndian.PutUint16(b[6:8], uint16(flagsAndFragOff))

	b[8] = byte(h.TTL)
	b[9] = byte(h.Proto)

	binary.BigEndian.PutUint16(b[10:12], uint16(h.HCheckSum))

	if ip := h.SRCip.To4(); ip != nil {
		copy(b[12:16], ip[:net.IPv4len])
	}

	if ip := h.DSTip.To4(); ip != nil {
		copy(b[16:20], ip[:net.IPv4len])
	} else {
		return nil, errors.New("missing address")
	}

	if len(h.Data) > 0 {
		copy(b[IpHeaderMinLen:], h.Data)
	}

	return b, nil
}