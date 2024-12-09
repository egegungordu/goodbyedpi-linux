package proxy

import (
	"encoding/binary"
	"fmt"
	"log"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

// Default fake HTTP request that will be sent
var defaultFakeHTTPRequest = []byte("GET / HTTP/1.1\r\nHost: www.w3.org\r\n" +
	"User-Agent: curl/7.65.3\r\nAccept: */*\r\n" +
	"Accept-Encoding: deflate, gzip, br\r\n\r\n")

// Default TTL for fake packets
const defaultFakeTTL = 5

// SendFragmentedHTTP sends a fragmented HTTP request in reverse order
func SendFragmentedHTTP(originalPacket gopacket.Packet, fragmentSize int) error {
	// Get original layers
	ipLayer := originalPacket.NetworkLayer()
	tcpLayer := originalPacket.TransportLayer().(*layers.TCP)
	payload := tcpLayer.Payload

	if len(payload) <= fragmentSize {
		return fmt.Errorf("payload too small to fragment")
	}

	// Create first fragment (rest of the data)
	firstFrag := make([]byte, len(payload)-fragmentSize)
	copy(firstFrag, payload[fragmentSize:])

	// Create second fragment (first 2 bytes)
	secondFrag := make([]byte, fragmentSize)
	copy(secondFrag, payload[:fragmentSize])

	// Send fragments in reverse order
	if err := sendFragment(ipLayer, tcpLayer, firstFrag, fragmentSize, true); err != nil {
		return fmt.Errorf("error sending first fragment: %v", err)
	}

	if err := sendFragment(ipLayer, tcpLayer, secondFrag, 0, false); err != nil {
		return fmt.Errorf("error sending second fragment: %v", err)
	}

	return nil
}

// sendFragment sends a single fragment
func sendFragment(ipLayer gopacket.NetworkLayer, tcpLayer *layers.TCP, data []byte, offset int, isFirstFragment bool) error {
	// Create new packet layers
	var ip layers.IPv4
	var tcp layers.TCP

	// Copy IP header
	if ipv4, ok := ipLayer.(*layers.IPv4); ok {
		ip = layers.IPv4{
			Version:    4,
			IHL:        ipv4.IHL,
			TOS:        ipv4.TOS,
			Length:     0, // Will be set automatically
			Id:         ipv4.Id + 1,
			Flags:      ipv4.Flags,
			FragOffset: ipv4.FragOffset,
			TTL:        ipv4.TTL,
			Protocol:   layers.IPProtocolTCP,
			SrcIP:      ipv4.SrcIP,
			DstIP:      ipv4.DstIP,
		}
	} else {
		return fmt.Errorf("only IPv4 supported for fragmentation")
	}

	// Copy TCP header
	tcp = layers.TCP{
		SrcPort:    tcpLayer.SrcPort,
		DstPort:    tcpLayer.DstPort,
		Seq:        tcpLayer.Seq + uint32(offset),
		Ack:        tcpLayer.Ack,
		DataOffset: tcpLayer.DataOffset,
		Window:     tcpLayer.Window,
		Urgent:     tcpLayer.Urgent,
		PSH:        true,
		ACK:        true,
	}

	// Set TCP checksum options
	tcp.SetNetworkLayerForChecksum(&ip)

	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("error creating raw socket: %v", err)
	}
	defer syscall.Close(fd)

	// Set socket options
	err = syscall.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		return fmt.Errorf("error setting IP_HDRINCL: %v", err)
	}

	// Mark the packet so it won't be caught by our NFQUEUE rules
	err = syscall.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 1)
	if err != nil {
		return fmt.Errorf("error setting SO_MARK: %v", err)
	}

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:      true,
	}

	err = gopacket.SerializeLayers(buf, opts,
		&ip,
		&tcp,
		gopacket.Payload(data),
	)
	if err != nil {
		return fmt.Errorf("error serializing packet: %v", err)
	}

	// Prepare socket address
	addr := syscall.SockaddrInet4{
		Port: 0, // Not used for raw sockets
	}
	copy(addr.Addr[:], ip.DstIP.To4())

	// Send the packet
	packetData := buf.Bytes()
	log.Printf("Sending fragment: Size=%d, Offset=%d, First 16 bytes=%x", len(packetData), offset, packetData[:16])
	err = syscall.Sendto(fd, packetData, 0, &addr)
	if err != nil {
		return fmt.Errorf("error sending packet: %v", err)
	}

	log.Printf("Sent fragment: Size=%d, Offset=%d", len(data), offset)
	return nil
}

// SendFakeHTTP creates and sends a fake HTTP packet
func SendFakeHTTP(originalPacket gopacket.Packet, doWrongChecksum, doWrongSeq bool) error {
	return SendFakeHTTPWithTTL(originalPacket, doWrongChecksum, doWrongSeq, defaultFakeTTL)
}

// SendFakeHTTPWithTTL creates and sends a fake HTTP packet with specified TTL
func SendFakeHTTPWithTTL(originalPacket gopacket.Packet, doWrongChecksum, doWrongSeq bool, ttl uint8) error {
	// Get original layers
	ipLayer := originalPacket.NetworkLayer()
	tcpLayer := originalPacket.TransportLayer().(*layers.TCP)

	// Create new packet layers
	var ip layers.IPv4
	var tcp layers.TCP

	// Copy IP header
	if ipv4, ok := ipLayer.(*layers.IPv4); ok {
		ip = layers.IPv4{
			Version:    4,
			IHL:        ipv4.IHL,
			TOS:        ipv4.TOS,
			Length:     0, // Will be set automatically
			Id:         ipv4.Id + 1, // Increment ID to avoid duplicate
			Flags:      ipv4.Flags,
			FragOffset: ipv4.FragOffset,
			TTL:        ttl, // Use specified TTL
			Protocol:   layers.IPProtocolTCP,
			SrcIP:      ipv4.SrcIP,
			DstIP:      ipv4.DstIP,
		}
	} else {
		return fmt.Errorf("IPv6 not implemented yet")
	}

	// Copy TCP header exactly as is from original packet
	tcp = layers.TCP{
		SrcPort:    tcpLayer.SrcPort,
		DstPort:    tcpLayer.DstPort,
		Seq:        tcpLayer.Seq,
		Ack:        tcpLayer.Ack,
		DataOffset: tcpLayer.DataOffset,
		Window:     tcpLayer.Window,
		Urgent:     tcpLayer.Urgent,
		// Copy all flags from original packet
		FIN:        tcpLayer.FIN,
		SYN:        tcpLayer.SYN,
		RST:        tcpLayer.RST,
		PSH:        tcpLayer.PSH,
		ACK:        tcpLayer.ACK,
		URG:        tcpLayer.URG,
		ECE:        tcpLayer.ECE,
		CWR:        tcpLayer.CWR,
		NS:         tcpLayer.NS,
	}

	// Modify sequence numbers if requested
	if doWrongSeq {
		// This is the smallest ACK drift Linux can't handle
		tcp.Ack = tcpLayer.Ack - 66000
		// Random offset for sequence number
		tcp.Seq = tcpLayer.Seq - 10000
		log.Printf("Modified sequence numbers - New Seq: %d, New Ack: %d", tcp.Seq, tcp.Ack)
	}

	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("error creating raw socket: %v", err)
	}
	defer syscall.Close(fd)

	// Set socket options
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return fmt.Errorf("error setting IP_HDRINCL: %v", err)
	}

	// Mark the packet so it won't be caught by our NFQUEUE rules
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, 1)
	if err != nil {
		return fmt.Errorf("error setting SO_MARK: %v", err)
	}

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:      true,
	}

	// Set TCP checksum options before serialization
	tcp.SetNetworkLayerForChecksum(&ip)

	err = gopacket.SerializeLayers(buf, opts,
		&ip,
		&tcp,
		gopacket.Payload(defaultFakeHTTPRequest),
	)
	if err != nil {
		return fmt.Errorf("error serializing packet: %v", err)
	}

	// If we want to damage the checksum
	if doWrongChecksum {
		serialized := buf.Bytes()
		// Find the TCP header and modify its checksum
		// TCP checksum is at offset 16 in the TCP header
		if len(serialized) > 40 { // IP header (20) + minimal TCP header (20)
			checksum := binary.BigEndian.Uint16(serialized[36:38])
			checksum-- // Damage the checksum
			binary.BigEndian.PutUint16(serialized[36:38], checksum)
			log.Printf("Modified checksum to: %d", checksum)
		}
	}

	// Prepare socket address
	addr := syscall.SockaddrInet4{
		Port: 0, // Not used for raw sockets
	}
	copy(addr.Addr[:], ip.DstIP.To4())

	// Send the fake packet first
	packetData := buf.Bytes()
	log.Printf("Sending fake packet: Size=%d, TTL=%d, First 16 bytes=%x", len(packetData), ttl, packetData[:16])
	err = syscall.Sendto(fd, packetData, 0, &addr)
	if err != nil {
		return fmt.Errorf("error sending fake packet: %v", err)
	}
	log.Printf("Sent fake packet with modifications - TTL: %d, Checksum: %v, Seq: %v, Size: %d", 
		ttl, doWrongChecksum, doWrongSeq, len(packetData))

	// Then send the fragmented real packet
	if err := SendFragmentedHTTP(originalPacket, 2); err != nil {
		return fmt.Errorf("error sending fragmented packet: %v", err)
	}

	return nil
} 