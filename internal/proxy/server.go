package proxy

import (
	"context"
	"fmt"
	"log"
	"net"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Server represents the proxy server
type Server struct {
	nfq            *nfqueue.Nfqueue
	doFakePacket   bool
	doWrongChecksum bool
	doWrongSeq     bool
}

// NewServer creates a new proxy server instance
func NewServer(doFakePacket, doWrongChecksum, doWrongSeq bool) (*Server, error) {
	config := nfqueue.Config{
		NfQueue:      0,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	nfq, err := nfqueue.Open(&config)
	if err != nil {
		return nil, fmt.Errorf("error creating netfilter queue: %v", err)
	}

	server := &Server{
		nfq:            nfq,
		doFakePacket:   doFakePacket,
		doWrongChecksum: doWrongChecksum,
		doWrongSeq:     doWrongSeq,
	}

	return server, nil
}

// Start begins the packet interception
func (s *Server) Start(ctx context.Context) error {
	defer s.nfq.Close()

	if err := s.nfq.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		id := *a.PacketID
		payload := *a.Payload

		packet := gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default)
		if err := s.handlePacket(packet, id); err != nil {
			log.Printf("Error handling packet: %v", err)
		}
		return 0
	}, func(e error) int {
		log.Printf("Error in packet handler: %v", e)
		return 1
	}); err != nil {
		return fmt.Errorf("couldn't register callback: %v", err)
	}

	<-ctx.Done()
	return nil
}

// handlePacket processes a single packet
func (s *Server) handlePacket(packet gopacket.Packet, id uint32) error {
	var verdict int = int(nfqueue.NfAccept)

	// Get IP layer
	ipLayer := packet.NetworkLayer()
	if ipLayer == nil {
		s.nfq.SetVerdict(id, verdict)
		return fmt.Errorf("no IP layer found")
	}

	// Get transport layer
	tcpLayer := packet.TransportLayer()
	if tcpLayer == nil {
		s.nfq.SetVerdict(id, verdict)
		return fmt.Errorf("no TCP layer found")
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		s.nfq.SetVerdict(id, verdict)
		return fmt.Errorf("not a TCP packet")
	}

	// Determine packet type based on IP version and data
	switch ipLayer.LayerType() {
	case layers.LayerTypeIPv4:
		ip, _ := ipLayer.(*layers.IPv4)
		
		// Determine if packet is outbound (from local to remote)
		isOutbound := isPrivateIP(ip.SrcIP)

		// Branch 1: TCP packet with data (HTTP/HTTPS)
		if len(tcp.Payload) > 0 {
			// Branch 1.1: Inbound packet with data (HTTP redirect detection)
			if !isOutbound && len(tcp.Payload) > 16 {
				log.Printf("Inbound packet with data: src=%v:%d, dst=%v:%d", 
					ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
			}

			// Branch 1.2: Outbound HTTP packet
			if isOutbound && tcp.DstPort == 80 {
				log.Printf("Outbound HTTP packet: src=%v:%d, dst=%v:%d", 
					ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
				
				// Drop original packet and send fake one instead
				if s.doFakePacket {
					if err := SendFakeHTTP(packet, s.doWrongChecksum, s.doWrongSeq); err != nil {
						log.Printf("Error sending fake HTTP packet: %v", err)
					}
					verdict = int(nfqueue.NfDrop)
				} else {
					verdict = int(nfqueue.NfAccept)
				}
			}
		}

		// Branch 2: TCP packet without data (connection handling)
		if len(tcp.Payload) == 0 {
			if !isOutbound {
				// Special case for SYN+ACK as it needs special handling
				if tcp.SYN && tcp.ACK {
					log.Printf("Inbound SYN+ACK packet: src=%v:%d, dst=%v:%d, flags=syn:%v/ack:%v", 
						ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, tcp.SYN, tcp.ACK)
				} else {
					// Log all other inbound TCP control packets
					log.Printf("Inbound TCP control packet: src=%v:%d, dst=%v:%d, flags=syn:%v/ack:%v", 
						ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, tcp.SYN, tcp.ACK)
				}
			} else {
				// Log outbound TCP control packets
				log.Printf("Outbound TCP control packet: src=%v:%d, dst=%v:%d, flags=syn:%v/ack:%v", 
					ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, tcp.SYN, tcp.ACK)
			}
			verdict = int(nfqueue.NfAccept)
		}

	case layers.LayerTypeIPv6:
		ip, _ := ipLayer.(*layers.IPv6)
		
		// Use the same isPrivateIP function for IPv6
		isOutbound := isPrivateIP(ip.SrcIP)

		// Similar branches as IPv4, but with IPv6-specific handling
		if len(tcp.Payload) == 0 {
			if !isOutbound {
				if tcp.SYN && tcp.ACK {
					log.Printf("IPv6 inbound SYN+ACK packet: src=%v:%d, dst=%v:%d, flags=syn:%v/ack:%v",
						ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
						tcp.SYN, tcp.ACK)
				} else {
					log.Printf("IPv6 inbound TCP control packet: src=%v:%d, dst=%v:%d, flags=syn:%v/ack:%v",
						ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
						tcp.SYN, tcp.ACK)
				}
			} else {
				log.Printf("IPv6 outbound TCP control packet: src=%v:%d, dst=%v:%d, flags=syn:%v/ack:%v",
					ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
					tcp.SYN, tcp.ACK)
			}
			verdict = int(nfqueue.NfAccept)
		} else {
			if isOutbound {
				log.Printf("IPv6 outbound data packet: src=%v:%d, dst=%v:%d, flags=syn:%v/ack:%v",
					ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
					tcp.SYN, tcp.ACK)

				// Drop original packet and send fake one instead for IPv6
				if s.doFakePacket && tcp.DstPort == 80 {
					if err := SendFakeHTTP(packet, s.doWrongChecksum, s.doWrongSeq); err != nil {
						log.Printf("Error sending fake HTTP packet (IPv6): %v", err)
					}
					verdict = int(nfqueue.NfDrop)
				} else {
					verdict = int(nfqueue.NfAccept)
				}
			} else {
				log.Printf("IPv6 inbound data packet: src=%v:%d, dst=%v:%d, flags=syn:%v/ack:%v",
					ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort,
					tcp.SYN, tcp.ACK)
				verdict = int(nfqueue.NfAccept)
			}
		}
	}

	// Set the verdict for the packet
	s.nfq.SetVerdict(id, verdict)
	return nil
}

// isPrivateIP checks if an IP address is in private ranges (RFC 1918)
func isPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// Check private IPv4 ranges
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		return false
	}

	// Check if it's a private IPv6 address
	if ip6 := ip.To16(); ip6 != nil {
		// fc00::/7 - Unique Local Address
		return ip6[0]&0xfe == 0xfc
	}

	return false
} 