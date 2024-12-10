package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Config holds all server configuration
type Config struct {
	// DNS redirection settings
	DNSIPv4Addr string
	DNSIPv4Port uint16
	DNSIPv6Addr string
	DNSIPv6Port uint16

	// Packet manipulation settings
	DoFakePacket   bool
	DoWrongChecksum bool
	DoWrongSeq     bool
}

// Server represents the proxy server
type Server struct {
	nfq         *nfqueue.Nfqueue
	config      *Config
	dnsHandler  *DNSHandler
}

// NewServer creates a new proxy server instance
func NewServer(config *Config) (*Server, error) {
	nfqConfig := nfqueue.Config{
		NfQueue:      0,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
	}

	nfq, err := nfqueue.Open(&nfqConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating netfilter queue: %v", err)
	}

	server := &Server{
		nfq:        nfq,
		config:     config,
		dnsHandler: NewDNSHandler(config),
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

	isIPv6 := ipLayer.LayerType() == layers.LayerTypeIPv6

	// Check for UDP (DNS) packets first
	if udpLayer := packet.TransportLayer(); udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			var srcIP, dstIP net.IP
			var ipv4 *layers.IPv4
			var ipv6 *layers.IPv6
			
			switch ipLayer.LayerType() {
			case layers.LayerTypeIPv4:
				ipv4, _ = ipLayer.(*layers.IPv4)
				srcIP = ipv4.SrcIP
				dstIP = ipv4.DstIP
			case layers.LayerTypeIPv6:
				ipv6, _ = ipLayer.(*layers.IPv6)
				srcIP = ipv6.SrcIP
				dstIP = ipv6.DstIP
			}

			isOutbound := isPrivateIP(srcIP)
			
			// Handle DNS packets
			if isOutbound && (udp.DstPort == layers.UDPPort(53) || udp.DstPort == layers.UDPPort(s.config.DNSIPv4Port)) {
				// Skip if already going to our DNS server
				if (dstIP.String() == s.config.DNSIPv4Addr && udp.DstPort == layers.UDPPort(s.config.DNSIPv4Port)) ||
					(dstIP.String() == s.config.DNSIPv6Addr && udp.DstPort == layers.UDPPort(s.config.DNSIPv6Port)) {
					s.nfq.SetVerdict(id, verdict)
					return nil
				}

				if s.dnsHandler.handleOutgoing(srcIP, uint16(udp.SrcPort), dstIP, uint16(udp.DstPort), udp.Payload, isIPv6) {
					// Modify and send the packet
					modifiedPacket, err := s.dnsHandler.modifyOutgoingPacket(packet, isIPv6)
					if err != nil {
						return fmt.Errorf("error modifying outgoing packet: %v", err)
					}

					// Send modified packet using raw socket
					if err := sendRawPacket(modifiedPacket, isIPv6); err != nil {
						return fmt.Errorf("error sending modified packet: %v", err)
					}
					
					// Drop the original packet
					s.nfq.SetVerdict(id, int(nfqueue.NfDrop))
					return nil
				}
			} else if !isOutbound && (udp.SrcPort == layers.UDPPort(53) || udp.SrcPort == layers.UDPPort(s.config.DNSIPv4Port) || udp.SrcPort == layers.UDPPort(s.config.DNSIPv6Port)) {
				// Handle incoming DNS response
				if origDstIP, origDstPort, clientSrcPort, ok := s.dnsHandler.handleIncoming(srcIP, uint16(udp.SrcPort), dstIP, uint16(udp.DstPort), udp.Payload, isIPv6); ok {
					// Modify and send the packet
					modifiedPacket, err := s.dnsHandler.modifyIncomingPacket(packet, origDstIP, origDstPort, clientSrcPort, isIPv6)
					if err != nil {
						return fmt.Errorf("error modifying incoming packet: %v", err)
					}

					// Send modified packet using raw socket
					if err := sendRawPacket(modifiedPacket, isIPv6); err != nil {
						return fmt.Errorf("error sending modified packet: %v", err)
					}

					// Drop the original packet
					s.nfq.SetVerdict(id, int(nfqueue.NfDrop))
					return nil
				}
				// If not a tracked DNS response or error, let it through
				s.nfq.SetVerdict(id, verdict)
				return nil
			}
			// Accept non-DNS UDP packets
			s.nfq.SetVerdict(id, verdict)
			return nil
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

// sendRawPacket sends a packet using raw sockets
func sendRawPacket(packetData []byte, isIPv6 bool) error {
	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_UDP)
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

	// Send the packet
	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], packetData[16:20]) // Copy destination IP from IP header
	addr.Port = int(binary.BigEndian.Uint16(packetData[22:24])) // Get destination port from UDP header
	
	err = syscall.Sendto(fd, packetData, 0, &addr)
	if err != nil {
		return fmt.Errorf("error sending packet: %v", err)
	}

	return nil
}