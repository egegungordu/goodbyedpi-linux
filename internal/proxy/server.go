package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

// DNSConfig holds DNS redirection configuration
type DNSConfig struct {
	IPv4Addr string
	IPv4Port uint16
	IPv6Addr string
	IPv6Port uint16
}

// DNSConnRecord represents a DNS connection tracking record
type DNSConnRecord struct {
	Key      string    // '4' or '6' + srcIP + srcPort
	Time     time.Time
	SrcIP    net.IP    // Client's source IP
	SrcPort  uint16    // Client's source port
	DstIP    net.IP    // Original destination IP
	DstPort  uint16    // Original destination port (53)
}

// Server represents the proxy server
type Server struct {
	nfq            *nfqueue.Nfqueue
	doFakePacket   bool
	doWrongChecksum bool
	doWrongSeq     bool
	dnsConfig      *DNSConfig
	dnsConnTrack   map[string]*DNSConnRecord
	dnsLock        sync.RWMutex
	lastCleanup    time.Time
}

const (
	dnsCleanupInterval = 30 * time.Second
)

// NewServer creates a new proxy server instance
func NewServer(doFakePacket, doWrongChecksum, doWrongSeq bool, dnsConfig *DNSConfig) (*Server, error) {
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
		dnsConfig:      dnsConfig,
		dnsConnTrack:   make(map[string]*DNSConnRecord),
		lastCleanup:    time.Now(),
	}

	return server, nil
}

// isDNSPacket checks if a packet is a DNS packet
func (s *Server) isDNSPacket(packetData []byte, outgoing bool) bool {
	if len(packetData) < 16 {
		return false
	}

	if outgoing {
		flags := uint16(packetData[2])<<8 | uint16(packetData[3])
		additionalCount := uint16(packetData[6])<<8 | uint16(packetData[7])
		return (flags&0xFA00) == 0 && additionalCount == 0
	}

	flags := uint16(packetData[2])<<8 | uint16(packetData[3])
	return (flags&0xF800) == 0x8000
}

// createDNSKey creates a unique key for DNS connection tracking
func (s *Server) createDNSKey(srcIP net.IP, srcPort uint16, isIPv6 bool) string {
	version := "4"
	if isIPv6 {
		version = "6"
	}
	return fmt.Sprintf("%s%s%d", version, srcIP.String(), srcPort)
}

// cleanupDNSRecords removes old DNS connection tracking records
func (s *Server) cleanupDNSRecords() {
	if time.Since(s.lastCleanup) < dnsCleanupInterval {
		return
	}

	s.dnsLock.Lock()
	defer s.dnsLock.Unlock()

	now := time.Now()
	for key, record := range s.dnsConnTrack {
		if now.Sub(record.Time) >= dnsCleanupInterval {
			delete(s.dnsConnTrack, key)
		}
	}
	s.lastCleanup = now
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

// handleDNSOutgoing handles outgoing DNS packets
func (s *Server) handleDNSOutgoing(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, packetData []byte, isIPv6 bool) bool {
	if len(packetData) < 16 {
		return false
	}

	s.cleanupDNSRecords()

	if s.isDNSPacket(packetData, true) {
		key := s.createDNSKey(srcIP, srcPort, isIPv6)
		
		s.dnsLock.Lock()
		s.dnsConnTrack[key] = &DNSConnRecord{
			Key:     key,
			Time:    time.Now(),
			SrcIP:   srcIP,    // Store client's source IP
			SrcPort: srcPort,  // Store client's source port
			DstIP:   dstIP,    // Store original destination IP
			DstPort: dstPort,  // Store original destination port (53)
		}
		s.dnsLock.Unlock()
		
		log.Printf("DNS outgoing: src=%v:%d, dst=%v:%d", srcIP, srcPort, dstIP, dstPort)
		return true
	}
	return false
}

// handleDNSIncoming handles incoming DNS response packets
func (s *Server) handleDNSIncoming(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, packetData []byte, isIPv6 bool) (net.IP, uint16, uint16, bool) {
	if len(packetData) < 16 {
		return nil, 0, 0, false
	}

	s.cleanupDNSRecords()

	if s.isDNSPacket(packetData, false) {
		// Use destination (client) IP/port for lookup since that's what we stored in outgoing
		key := s.createDNSKey(dstIP, dstPort, isIPv6)
		
		s.dnsLock.Lock()
		record, exists := s.dnsConnTrack[key]
		if exists {
			delete(s.dnsConnTrack, key)
			s.dnsLock.Unlock()
			log.Printf("DNS incoming: src=%v:%d, original_dst=%v:%d, client_port=%d", 
				srcIP, srcPort, record.DstIP, record.DstPort, record.SrcPort)
			return record.DstIP, record.DstPort, record.SrcPort, true
		}
		s.dnsLock.Unlock()
	}
	return nil, 0, 0, false
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
			if isOutbound && (udp.DstPort == layers.UDPPort(53) || udp.DstPort == layers.UDPPort(s.dnsConfig.IPv4Port)) {
				// Skip if already going to our DNS server
				if (dstIP.String() == s.dnsConfig.IPv4Addr && udp.DstPort == layers.UDPPort(s.dnsConfig.IPv4Port)) ||
					(dstIP.String() == s.dnsConfig.IPv6Addr && udp.DstPort == layers.UDPPort(s.dnsConfig.IPv6Port)) {
					s.nfq.SetVerdict(id, verdict)
					return nil
				}

				if s.handleDNSOutgoing(srcIP, uint16(udp.SrcPort), dstIP, uint16(udp.DstPort), udp.Payload, isIPv6) {
					// Create new packet with modified destination
					buffer := gopacket.NewSerializeBuffer()
					opts := gopacket.SerializeOptions{
						ComputeChecksums: true,
						FixLengths:      true,
					}

					if isIPv6 {
						newDstIP := net.ParseIP(s.dnsConfig.IPv6Addr)
						ipv6.DstIP = newDstIP
						udp.DstPort = layers.UDPPort(s.dnsConfig.IPv6Port)
						udp.SetNetworkLayerForChecksum(ipv6)
						if err := gopacket.SerializeLayers(buffer, opts,
							ipv6, udp, gopacket.Payload(udp.Payload),
						); err != nil {
							return fmt.Errorf("error serializing modified packet: %v", err)
						}
					} else {
						newDstIP := net.ParseIP(s.dnsConfig.IPv4Addr)
						ipv4.DstIP = newDstIP
						udp.DstPort = layers.UDPPort(s.dnsConfig.IPv4Port)
						udp.SetNetworkLayerForChecksum(ipv4)
						if err := gopacket.SerializeLayers(buffer, opts,
							ipv4, udp, gopacket.Payload(udp.Payload),
						); err != nil {
							return fmt.Errorf("error serializing modified packet: %v", err)
						}
					}

					// Send modified packet using raw socket
					if err := sendRawPacket(buffer.Bytes(), isIPv6); err != nil {
						return fmt.Errorf("error sending modified packet: %v", err)
					}
					
					// Drop the original packet
					s.nfq.SetVerdict(id, int(nfqueue.NfDrop))
					return nil
				}
			} else if !isOutbound && (udp.SrcPort == layers.UDPPort(53) || udp.SrcPort == layers.UDPPort(s.dnsConfig.IPv4Port) || udp.SrcPort == layers.UDPPort(s.dnsConfig.IPv6Port)) {
				// Handle incoming DNS response
				if origDstIP, origDstPort, clientSrcPort, ok := s.handleDNSIncoming(srcIP, uint16(udp.SrcPort), dstIP, uint16(udp.DstPort), udp.Payload, isIPv6); ok {
					// Create new packet with modified source/ports
					buffer := gopacket.NewSerializeBuffer()
					opts := gopacket.SerializeOptions{
						ComputeChecksums: true,
						FixLengths:      true,
					}

					if isIPv6 {
						ipv6.SrcIP = origDstIP
						udp.SrcPort = layers.UDPPort(origDstPort)  // Original destination port (53)
						udp.DstPort = layers.UDPPort(clientSrcPort)  // Client's original source port
						udp.SetNetworkLayerForChecksum(ipv6)
						if err := gopacket.SerializeLayers(buffer, opts,
							ipv6, udp, gopacket.Payload(udp.Payload),
						); err != nil {
							return fmt.Errorf("error serializing modified packet: %v", err)
						}
					} else {
						ipv4.SrcIP = origDstIP
						udp.SrcPort = layers.UDPPort(origDstPort)  // Original destination port (53)
						udp.DstPort = layers.UDPPort(clientSrcPort)  // Client's original source port
						udp.SetNetworkLayerForChecksum(ipv4)
						if err := gopacket.SerializeLayers(buffer, opts,
							ipv4, udp, gopacket.Payload(udp.Payload),
						); err != nil {
							return fmt.Errorf("error serializing modified packet: %v", err)
						}
					}

					log.Printf("Modified packet: src=%v:%d, dst=%v:%d",
						origDstIP, udp.SrcPort, dstIP, udp.DstPort)

					// Send modified packet using raw socket
					if err := sendRawPacket(buffer.Bytes(), isIPv6); err != nil {
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
	err = syscall.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		return fmt.Errorf("error setting IP_HDRINCL: %v", err)
	}

	// Mark the packet so it won't be caught by our NFQUEUE rules
	err = syscall.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 1)
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