package proxy

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DNSHandler handles DNS packet interception and modification
type DNSHandler struct {
	config       *Config
	connTrack    map[string]*DNSConnRecord
	lock         sync.RWMutex
	lastCleanup  time.Time
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

const (
	dnsCleanupInterval = 30 * time.Second
)

// NewDNSHandler creates a new DNS handler
func NewDNSHandler(config *Config) *DNSHandler {
	return &DNSHandler{
		config:      config,
		connTrack:   make(map[string]*DNSConnRecord),
		lastCleanup: time.Now(),
	}
}

// isDNSPacket checks if a packet is a DNS packet
func (h *DNSHandler) isDNSPacket(packetData []byte, outgoing bool) bool {
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
func (h *DNSHandler) createDNSKey(srcIP net.IP, srcPort uint16, isIPv6 bool) string {
	version := "4"
	if isIPv6 {
		version = "6"
	}
	return fmt.Sprintf("%s%s%d", version, srcIP.String(), srcPort)
}

// cleanupRecords removes old DNS connection tracking records
func (h *DNSHandler) cleanupRecords() {
	if time.Since(h.lastCleanup) < dnsCleanupInterval {
		return
	}

	h.lock.Lock()
	defer h.lock.Unlock()

	now := time.Now()
	for key, record := range h.connTrack {
		if now.Sub(record.Time) >= dnsCleanupInterval {
			delete(h.connTrack, key)
		}
	}
	h.lastCleanup = now
}

// handleOutgoing handles outgoing DNS packets
func (h *DNSHandler) handleOutgoing(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, packetData []byte, isIPv6 bool) bool {
	if len(packetData) < 16 {
		return false
	}

	h.cleanupRecords()

	if h.isDNSPacket(packetData, true) {
		key := h.createDNSKey(srcIP, srcPort, isIPv6)
		
		h.lock.Lock()
		h.connTrack[key] = &DNSConnRecord{
			Key:     key,
			Time:    time.Now(),
			SrcIP:   srcIP,    // Store client's source IP
			SrcPort: srcPort,  // Store client's source port
			DstIP:   dstIP,    // Store original destination IP
			DstPort: dstPort,  // Store original destination port (53)
		}
		h.lock.Unlock()
		
		log.Printf("DNS outgoing: src=%v:%d, dst=%v:%d", srcIP, srcPort, dstIP, dstPort)
		return true
	}
	return false
}

// handleIncoming handles incoming DNS response packets
func (h *DNSHandler) handleIncoming(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, packetData []byte, isIPv6 bool) (net.IP, uint16, uint16, bool) {
	if len(packetData) < 16 {
		return nil, 0, 0, false
	}

	h.cleanupRecords()

	if h.isDNSPacket(packetData, false) {
		// Use destination (client) IP/port for lookup since that's what we stored in outgoing
		key := h.createDNSKey(dstIP, dstPort, isIPv6)
		
		h.lock.Lock()
		record, exists := h.connTrack[key]
		if exists {
			delete(h.connTrack, key)
			h.lock.Unlock()
			log.Printf("DNS incoming: src=%v:%d, original_dst=%v:%d, client_port=%d", 
				srcIP, srcPort, record.DstIP, record.DstPort, record.SrcPort)
			return record.DstIP, record.DstPort, record.SrcPort, true
		}
		h.lock.Unlock()
	}
	return nil, 0, 0, false
}

// modifyOutgoingPacket modifies an outgoing DNS packet
func (h *DNSHandler) modifyOutgoingPacket(packet gopacket.Packet, isIPv6 bool) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:      true,
	}

	ipLayer := packet.NetworkLayer()
	udpLayer := packet.TransportLayer().(*layers.UDP)

	if isIPv6 {
		ipv6 := ipLayer.(*layers.IPv6)
		newDstIP := net.ParseIP(h.config.DNSIPv6Addr)
		ipv6.DstIP = newDstIP
		udpLayer.DstPort = layers.UDPPort(h.config.DNSIPv6Port)
		udpLayer.SetNetworkLayerForChecksum(ipv6)
		if err := gopacket.SerializeLayers(buffer, opts,
			ipv6, udpLayer, gopacket.Payload(udpLayer.Payload),
		); err != nil {
			return nil, fmt.Errorf("error serializing modified packet: %v", err)
		}
	} else {
		ipv4 := ipLayer.(*layers.IPv4)
		newDstIP := net.ParseIP(h.config.DNSIPv4Addr)
		ipv4.DstIP = newDstIP
		udpLayer.DstPort = layers.UDPPort(h.config.DNSIPv4Port)
		udpLayer.SetNetworkLayerForChecksum(ipv4)
		if err := gopacket.SerializeLayers(buffer, opts,
			ipv4, udpLayer, gopacket.Payload(udpLayer.Payload),
		); err != nil {
			return nil, fmt.Errorf("error serializing modified packet: %v", err)
		}
	}

	return buffer.Bytes(), nil
}

// modifyIncomingPacket modifies an incoming DNS packet
func (h *DNSHandler) modifyIncomingPacket(packet gopacket.Packet, origDstIP net.IP, origDstPort uint16, clientSrcPort uint16, isIPv6 bool) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:      true,
	}

	ipLayer := packet.NetworkLayer()
	udpLayer := packet.TransportLayer().(*layers.UDP)

	if isIPv6 {
		ipv6 := ipLayer.(*layers.IPv6)
		ipv6.SrcIP = origDstIP
		udpLayer.SrcPort = layers.UDPPort(origDstPort)  // Original destination port (53)
		udpLayer.DstPort = layers.UDPPort(clientSrcPort)  // Client's original source port
		udpLayer.SetNetworkLayerForChecksum(ipv6)
		if err := gopacket.SerializeLayers(buffer, opts,
			ipv6, udpLayer, gopacket.Payload(udpLayer.Payload),
		); err != nil {
			return nil, fmt.Errorf("error serializing modified packet: %v", err)
		}
	} else {
		ipv4 := ipLayer.(*layers.IPv4)
		ipv4.SrcIP = origDstIP
		udpLayer.SrcPort = layers.UDPPort(origDstPort)  // Original destination port (53)
		udpLayer.DstPort = layers.UDPPort(clientSrcPort)  // Client's original source port
		udpLayer.SetNetworkLayerForChecksum(ipv4)
		if err := gopacket.SerializeLayers(buffer, opts,
			ipv4, udpLayer, gopacket.Payload(udpLayer.Payload),
		); err != nil {
			return nil, fmt.Errorf("error serializing modified packet: %v", err)
		}
	}

	return buffer.Bytes(), nil
}