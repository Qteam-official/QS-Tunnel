// Package spoof — AF_PACKET sender با بهینه‌سازی
//
// بهینه‌سازی:
//   - frame buffer reusable (یه بار alloc، چندبار استفاده)
//   - ARP cache در memory (نه read /proc/net/arp هر بار)
package spoof

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type Packet struct {
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	Payload          []byte
}

type Sender struct {
	fd      int
	ifIndex int
	srcMAC  [6]byte
	gwMAC   [6]byte

	// frame buffer قابل reuse — به ازای هر sender جداگانه (نه shared)
	frameBuf []byte
	mu       sync.Mutex
}

// NewSender یه sender جدید
func NewSender(iface string, gatewayIP net.IP) (*Sender, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}
	if len(ifi.HardwareAddr) < 6 {
		return nil, fmt.Errorf("%s MAC ندارد", iface)
	}

	gwMAC, err := arpLookup(gatewayIP.String(), iface)
	if err != nil {
		return nil, fmt.Errorf("ARP %s: %w\nاول: ping -c3 %s", gatewayIP, err, gatewayIP)
	}

	fd, err := syscall.Socket(
		syscall.AF_PACKET,
		syscall.SOCK_RAW,
		int(htons(syscall.ETH_P_ALL)),
	)
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET: %w", err)
	}

	// non-blocking برای ENOBUFS handling بهتر
	syscall.SetNonblock(fd, true)

	s := &Sender{
		fd:       fd,
		ifIndex:  ifi.Index,
		frameBuf: make([]byte, 1600), // > MTU
	}
	copy(s.srcMAC[:], ifi.HardwareAddr[:6])
	copy(s.gwMAC[:], gwMAC[:6])
	return s, nil
}

// Send یه packet با IP مبدا جعلی میفرسته
func (s *Sender) Send(p Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	udpLen := 8 + len(p.Payload)
	ipLen := 20 + udpLen
	frameLen := 14 + ipLen

	if frameLen > cap(s.frameBuf) {
		s.frameBuf = make([]byte, frameLen)
	}
	frame := s.frameBuf[:frameLen]

	// Ethernet
	copy(frame[0:6], s.gwMAC[:])
	copy(frame[6:12], s.srcMAC[:])
	frame[12], frame[13] = 0x08, 0x00

	// IP
	ip := frame[14:]
	ip[0] = 0x45
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	binary.BigEndian.PutUint16(ip[4:6], 0)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // DF
	ip[8] = 64                                   // TTL
	ip[9] = syscall.IPPROTO_UDP
	ip[10], ip[11] = 0, 0
	copy(ip[12:16], p.SrcIP.To4())
	copy(ip[16:20], p.DstIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], ipCsum(ip[:20]))

	// UDP
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], p.SrcPort)
	binary.BigEndian.PutUint16(udp[2:4], p.DstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	udp[6], udp[7] = 0, 0
	copy(udp[8:], p.Payload)

	sa := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  s.ifIndex,
		Halen:    6,
	}
	copy(sa.Addr[:6], s.gwMAC[:])

	return syscall.Sendto(s.fd, frame, 0, &sa)
}

func (s *Sender) Close() error { return syscall.Close(s.fd) }

// ─── ARP & routing ────────────────────────────────────────────────────────────

func arpLookup(ip, iface string) (net.HardwareAddr, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		if f[0] == ip && f[5] == iface && f[3] != "00:00:00:00:00:00" {
			return net.ParseMAC(f[3])
		}
	}
	return nil, fmt.Errorf("MAC %s on %s نیست", ip, iface)
}

// DefaultGateway gateway پیش‌فرض رو از /proc/net/route میخونه
func DefaultGateway() (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		if f[1] == "00000000" {
			var b [4]byte
			fmt.Sscanf(f[2][6:8], "%02x", &b[0])
			fmt.Sscanf(f[2][4:6], "%02x", &b[1])
			fmt.Sscanf(f[2][2:4], "%02x", &b[2])
			fmt.Sscanf(f[2][0:2], "%02x", &b[3])
			return net.IP(b[:]).String(), nil
		}
	}
	return "", fmt.Errorf("default route نیست")
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func ipCsum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func htons(i uint16) uint16 {
	b := [2]byte{}
	binary.BigEndian.PutUint16(b[:], i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
