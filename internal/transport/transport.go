// Package transport — لایه انتقال قابل تعویض
//
// دو حالت:
//   ModeUDP  — UDP ساده، سریع‌ترین، پورت دلخواه
//   ModeObfs — UDP obfuscated، شبیه QUIC از دید DPI، پورت 443
package transport

import (
	"net"
	"time"
)

// Mode نوع transport
type Mode int

const (
	ModeUDP  Mode = iota // UDP ساده
	ModeObfs             // Obfuscated UDP (شبیه QUIC)
)

func (m Mode) String() string {
	if m == ModeObfs {
		return "obfs"
	}
	return "udp"
}

// Transport یه interface مشترک برای ارسال و دریافت UDP
type Transport interface {
	// Send یه datagram میفرسته
	Send(dst *net.UDPAddr, data []byte) error

	// Recv یه datagram دریافت میکنه
	// buf باید حداقل 1500 بایت باشه
	Recv(buf []byte) (n int, from *net.UDPAddr, err error)

	// SetReadDeadline
	SetReadDeadline(t time.Time) error

	// LocalAddr آدرس محلی
	LocalAddr() *net.UDPAddr

	// Close
	Close() error
}
