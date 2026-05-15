// ObfsSpoofTransport — obfs + IP spoof با هم
//
// سرور از این استفاده میکنه وقتی هم transport=obfs هم spoof_ip داریم:
//   1. payload رو با AES-256-GCM encrypt میکنه (همون نود obfs)
//   2. frame رو با AF_PACKET و IP مبدا جعلی میفرسته
//
// کلاینت فقط ObfsTransport معمولی داره — spoof لازم نداره
package transport

import (
	"crypto/cipher"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/sttunnel/internal/spoof"
)

// ObfsSpoofTransport
type ObfsSpoofTransport struct {
	// دریافت (آپلود از کلاینت)
	conn *net.UDPConn

	// ارسال با IP جعلی
	spoofer   *spoof.Sender
	spoofIP   net.IP
	spoofPort uint16

	// رمزنگاری — همون اشتراکی با obfs.go
	aead   cipher.AEAD
	connID [connIDSize]byte
	pktNum atomic.Uint64
	rng    *rand.Rand
}

// NewObfsSpoof یه transport میسازه که هم encrypt میکنه هم spoof
func NewObfsSpoof(
	localPort int,
	key []byte,
	iface string,
	gw net.IP,
	srcIP net.IP,
	srcPort uint16,
) (*ObfsSpoofTransport, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key باید ۳۲ بایت باشه")
	}

	// AES-256-GCM — همون تابع مشترک از obfs.go
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	// UDP socket برای دریافت آپلود
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
	if err != nil {
		return nil, fmt.Errorf("UDP listen: %w", err)
	}
	conn.SetReadBuffer(8 * 1024 * 1024)
	conn.SetWriteBuffer(8 * 1024 * 1024)

	// AF_PACKET sender
	s, err := spoof.NewSender(iface, gw)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("spoof sender: %w", err)
	}

	t := &ObfsSpoofTransport{
		conn:      conn,
		spoofer:   s,
		spoofIP:   srcIP,
		spoofPort: srcPort,
		aead:      aead,
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	// connID از key مشتق میشه — همون روش obfs.go
	deriveConnID(key, t.connID[:])
	return t, nil
}

// Send: encrypt → AF_PACKET با IP جعلی
func (t *ObfsSpoofTransport) Send(dst *net.UDPAddr, data []byte) error {
	pktNum := t.pktNum.Add(1)

	// از تابع مشترک encryptObfs استفاده میکنیم
	// این تضمین میکنه nonce دقیقاً مثل ObfsTransport حساب میشه
	frame, err := encryptObfs(t.aead, t.connID[:], pktNum,
		byte(t.rng.Intn(8)), data)
	if err != nil {
		return err
	}

	// ارسال با IP جعلی از طریق AF_PACKET
	return t.spoofer.Send(spoof.Packet{
		SrcIP:   t.spoofIP,
		DstIP:   dst.IP,
		SrcPort: t.spoofPort,
		DstPort: uint16(dst.Port),
		Payload: frame,
	})
}

// Recv: دریافت آپلود از کلاینت و decrypt
func (t *ObfsSpoofTransport) Recv(buf []byte) (int, *net.UDPAddr, error) {
	raw := make([]byte, 1500+t.aead.Overhead())
	for {
		n, from, err := t.conn.ReadFromUDP(raw)
		if err != nil {
			return 0, nil, err
		}
		// از تابع مشترک decryptObfs — همون که ObfsTransport کلاینت استفاده میکنه
		pt, err := decryptObfs(t.aead, t.connID[:], raw[:n])
		if err != nil {
			// noise یا پکت نامعتبر — ignore
			continue
		}
		return copy(buf, pt), from, nil
	}
}

func (t *ObfsSpoofTransport) SetReadDeadline(d time.Time) error {
	return t.conn.SetReadDeadline(d)
}

func (t *ObfsSpoofTransport) LocalAddr() *net.UDPAddr {
	return t.conn.LocalAddr().(*net.UDPAddr)
}

func (t *ObfsSpoofTransport) Close() error {
	t.spoofer.Close()
	return t.conn.Close()
}
