// UDP ساده — سریع‌ترین حالت
package transport

import (
	"net"
	"time"

	"github.com/sttunnel/internal/spoof"
)

// UDPTransport UDP ساده
type UDPTransport struct {
	conn *net.UDPConn
}

func NewUDP(localPort int) (*UDPTransport, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
	if err != nil {
		return nil, err
	}
	conn.SetReadBuffer(8 * 1024 * 1024)
	conn.SetWriteBuffer(8 * 1024 * 1024)
	return &UDPTransport{conn: conn}, nil
}

func (t *UDPTransport) Send(dst *net.UDPAddr, data []byte) error {
	_, err := t.conn.WriteToUDP(data, dst)
	return err
}

func (t *UDPTransport) Recv(buf []byte) (int, *net.UDPAddr, error) {
	return t.conn.ReadFromUDP(buf)
}

func (t *UDPTransport) SetReadDeadline(d time.Time) error {
	return t.conn.SetReadDeadline(d)
}

func (t *UDPTransport) LocalAddr() *net.UDPAddr {
	return t.conn.LocalAddr().(*net.UDPAddr)
}

func (t *UDPTransport) Close() error {
	return t.conn.Close()
}

// ─── UDPWithSpoof ─────────────────────────────────────────────────────────────

// UDPWithSpoof UDP با IP مبدا جعلی (فقط سرور)
type UDPWithSpoof struct {
	conn      *net.UDPConn
	spoofer   *spoof.Sender
	spoofIP   net.IP
	spoofPort uint16
}

func NewUDPWithSpoof(localPort int, iface string, gw net.IP, srcIP net.IP, srcPort uint16) (*UDPWithSpoof, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
	if err != nil {
		return nil, err
	}
	conn.SetReadBuffer(8 * 1024 * 1024)
	conn.SetWriteBuffer(8 * 1024 * 1024)

	s, err := spoof.NewSender(iface, gw)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &UDPWithSpoof{
		conn:      conn,
		spoofer:   s,
		spoofIP:   srcIP,
		spoofPort: srcPort,
	}, nil
}

func (t *UDPWithSpoof) Send(dst *net.UDPAddr, data []byte) error {
	return t.spoofer.Send(spoof.Packet{
		SrcIP:   t.spoofIP,
		DstIP:   dst.IP,
		SrcPort: t.spoofPort,
		DstPort: uint16(dst.Port),
		Payload: data,
	})
}

func (t *UDPWithSpoof) Recv(buf []byte) (int, *net.UDPAddr, error) {
	return t.conn.ReadFromUDP(buf)
}

func (t *UDPWithSpoof) SetReadDeadline(d time.Time) error {
	return t.conn.SetReadDeadline(d)
}

func (t *UDPWithSpoof) LocalAddr() *net.UDPAddr {
	return t.conn.LocalAddr().(*net.UDPAddr)
}

func (t *UDPWithSpoof) Close() error {
	t.spoofer.Close()
	return t.conn.Close()
}
