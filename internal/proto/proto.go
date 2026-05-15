// Package proto — پروتکل wire بهینه
//
// ═══════════════════════════════════════════════════════
//  TCP frame (multiplexed)
// ═══════════════════════════════════════════════════════
//
//  ┌──────────┬──────────┬──────────┬────────────────┐
//  │ StreamID │  Type    │  Length  │  Payload       │
//  │  3 B     │  1 B     │  2 B     │  N bytes       │
//  └──────────┴──────────┴──────────┴────────────────┘
//
//  StreamID: 24bit → حداکثر 16M stream همزمان (کافیه)
//  Length: 16bit → حداکثر 64KB payload
//  کل header: 6 بایت (قبل 8 بایت بود → 25% کمتر)
//
// ═══════════════════════════════════════════════════════
//  UDP datagram (دانلود)
// ═══════════════════════════════════════════════════════
//
//  ┌────────┬──────────┬──────────┬────────┬─────────┐
//  │ Magic  │ StreamID │  SeqNum  │ Flags  │ Payload │
//  │  2 B   │  3 B     │  3 B     │  1 B   │  var    │
//  └────────┴──────────┴──────────┴────────┴─────────┘
//
//  StreamID: 24bit (3B بجای 4B)
//  SeqNum:   24bit (3B بجای 4B) → کافی برای 16M پکت per stream
//  کل header: 9 بایت (قبل 11 بایت بود → 18% کمتر)
//
// ═══════════════════════════════════════════════════════
//  Packet Coalescing (TCP upload)
// ═══════════════════════════════════════════════════════
//
//  پکت‌های کوچیک (<coalescThresh) رو با هم merge میکنیم
//  قبل از فرستادن → syscall کمتر → throughput بیشتر
//
// ═══════════════════════════════════════════════════════
//  فشرده‌سازی
// ═══════════════════════════════════════════════════════
//
//  فقط روی plaintext ترافیک فعاله (نه TLS/encrypted)
//  تشخیص: اگه اولین بایت payload نشانه TLS باشه → skip
//  الگوریتم: LZ4 (سریعترین decompressor موجود)
//  چون encrypted data فشرده نمیشه، overhead detection رو نگه میداریم کم
package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ─── Sizes ────────────────────────────────────────────────────────────────────

const (
	TCPHdrSize   = 6    // streamID(3)+type(1)+length(2)  [قبلاً 8]
	UDPHdrSize   = 9    // magic(2)+streamID(3)+seq(3)+flags(1)  [قبلاً 11]
	UDPMagic     = uint16(0xABCD)
	MaxPayload   = 1460
	MaxFrameSize = 64 * 1024

	SessionIDLen = 16
)

// ─── TCP Types ────────────────────────────────────────────────────────────────

const (
	MsgHello    = byte(0x01)
	MsgConnect  = byte(0x02)
	MsgConnAck  = byte(0x03)
	MsgConnErr  = byte(0x04)
	MsgData     = byte(0x05)
	MsgClose    = byte(0x06)
	MsgPing     = byte(0x07)
	MsgPong     = byte(0x08)
	MsgFlowAck  = byte(0x09)
)

// ─── UDP Flags ────────────────────────────────────────────────────────────────

const (
	FlagLast  = byte(0x01)
	FlagClose = byte(0x02)
)

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	ErrShort  = errors.New("frame too short")
	ErrMagic  = errors.New("bad magic")
	ErrTooBig = errors.New("frame too large")
)

// ─── TCP Header encode/decode (6 bytes) ──────────────────────────────────────

// EncodeTCPHdr 6 بایت header مینویسه
// streamID: 24bit (3 bytes)
// msgType:  8bit
// length:   16bit
func EncodeTCPHdr(b []byte, streamID uint32, msgType byte, payloadLen int) {
	b[0] = byte(streamID >> 16)
	b[1] = byte(streamID >> 8)
	b[2] = byte(streamID)
	b[3] = msgType
	b[4] = byte(payloadLen >> 8)
	b[5] = byte(payloadLen)
}

func DecodeTCPHdr(b []byte) (streamID uint32, msgType byte, payloadLen int) {
	streamID = uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	msgType = b[3]
	payloadLen = int(b[4])<<8 | int(b[5])
	return
}

// ─── TCP Frame ────────────────────────────────────────────────────────────────

type TCPFrame struct {
	StreamID uint32
	Type     byte
	Payload  []byte
}

func ReadTCPFrame(r io.Reader) (TCPFrame, error) {
	var hdr [TCPHdrSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return TCPFrame{}, err
	}
	sid, mt, n := DecodeTCPHdr(hdr[:])
	if n > MaxFrameSize {
		return TCPFrame{}, ErrTooBig
	}
	var pay []byte
	if n > 0 {
		pay = make([]byte, n)
		if _, err := io.ReadFull(r, pay); err != nil {
			return TCPFrame{}, err
		}
	}
	return TCPFrame{StreamID: sid, Type: mt, Payload: pay}, nil
}

// ─── UDP Header (9 bytes) ────────────────────────────────────────────────────

// EncodeUDP یه UDP datagram کامل میسازه — zero allocation اگه dst کافی باشه
func EncodeUDP(dst []byte, streamID, seq uint32, flags byte, payload []byte) int {
	binary.BigEndian.PutUint16(dst[0:2], UDPMagic)
	// StreamID: 24bit
	dst[2] = byte(streamID >> 16)
	dst[3] = byte(streamID >> 8)
	dst[4] = byte(streamID)
	// Seq: 24bit
	dst[5] = byte(seq >> 16)
	dst[6] = byte(seq >> 8)
	dst[7] = byte(seq)
	dst[8] = flags
	copy(dst[UDPHdrSize:], payload)
	return UDPHdrSize + len(payload)
}

type UDPHeader struct {
	StreamID uint32
	Seq      uint32
	Flags    byte
}

func DecodeUDPHdr(b []byte) (h UDPHeader, payloadStart int, err error) {
	if len(b) < UDPHdrSize {
		err = ErrShort
		return
	}
	if binary.BigEndian.Uint16(b[0:2]) != UDPMagic {
		err = ErrMagic
		return
	}
	h.StreamID = uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4])
	h.Seq = uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	h.Flags = b[8]
	payloadStart = UDPHdrSize
	return
}

// ─── Coalescing Writer ────────────────────────────────────────────────────────
//
// پکت‌های کوچیک رو جمع میکنه تا یه batch بفرسته.
// این syscall‌ها رو کم میکنه و throughput رو بالا میبره.
//
// منطق:
//   - اگه payload < coalescThresh: نگه دار
//   - اگه buffer پر شد یا maxDelay گذشت: flush
//   - اگه payload >= coalescThresh: مستقیم بفرست

const (
	coalescThresh = 256             // پکت کوچیک‌تر از این coalesce میشه
	coalescBufSize = 32 * 1024      // حداکثر buffer قبل از flush
	coalescDelay   = 2 * time.Millisecond // حداکثر تاخیر
)

type CoalescingWriter struct {
	mu     sync.Mutex
	conn   io.Writer
	buf    []byte
	timer  *time.Timer
	closed bool
}

func NewCoalescingWriter(conn io.Writer) *CoalescingWriter {
	cw := &CoalescingWriter{
		conn: conn,
		buf:  make([]byte, 0, coalescBufSize),
	}
	return cw
}

// Write یه frame رو مینویسه (با coalescing)
func (cw *CoalescingWriter) Write(hdr []byte, payload []byte) error {
	total := len(hdr) + len(payload)

	cw.mu.Lock()
	defer cw.mu.Unlock()

	if cw.closed {
		return io.ErrClosedPipe
	}

	// اگه بزرگه → مستقیم flush و بفرست
	if total >= coalescThresh || len(cw.buf)+total > coalescBufSize {
		if len(cw.buf) > 0 {
			if err := cw.flushLocked(); err != nil {
				return err
			}
		}
		// مستقیم بنویس بدون copy
		if _, err := cw.conn.Write(hdr); err != nil {
			return err
		}
		if len(payload) > 0 {
			_, err := cw.conn.Write(payload)
			return err
		}
		return nil
	}

	// کوچیکه → اضافه کن به buffer
	cw.buf = append(cw.buf, hdr...)
	cw.buf = append(cw.buf, payload...)

	// timer برای flush
	if cw.timer == nil {
		cw.timer = time.AfterFunc(coalescDelay, func() {
			cw.mu.Lock()
			cw.flushLocked()
			cw.timer = nil
			cw.mu.Unlock()
		})
	}
	return nil
}

// Flush فوری همه چیز رو میفرسته
func (cw *CoalescingWriter) Flush() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	return cw.flushLocked()
}

func (cw *CoalescingWriter) flushLocked() error {
	if len(cw.buf) == 0 {
		return nil
	}
	if cw.timer != nil {
		cw.timer.Stop()
		cw.timer = nil
	}
	_, err := cw.conn.Write(cw.buf)
	cw.buf = cw.buf[:0]
	return err
}

func (cw *CoalescingWriter) Close() {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.closed = true
	if cw.timer != nil {
		cw.timer.Stop()
		cw.timer = nil
	}
	cw.flushLocked()
}

// ─── Hello payload ────────────────────────────────────────────────────────────

func EncodeHello(sessionID [SessionIDLen]byte, ip net.IP, port uint16) []byte {
	b := make([]byte, SessionIDLen+6)
	copy(b[0:SessionIDLen], sessionID[:])
	copy(b[SessionIDLen:SessionIDLen+4], ip.To4())
	binary.BigEndian.PutUint16(b[SessionIDLen+4:], port)
	return b
}

func DecodeHello(b []byte) (sessionID [SessionIDLen]byte, ip net.IP, port uint16, err error) {
	if len(b) < SessionIDLen+6 {
		err = ErrShort
		return
	}
	copy(sessionID[:], b[0:SessionIDLen])
	ip = make(net.IP, 4)
	copy(ip, b[SessionIDLen:SessionIDLen+4])
	port = binary.BigEndian.Uint16(b[SessionIDLen+4:])
	return
}

// ─── Connect payload ──────────────────────────────────────────────────────────

type ConnectPayload struct {
	AddrType byte
	Addr     []byte
	Port     uint16
}

func EncodeConnect(c ConnectPayload) []byte {
	b := make([]byte, 1+len(c.Addr)+2)
	b[0] = c.AddrType
	copy(b[1:], c.Addr)
	binary.BigEndian.PutUint16(b[1+len(c.Addr):], c.Port)
	return b
}

func DecodeConnect(b []byte) (ConnectPayload, error) {
	if len(b) < 4 {
		return ConnectPayload{}, ErrShort
	}
	at := b[0]
	var al int
	switch at {
	case 0x01:
		al = 4
	case 0x04:
		al = 16
	case 0x03:
		al = 1 + int(b[1])
	default:
		return ConnectPayload{}, errors.New("unknown addr type")
	}
	if len(b) < 1+al+2 {
		return ConnectPayload{}, ErrShort
	}
	return ConnectPayload{
		AddrType: at,
		Addr:     b[1 : 1+al],
		Port:     binary.BigEndian.Uint16(b[1+al:]),
	}, nil
}

func (c ConnectPayload) HostPort() string {
	switch c.AddrType {
	case 0x01:
		return fmt.Sprintf("%s:%d", net.IP(c.Addr).String(), c.Port)
	case 0x04:
		return fmt.Sprintf("[%s]:%d", net.IP(c.Addr).String(), c.Port)
	case 0x03:
		return fmt.Sprintf("%s:%d", string(c.Addr[1:]), c.Port)
	}
	return ""
}

// ─── FlowAck ─────────────────────────────────────────────────────────────────

func EncodeFlowAck(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

func DecodeFlowAck(b []byte) (uint32, error) {
	if len(b) < 4 {
		return 0, ErrShort
	}
	return binary.BigEndian.Uint32(b), nil
}
