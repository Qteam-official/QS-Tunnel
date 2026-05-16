// Package transport — Obfuscated UDP
//
// ساختار پکت:
//
//   ┌─────┬──────────┬──────────┬──────────────────────┐
//   │ 0x4X│ connID   │ pktNum   │ AES-256-GCM payload  │
//   │ 1 B │ 8 B      │ 8 B      │ N bytes              │
//   └─────┴──────────┴──────────┴──────────────────────┘
//
//   byte اول: 0x40-0x47 = QUIC Short Header pattern
//   connID:   8B ثابت، از key مشتق
//   pktNum:   8B کامل (64bit) = nonce یکتا per packet
//   payload:  AES-256-GCM encrypted, بدون padding
package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"
)

const (
	quicShortHdrByte = byte(0x40)
	connIDSize       = 8
	pktNumSize       = 8
	obfsHdrSize      = 1 + connIDSize + pktNumSize // 17 bytes
)

type ObfsTransport struct {
	conn   *net.UDPConn
	aead   cipher.AEAD
	connID [connIDSize]byte
	pktNum atomic.Uint64
	rng    *rand.Rand
}

func NewObfs(localPort int, key []byte) (*ObfsTransport, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key باید ۳۲ بایت باشه (داده شده: %d)", len(key))
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort})
	if err != nil {
		return nil, fmt.Errorf("UDP listen: %w", err)
	}
	conn.SetReadBuffer(8 * 1024 * 1024)
	conn.SetWriteBuffer(8 * 1024 * 1024)

	t := &ObfsTransport{
		conn: conn,
		aead: aead,
		rng:  rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	deriveConnID(key, t.connID[:])
	return t, nil
}

func (t *ObfsTransport) Send(dst *net.UDPAddr, data []byte) error {
	frame := encryptObfs(t.aead, t.connID[:], t.pktNum.Add(1),
		byte(t.rng.Intn(8)), data)
	_, err := t.conn.WriteToUDP(frame, dst)
	return err
}

func (t *ObfsTransport) Recv(buf []byte) (int, *net.UDPAddr, error) {
	raw := make([]byte, 1500+t.aead.Overhead())
	for {
		n, from, err := t.conn.ReadFromUDP(raw)
		if err != nil {
			return 0, nil, err
		}
		pt, err := decryptObfs(t.aead, t.connID[:], raw[:n])
		if err != nil {
			continue
		}
		return copy(buf, pt), from, nil
	}
}

func (t *ObfsTransport) SetReadDeadline(d time.Time) error { return t.conn.SetReadDeadline(d) }
func (t *ObfsTransport) LocalAddr() *net.UDPAddr           { return t.conn.LocalAddr().(*net.UDPAddr) }
func (t *ObfsTransport) Close() error                      { return t.conn.Close() }

// ─── shared helpers (مشترک با obfs_spoof.go) ─────────────────────────────────

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}
	return aead, nil
}

// encryptObfs: data → obfs frame
// بدون padding — داده مستقیم encrypt میشه
func encryptObfs(aead cipher.AEAD, connID []byte, pktNum uint64, randBits byte, data []byte) []byte {
	// nonce: [4B zero][8B pktNum]
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], pktNum)

	encrypted := aead.Seal(nil, nonce[:], data, nil)

	frame := make([]byte, obfsHdrSize+len(encrypted))
	frame[0] = quicShortHdrByte | (randBits & 0x07)
	copy(frame[1:1+connIDSize], connID)
	binary.BigEndian.PutUint64(frame[1+connIDSize:obfsHdrSize], pktNum)
	copy(frame[obfsHdrSize:], encrypted)
	return frame
}

// decryptObfs: obfs frame → data
func decryptObfs(aead cipher.AEAD, connID []byte, frame []byte) ([]byte, error) {
	if len(frame) < obfsHdrSize+aead.Overhead() {
		return nil, errors.New("too short")
	}
	if frame[0]&0xC0 != 0x40 {
		return nil, errors.New("not QUIC short header")
	}
	if string(frame[1:1+connIDSize]) != string(connID) {
		return nil, errors.New("connID mismatch")
	}
	pktNum := binary.BigEndian.Uint64(frame[1+connIDSize : obfsHdrSize])

	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], pktNum)

	pt, err := aead.Open(nil, nonce[:], frame[obfsHdrSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return pt, nil
}

// deriveConnID: از key مشتق میکنه
func deriveConnID(key []byte, out []byte) {
	for i := 0; i < connIDSize; i++ {
		out[i] = key[i] ^ key[i+8] ^ key[i+16] ^ key[i+24]
	}
}
