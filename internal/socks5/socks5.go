// Package socks5 — SOCKS5 server که ErrTCPDown رو handle میکنه
//
// وقتی TCP تونل قطع میشه:
//   - Read از stream → ErrTCPDown
//   - relay به browser pause میکنه (نه بستن connection)
//   - بعد از reconnect، relay ادامه میده
package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sttunnel/internal/pool"
)

// ErrTCPDown باید از package stream import بشه — ولی چون circular میشه،
// اینجا یه نسخه local داریم که با string مقایسه میشه
var errTCPDown = errors.New("TCP temporarily down")

// IsTCPDown بررسی میکنه آیا error مربوط به قطعی TCP تونله
func IsTCPDown(err error) bool {
	return err != nil && err.Error() == "TCP temporarily down"
}

type Dialer func(addrType byte, addr []byte, port uint16) (io.ReadWriteCloser, error)

type Server struct {
	addr      string
	dialer    Dialer
	log       *slog.Logger
	ln        net.Listener
	closed    atomic.Bool
	wg        sync.WaitGroup
	semaphore chan struct{}
}

func New(addr string, dialer Dialer, maxConcurrent int, log *slog.Logger) *Server {
	s := &Server{addr: addr, dialer: dialer, log: log}
	if maxConcurrent > 0 {
		s.semaphore = make(chan struct{}, maxConcurrent)
	}
	return s
}

func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.log.Info("SOCKS5 listening", "addr", s.addr)

	for {
		c, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			continue
		}
		if s.semaphore != nil {
			select {
			case s.semaphore <- struct{}{}:
			default:
				c.Close()
				continue
			}
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(30 * time.Second)
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer func() {
				if s.semaphore != nil {
					<-s.semaphore
				}
			}()
			s.handle(c)
		}(c)
	}
}

func (s *Server) Close() {
	s.closed.Store(true)
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
}

var replyOK = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}

func (s *Server) handle(c net.Conn) {
	defer c.Close()

	if err := negotiate(c); err != nil {
		return
	}
	addrType, addr, port, err := readRequest(c)
	if err != nil {
		return
	}

	remote, err := s.dialer(addrType, addr, port)
	if err != nil {
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	c.Write(replyOK)

	// relay با handling درست ErrTCPDown
	var wg sync.WaitGroup
	wg.Add(2)

	// browser → tunnel (upload)
	go func() {
		defer wg.Done()
		uploadRelay(remote, c, s.log)
	}()

	// tunnel → browser (download)
	go func() {
		defer wg.Done()
		downloadRelay(c, remote, s.log)
	}()

	wg.Wait()
}

// uploadRelay: browser → stream
// اگه stream خطا بده (شامل ErrTCPDown)، فوری بیا بیرون
// browser connection رو نمیبندیم — کل handle تموم میشه و defer remote.Close() اجرا میشه
func uploadRelay(dst io.Writer, src net.Conn, log *slog.Logger) {
	bp := pool.Frame.Get()
	defer pool.Frame.Put(bp)
	buf := *bp

	for {
		// timeout کوتاه روی read از browser — تا بتونیم لایو بمونیم
		if tc, ok := src.(interface{ SetReadDeadline(time.Time) error }); ok {
			tc.SetReadDeadline(time.Now().Add(60 * time.Second))
		}

		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				if IsTCPDown(werr) {
					log.Debug("upload paused: TCP down", "waiting_for_reconnect", true)
					// صبر نمیکنیم — browser رو رها میکنیم تا retry کنه
				}
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// downloadRelay: stream → browser
// ErrTCPDown رو handle میکنه — منتظر میمونه تا TCP برگرده
func downloadRelay(dst net.Conn, src io.Reader, log *slog.Logger) {
	bp := pool.Frame.Get()
	defer pool.Frame.Put(bp)
	buf := *bp

	for {
		n, err := src.Read(buf)
		if n > 0 {
			if tc, ok := dst.(interface{ SetWriteDeadline(time.Time) error }); ok {
				tc.SetWriteDeadline(time.Now().Add(30 * time.Second))
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if IsTCPDown(err) {
				// TCP قطعه — به browser چیزی نمیفرستیم، منتظر reconnect میمونیم
				// Read دوباره فراخوانی میشه و اگه reconnect شد ادامه میده
				log.Debug("download paused: TCP down")
				// کوتاه صبر کن قبل از retry
				time.Sleep(100 * time.Millisecond)
				continue // دوباره Read بزن
			}
			return
		}
	}
}

func negotiate(c net.Conn) error {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})

	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != 5 {
		return errors.New("not socks5")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	_, err := c.Write([]byte{5, 0})
	return err
}

func readRequest(c net.Conn) (addrType byte, addr []byte, port uint16, err error) {
	var req [4]byte
	if _, err = io.ReadFull(c, req[:]); err != nil {
		return
	}
	if req[1] != 1 {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		err = errors.New("unsupported cmd")
		return
	}
	addrType = req[3]
	switch addrType {
	case 0x01:
		addr = make([]byte, 4)
		_, err = io.ReadFull(c, addr)
	case 0x04:
		addr = make([]byte, 16)
		_, err = io.ReadFull(c, addr)
	case 0x03:
		var lb [1]byte
		if _, err = io.ReadFull(c, lb[:]); err != nil {
			return
		}
		addr = make([]byte, 1+int(lb[0]))
		addr[0] = lb[0]
		_, err = io.ReadFull(c, addr[1:])
	default:
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		err = errors.New("unknown atyp")
	}
	if err != nil {
		return
	}
	var portB [2]byte
	_, err = io.ReadFull(c, portB[:])
	port = binary.BigEndian.Uint16(portB[:])
	return
}
