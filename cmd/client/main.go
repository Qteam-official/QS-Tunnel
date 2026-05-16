// sttunnel client
//
// معماری: هر stream → TCP connection مستقل
//   - قطع یه proxy فقط اون stream رو تحت تأثیر میذاره
//   - reconnect per-stream با exponential backoff
//   - UDP دانلود مشترک (stateless)
package main

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	cfgpkg "github.com/sttunnel/internal/config"
	"github.com/sttunnel/internal/metrics"
	"github.com/sttunnel/internal/proto"
	"github.com/sttunnel/internal/reasm"
	"github.com/sttunnel/internal/socks5"
	"github.com/sttunnel/internal/transport"
)

var M = metrics.New()

const (
	flowAckUnit  = 16 * 1024
	maxReconnect = 8
)

// ─── session ID مشترک بین همه stream‌ها ──────────────────────────────────────

var globalSessionID [proto.SessionIDLen]byte

// ─── stream ──────────────────────────────────────────────────────────────────
// هر stream یه TCP connection مستقل به upload proxy دارد

type stream struct {
	id          uint32
	addrType    byte
	addr        []byte
	port        uint16
	uploadProxy string
	serverAddr  string
	udpAddr     *net.UDPAddr
	reasmMgr    *reasm.Manager

	// TCP connection این stream
	mu     sync.Mutex
	conn   net.Conn
	writer *tcpWriter

	// reassembler (دانلود)
	rx atomic.Pointer[reasm.Reassembler]

	// lifecycle
	ctx    context.Context
	cancel context.CancelFunc

	bytesUnacked atomic.Int64
	closed       atomic.Bool
	closeFn      func()
	log          *slog.Logger
}

func newStream(
	id uint32, parentCtx context.Context,
	uploadProxy, serverAddr string,
	udpAddr *net.UDPAddr,
	reasmMgr *reasm.Manager,
	addrType byte, addr []byte, port uint16,
	log *slog.Logger,
) *stream {
	ctx, cancel := context.WithCancel(parentCtx)
	s := &stream{
		id: id, addrType: addrType,
		addr: append([]byte{}, addr...), port: port,
		uploadProxy: uploadProxy, serverAddr: serverAddr,
		udpAddr: udpAddr, reasmMgr: reasmMgr,
		ctx: ctx, cancel: cancel, log: log,
	}
	s.rx.Store(reasm.New(1))
	return s
}

// dial: اتصال TCP + Hello + Connect
func (s *stream) dial() error {
	conn, err := dialViaSocks5(s.uploadProxy, s.serverAddr)
	if err != nil {
		return err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(10 * time.Second)
		tc.SetReadBuffer(256 * 1024)
		tc.SetWriteBuffer(256 * 1024)
	}

	w := newTCPWriter(conn)

	// Hello
	helloPayload := proto.EncodeHello(globalSessionID, s.udpAddr.IP, uint16(s.udpAddr.Port))
	if err := w.write(0, proto.MsgHello, helloPayload, true); err != nil {
		w.close(); conn.Close()
		return fmt.Errorf("hello: %w", err)
	}

	// Connect
	errCh := make(chan error, 1)
	ackDone := make(chan struct{})
	go func() {
		defer close(ackDone)
		for {
			f, err := proto.ReadTCPFrame(conn)
			if err != nil { errCh <- err; return }
			switch f.Type {
			case proto.MsgConnAck:
				errCh <- nil; return
			case proto.MsgConnErr:
				errCh <- errors.New("connect rejected"); return
			case proto.MsgPing:
				w.write(0, proto.MsgPong, nil, false)
			}
		}
	}()

	if err := w.write(s.id, proto.MsgConnect,
		proto.EncodeConnect(proto.ConnectPayload{
			AddrType: s.addrType, Addr: s.addr, Port: s.port,
		}), false,
	); err != nil {
		w.close(); conn.Close()
		return fmt.Errorf("connect write: %w", err)
	}

	select {
	case err := <-errCh:
		if err != nil { w.close(); conn.Close(); return err }
	case <-time.After(15 * time.Second):
		w.close(); conn.Close()
		return errors.New("connack timeout")
	case <-s.ctx.Done():
		w.close(); conn.Close()
		return s.ctx.Err()
	}

	// reassembler جدید
	oldRx := s.rx.Load()
	newRx := reasm.New(1)
	s.rx.Store(newRx)
	s.reasmMgr.Register(s.id, newRx)
	if oldRx != nil {
		oldRx.Close()
	}

	s.mu.Lock()
	s.conn = conn
	s.writer = w
	s.mu.Unlock()

	// reader loop
	go s.readLoop(conn, w)
	return nil
}

func (s *stream) readLoop(conn net.Conn, w *tcpWriter) {
	defer func() {
		w.close()
		conn.Close()
		s.mu.Lock()
		if s.writer == w {
			s.writer = nil
			s.conn = nil
		}
		s.mu.Unlock()

		if !s.closed.Load() {
			go s.reconnect()
		}
	}()

	for {
		f, err := proto.ReadTCPFrame(conn)
		if err != nil {
			if !s.closed.Load() {
				s.log.Debug("TCP read end", "sid", s.id, "err", err)
			}
			return
		}
		switch f.Type {
		case proto.MsgClose:
			s.Close()
			return
		case proto.MsgPing:
			w.write(0, proto.MsgPong, nil, false)
		}
	}
}

func (s *stream) reconnect() {
	backoff := 500 * time.Millisecond
	for i := 1; i <= maxReconnect; i++ {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(backoff):
		}
		if s.closed.Load() {
			return
		}
		s.log.Info("🔄 reconnect", "sid", s.id, "attempt", i)
		if err := s.dial(); err == nil {
			s.log.Info("✅ reconnect OK", "sid", s.id)
			M.Reconnects.Add(1)
			return
		}
		backoff = minDur(backoff*2, 20*time.Second)
	}
	s.log.Warn("❌ reconnect failed", "sid", s.id)
	s.Close()
}

func (s *stream) Write(p []byte) (int, error) {
	for {
		if s.closed.Load() {
			return 0, io.ErrClosedPipe
		}
		select {
		case <-s.ctx.Done():
			return 0, io.ErrClosedPipe
		default:
		}

		s.mu.Lock()
		w := s.writer
		s.mu.Unlock()

		if w == nil {
			// TCP در حال reconnect — کوتاه صبر کن
			select {
			case <-s.ctx.Done():
				return 0, io.ErrClosedPipe
			case <-time.After(200 * time.Millisecond):
				continue
			}
		}

		if err := w.write(s.id, proto.MsgData, p, false); err != nil {
			// TCP قطع شد — reconnect در جریانه
			select {
			case <-s.ctx.Done():
				return 0, io.ErrClosedPipe
			case <-time.After(200 * time.Millisecond):
				continue
			}
		}

		M.UploadBytes.Add(uint64(len(p)))
		M.UploadPackets.Add(1)
		return len(p), nil
	}
}

func (s *stream) Read(p []byte) (int, error) {
	for {
		if s.closed.Load() {
			return 0, io.EOF
		}
		rx := s.rx.Load()
		select {
		case <-s.ctx.Done():
			return 0, io.EOF
		case data, ok := <-rx.Chan():
			if !ok {
				if s.closed.Load() {
					return 0, io.EOF
				}
				time.Sleep(20 * time.Millisecond)
				continue
			}
			n := copy(p, data)
			unacked := s.bytesUnacked.Add(int64(n))
			if unacked >= flowAckUnit {
				toAck := s.bytesUnacked.Swap(0)
				s.mu.Lock()
				w := s.writer
				s.mu.Unlock()
				if w != nil {
					_ = w.write(s.id, proto.MsgFlowAck,
						proto.EncodeFlowAck(uint32(toAck)), false)
					M.FlowAcksSent.Add(1)
				}
			}
			return n, nil
		}
	}
}

func (s *stream) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.cancel()

		s.mu.Lock()
		w := s.writer
		conn := s.conn
		s.writer = nil
		s.conn = nil
		s.mu.Unlock()

		if rx := s.rx.Load(); rx != nil {
			rx.Close()
		}
		s.reasmMgr.Unregister(s.id)

		if w != nil {
			// MsgClose بفرست — بعد conn رو ببند
			// w.close() رو صدا نمیکنیم چون readLoop خودش صدا میکنه
			_ = w.write(s.id, proto.MsgClose, nil, false)
		}
		if conn != nil {
			// بستن conn باعث میشه readLoop از ReadTCPFrame با error برگرده
			// → readLoop.defer → w.close() فقط یه بار
			conn.Close()
		}
		if s.closeFn != nil {
			s.closeFn()
		}
	}
	return nil
}

// ─── streamMux ───────────────────────────────────────────────────────────────

type streamMux struct {
	mu       sync.RWMutex
	streams  map[uint32]*stream
	reasmMgr *reasm.Manager
	nextID   atomic.Uint32
}

func newMux() *streamMux {
	return &streamMux{
		streams:  make(map[uint32]*stream),
		reasmMgr: reasm.NewManager(),
	}
}

func (m *streamMux) add(s *stream) {
	m.mu.Lock()
	m.streams[s.id] = s
	m.mu.Unlock()
}

func (m *streamMux) get(id uint32) (*stream, bool) {
	m.mu.RLock()
	s, ok := m.streams[id]
	m.mu.RUnlock()
	return s, ok
}

func (m *streamMux) remove(id uint32) {
	m.mu.Lock()
	_, ok := m.streams[id]
	if ok {
		delete(m.streams, id)
	}
	m.mu.Unlock()
	if ok {
		m.reasmMgr.Unregister(id)
		M.ActiveStreams.Add(-1)
	}
}

func (m *streamMux) closeAll() {
	m.mu.Lock()
	streams := m.streams
	m.streams = make(map[uint32]*stream)
	m.mu.Unlock()
	for _, s := range streams {
		s.Close()
	}
}

func (m *streamMux) Stop() { m.reasmMgr.Stop() }

// ─── tcpWriter ───────────────────────────────────────────────────────────────

type tcpWriter struct {
	ch        chan tcpJob
	done      chan struct{}
	closeOnce sync.Once
}

type tcpJob struct {
	streamID uint32
	msgType  byte
	payload  []byte
	errCh    chan error
}

func newTCPWriter(conn net.Conn) *tcpWriter {
	w := &tcpWriter{ch: make(chan tcpJob, 512), done: make(chan struct{})}
	go w.loop(conn)
	return w
}

func (w *tcpWriter) loop(conn net.Conn) {
	defer close(w.done)
	hdr := make([]byte, proto.TCPHdrSize)
	cw := proto.NewCoalescingWriter(conn)
	defer cw.Close()
	for job := range w.ch {
		proto.EncodeTCPHdr(hdr, job.streamID, job.msgType, len(job.payload))
		err := cw.Write(hdr, job.payload)
		if job.errCh != nil {
			if err == nil {
				err = cw.Flush()
			}
			job.errCh <- err
		}
		if err != nil {
			for job := range w.ch {
				if job.errCh != nil {
					job.errCh <- io.ErrClosedPipe
				}
			}
			return
		}
	}
}

func (w *tcpWriter) write(streamID uint32, msgType byte, payload []byte, sync bool) error {
	var errCh chan error
	if sync {
		errCh = make(chan error, 1)
	}
	job := tcpJob{streamID: streamID, msgType: msgType, payload: payload, errCh: errCh}
	select {
	case w.ch <- job:
	case <-w.done:
		return io.ErrClosedPipe
	default:
		if !sync {
			return nil
		}
		select {
		case w.ch <- job:
		case <-w.done:
			return io.ErrClosedPipe
		}
	}
	if sync {
		select {
		case err := <-errCh:
			return err
		case <-w.done:
			return io.ErrClosedPipe
		}
	}
	return nil
}

func (w *tcpWriter) close() {
	w.closeOnce.Do(func() {
		close(w.ch)
	})
	<-w.done
}

// ─── Main ────────────────────────────────────────────────────────────────────

func main() {
	cfgFile   := flag.String("config", "", "مسیر فایل config")
	genConfig := flag.Bool("gen-config", false, "ساخت config نمونه")
	genKey    := flag.Bool("gen-key", false, "ساخت کلید obfs")

	fServer    := flag.String("server", "", "آدرس سرور")
	fUpProxy   := flag.String("upload-proxy", "", "SOCKS5 آپلود")
	fSocks     := flag.String("local-socks", "", "SOCKS5 listener")
	fDLPort    := flag.Int("download-port", 0, "پورت UDP دانلود")
	fMyIP      := flag.String("my-public-ip", "", "IP عمومی")
	fTransport := flag.String("transport", "", "udp یا obfs")
	fObfsKey   := flag.String("obfs-key", "", "کلید obfs")
	fMaxConn   := flag.Int("max-connections", 0, "حداکثر اتصال")
	fMetrics   := flag.String("metrics-addr", "", "آدرس metrics")
	fVerbose   := flag.Bool("v", false, "verbose")
	flag.Parse()

	if *genKey {
		key := make([]byte, 32)
		cryptoRand.Read(key)
		fmt.Printf("🔑 %x\n", key)
		fmt.Printf("  \"obfs_key\": \"%x\"\n", key)
		os.Exit(0)
	}

	if *genConfig {
		path := "client.json"
		if *cfgFile != "" {
			path = *cfgFile
		}
		cfgpkg.SaveClientExample(path)
		fmt.Printf("✅ %s ساخته شد\n./client --config %s\n", path, path)
		os.Exit(0)
	}

	cfg := cfgpkg.DefaultClient()
	if *cfgFile != "" {
		loaded, err := cfgpkg.LoadClient(*cfgFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		cfg = loaded
	}

	d := cfgpkg.DefaultClient()
	cfgpkg.ApplyString(&cfg.ServerAddr, *fServer, d.ServerAddr)
	cfgpkg.ApplyString(&cfg.UploadProxy, *fUpProxy, d.UploadProxy)
	cfgpkg.ApplyString(&cfg.LocalSocks, *fSocks, d.LocalSocks)
	cfgpkg.ApplyInt(&cfg.DownloadPort, *fDLPort, d.DownloadPort)
	cfgpkg.ApplyString(&cfg.MyPublicIP, *fMyIP, d.MyPublicIP)
	cfgpkg.ApplyString(&cfg.TransportMode, *fTransport, d.TransportMode)
	cfgpkg.ApplyString(&cfg.ObfsKey, *fObfsKey, d.ObfsKey)
	cfgpkg.ApplyInt(&cfg.MaxStreams, *fMaxConn, d.MaxStreams)
	cfgpkg.ApplyString(&cfg.MetricsAddr, *fMetrics, d.MetricsAddr)
	cfgpkg.ApplyBool(&cfg.Verbose, *fVerbose)

	if cfg.ServerAddr == "" {
		fmt.Fprintln(os.Stderr, "❌ --server لازمه")
		os.Exit(1)
	}

	log := makeLogger(cfg.Verbose)
	log.Info("📋 config",
		"server", cfg.ServerAddr,
		"upload_proxy", cfg.UploadProxy,
		"local_socks", cfg.LocalSocks,
		"transport", cfg.TransportMode,
	)

	go func() { M.StartHTTPServer(cfg.MetricsAddr) }()

	// sessionID مشترک
	cryptoRand.Read(globalSessionID[:])

	// IP عمومی
	var realIP net.IP
	if cfg.MyPublicIP != "" {
		realIP = net.ParseIP(cfg.MyPublicIP).To4()
	} else {
		if ipStr, err := cfgpkg.DetectOutboundIP(cfg.ServerAddr); err == nil {
			realIP = net.ParseIP(ipStr).To4()
		}
		if realIP == nil || realIP.IsPrivate() {
			if ipStr, err := cfgpkg.DetectPublicIP(); err == nil {
				realIP = net.ParseIP(ipStr).To4()
			}
		}
		if realIP == nil {
			log.Error("❌ IP تشخیص داده نشد — با --my-public-ip مشخص کن")
			os.Exit(1)
		}
		log.Info("🌐 IP", "ip", realIP)
	}
	udpAddr := &net.UDPAddr{IP: realIP, Port: cfg.DownloadPort}

	// Transport
	var tr transport.Transport
	switch cfg.TransportMode {
	case "obfs":
		key, err := parseObfsKey(cfg.ObfsKey)
		if err != nil {
			log.Error("obfs-key", "err", err)
			os.Exit(1)
		}
		tr, err = transport.NewObfs(cfg.DownloadPort, key)
		if err != nil {
			log.Error("obfs", "err", err)
			os.Exit(1)
		}
		log.Info("⚡ transport: obfs", "port", cfg.DownloadPort)
	default:
		var err error
		tr, err = transport.NewUDP(cfg.DownloadPort)
		if err != nil {
			log.Error("UDP", "err", err)
			os.Exit(1)
		}
		log.Info("⚡ transport: UDP", "port", cfg.DownloadPort)
	}
	defer tr.Close()

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	mux := newMux()
	defer mux.Stop()

	// UDP receiver
	for i := 0; i < 2; i++ {
		go udpReceiver(ctx, tr, mux, log)
	}

	// SOCKS5 dialer — هر connection یه stream مستقل
	var nextID atomic.Uint32
	dialer := func(addrType byte, addr []byte, port uint16) (io.ReadWriteCloser, error) {
		id := nextID.Add(1)

		s := newStream(
			id, ctx,
			cfg.UploadProxy, cfg.ServerAddr, udpAddr,
			mux.reasmMgr,
			addrType, addr, port, log,
		)
		s.closeFn = func() { mux.remove(id) }

		if err := s.dial(); err != nil {
			return nil, fmt.Errorf("dial stream %d: %w", id, err)
		}

		mux.add(s)
		M.ActiveStreams.Add(1)
		M.TotalStreams.Add(1)
		return s, nil
	}

	s5 := socks5.New(cfg.LocalSocks, dialer, cfg.MaxStreams, log)
	go func() {
		if err := s5.Listen(); err != nil && ctx.Err() == nil {
			log.Error("SOCKS5", "err", err)
		}
	}()

	log.Info("✅ کلاینت آماده",
		"socks5", cfg.LocalSocks,
		"download", udpAddr,
		"server", cfg.ServerAddr,
		"transport", cfg.TransportMode,
	)

	go statsLogger(ctx, log)
	<-ctx.Done()
	s5.Close()
	mux.closeAll()
	log.Info("کلاینت خاموش")
}

// ─── UDP receiver ────────────────────────────────────────────────────────────

func udpReceiver(ctx context.Context, tr transport.Transport, mux *streamMux, log *slog.Logger) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		tr.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := tr.Recv(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n < proto.UDPHdrSize {
			continue
		}
		if binary.BigEndian.Uint16(buf[0:2]) != proto.UDPMagic {
			continue
		}
		streamID := uint32(buf[2])<<16 | uint32(buf[3])<<8 | uint32(buf[4])
		seq      := uint32(buf[5])<<16 | uint32(buf[6])<<8 | uint32(buf[7])
		flags    := buf[8]

		M.DownloadPackets.Add(1)
		M.DownloadBytes.Add(uint64(n - proto.UDPHdrSize))

		s, ok := mux.get(streamID)
		if !ok {
			continue
		}
		if flags&proto.FlagClose != 0 {
			s.Close()
			continue
		}
		pay := make([]byte, n-proto.UDPHdrSize)
		copy(pay, buf[proto.UDPHdrSize:n])
		s.rx.Load().Push(seq, flags, pay)
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func dialViaSocks5(proxy, dst string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return nil, err
	}
	port, _ := net.LookupPort("tcp", portStr)
	conn, err := net.DialTimeout("tcp", proxy, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", proxy, err)
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{})
	conn.Write([]byte{5, 1, 0})
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil || resp[1] != 0 {
		conn.Close()
		return nil, errors.New("SOCKS5 auth fail")
	}
	req := buildConnect(host, uint16(port))
	conn.Write(req)
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("CONNECT fail")
	}
	switch hdr[3] {
	case 1:
		io.ReadFull(conn, make([]byte, 6))
	case 4:
		io.ReadFull(conn, make([]byte, 18))
	case 3:
		lb := make([]byte, 1)
		io.ReadFull(conn, lb)
		io.ReadFull(conn, make([]byte, int(lb[0])+2))
	}
	return conn, nil
}

func buildConnect(host string, port uint16) []byte {
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		b := make([]byte, 10)
		b[0], b[1], b[2], b[3] = 5, 1, 0, 1
		copy(b[4:8], ip4)
		b[8], b[9] = byte(port>>8), byte(port)
		return b
	}
	if ip6 := ip.To16(); ip6 != nil {
		b := make([]byte, 22)
		b[0], b[1], b[2], b[3] = 5, 1, 0, 4
		copy(b[4:20], ip6)
		b[20], b[21] = byte(port>>8), byte(port)
		return b
	}
	b := make([]byte, 7+len(host))
	b[0], b[1], b[2], b[3] = 5, 1, 0, 3
	b[4] = byte(len(host))
	copy(b[5:], host)
	b[5+len(host)] = byte(port >> 8)
	b[6+len(host)] = byte(port)
	return b
}

func parseObfsKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		return nil, fmt.Errorf("obfs-key خالی")
	}
	if len(hexKey) != 64 {
		return nil, fmt.Errorf("obfs-key باید 64 کاراکتر باشه")
	}
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b, err := strconv.ParseUint(hexKey[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("hex نامعتبر در %d", i*2)
		}
		key[i] = byte(b)
	}
	return key, nil
}

func statsLogger(ctx context.Context, log *slog.Logger) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s := M.Snapshot()
			log.Info("📊",
				"streams", s.ActiveStreams,
				"up_MB", s.UploadBytes>>20,
				"dn_MB", s.DownloadBytes>>20,
				"reconnects", s.Reconnects,
			)
		}
	}
}

func makeLogger(v bool) *slog.Logger {
	lvl := slog.LevelInfo
	if v {
		lvl = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
