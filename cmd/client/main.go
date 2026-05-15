// کلاینت split-tunnel
//
// اجرا با config:     ./client --config client.json
// اجرا با flag:       ./client --server 1.2.3.4:9000
// ساخت config نمونه: ./client --gen-config
package main

import (
	"context"
	cryptoRand "crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
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

const flowAckUnit = 16 * 1024

// ─── connState ────────────────────────────────────────────────────────────────

type connState struct {
	mu      sync.RWMutex
	writer  *tcpWriter
	version uint64
	waiters []chan struct{}
}

func newConnState() *connState { return &connState{} }

func (c *connState) getWriter() (*tcpWriter, uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.writer, c.version
}

func (c *connState) setConnected(w *tcpWriter) {
	c.mu.Lock()
	c.writer = w
	c.version++
	waiters := c.waiters
	c.waiters = nil
	c.mu.Unlock()
	for _, ch := range waiters {
		close(ch)
	}
}

func (c *connState) setDisconnected() {
	c.mu.Lock()
	c.writer = nil
	c.mu.Unlock()
}

func (c *connState) waitForWriter(ctx context.Context, deadline time.Time) (*tcpWriter, error) {
	for {
		c.mu.Lock()
		if c.writer != nil {
			w := c.writer
			c.mu.Unlock()
			return w, nil
		}
		ch := make(chan struct{})
		c.waiters = append(c.waiters, ch)
		c.mu.Unlock()

		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-ch:
			timer.Stop()
			continue
		case <-timer.C:
			return nil, errors.New("TCP reconnect timeout")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// ─── stream ───────────────────────────────────────────────────────────────────

type stream struct {
	id           uint32
	rx           atomic.Pointer[reasm.Reassembler]
	state        *connState
	addrType     byte
	addr         []byte
	port         uint16
	bytesUnacked atomic.Int64
	closed       atomic.Bool
	once         sync.Once
	closeFn      func()
}

func newStream(id uint32, state *connState, addrType byte, addr []byte, port uint16) *stream {
	s := &stream{
		id:       id,
		state:    state,
		addrType: addrType,
		addr:     append([]byte{}, addr...),
		port:     port,
	}
	s.rx.Store(reasm.New(1))
	return s
}

func (s *stream) replaceRx(mgr *reasm.Manager) {
	old := s.rx.Load()
	newRx := reasm.New(1)
	s.rx.Store(newRx)
	mgr.Register(s.id, newRx)
	old.Close()
}

func (s *stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	w, _ := s.state.getWriter()
	if w == nil {
		return 0, errors.New("TCP temporarily down")
	}
	if err := w.write(s.id, proto.MsgData, p, false); err != nil {
		return 0, err
	}
	M.UploadBytes.Add(uint64(len(p)))
	M.UploadPackets.Add(1)
	return len(p), nil
}

func (s *stream) Read(p []byte) (int, error) {
	for {
		if s.closed.Load() {
			return 0, io.EOF
		}
		select {
		case data, ok := <-s.rx.Load().Chan():
			if !ok {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			n := copy(p, data)
			unacked := s.bytesUnacked.Add(int64(n))
			if unacked >= flowAckUnit {
				toAck := s.bytesUnacked.Swap(0)
				if w, _ := s.state.getWriter(); w != nil {
					w.write(s.id, proto.MsgFlowAck, proto.EncodeFlowAck(uint32(toAck)), false)
					M.FlowAcksSent.Add(1)
				}
			}
			return n, nil
		}
	}
}

func (s *stream) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		if rx := s.rx.Load(); rx != nil {
			rx.Close()
		}
		if w, _ := s.state.getWriter(); w != nil {
			w.write(s.id, proto.MsgClose, nil, false)
		}
		if s.closeFn != nil {
			s.closeFn()
		}
	})
	return nil
}

// ─── streamMux ────────────────────────────────────────────────────────────────

type streamMux struct {
	mu        sync.RWMutex
	streams   map[uint32]*stream
	nextID    atomic.Uint32
	reasmMgr  *reasm.Manager
	state     *connState
	sessionID [proto.SessionIDLen]byte
}

func newMux(state *connState) *streamMux {
	return &streamMux{
		streams:  make(map[uint32]*stream),
		reasmMgr: reasm.NewManager(),
		state:    state,
	}
}

func (m *streamMux) add(s *stream) {
	m.reasmMgr.Register(s.id, s.rx.Load())
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
	for id, s := range m.streams {
		if rx := s.rx.Load(); rx != nil {
			rx.Close()
		}
		m.reasmMgr.Unregister(id)
		M.ActiveStreams.Add(-1)
	}
	m.streams = make(map[uint32]*stream)
	m.mu.Unlock()
}

func (m *streamMux) Stop() { m.reasmMgr.Stop() }

func (m *streamMux) reattach(w *tcpWriter, pending *pendingAcks, log *slog.Logger) {
	m.mu.RLock()
	live := make([]*stream, 0, len(m.streams))
	for _, s := range m.streams {
		if !s.closed.Load() {
			live = append(live, s)
		}
	}
	m.mu.RUnlock()
	if len(live) == 0 {
		return
	}
	log.Info("reattach", "streams", len(live))
	for _, s := range live {
		if s.addrType == 0 {
			continue
		}
		s.replaceRx(m.reasmMgr)
		ackCh := pending.register(s.id)
		if err := w.write(s.id, proto.MsgConnect,
			proto.EncodeConnect(proto.ConnectPayload{
				AddrType: s.addrType, Addr: s.addr, Port: s.port,
			}), false,
		); err != nil {
			pending.resolve(s.id, err)
			s.Close()
			continue
		}
		go func(st *stream, ch chan error) {
			select {
			case err := <-ch:
				if err != nil {
					st.Close()
				}
			case <-time.After(15 * time.Second):
				pending.resolve(st.id, errors.New("timeout"))
				st.Close()
			}
		}(s, ackCh)
	}
}

// ─── tcpWriter ────────────────────────────────────────────────────────────────

type tcpWriter struct {
	ch   chan tcpJob
	done chan struct{}
}

type tcpJob struct {
	streamID uint32
	msgType  byte
	payload  []byte
	errCh    chan error
}

func newTCPWriter(conn net.Conn) *tcpWriter {
	w := &tcpWriter{ch: make(chan tcpJob, 2048), done: make(chan struct{})}
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
			M.WriteErrors.Add(1)
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
			M.WriteErrors.Add(1)
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
	close(w.ch)
	<-w.done
}

// ─── pendingAcks ──────────────────────────────────────────────────────────────

type pendingAcks struct {
	mu sync.Mutex
	m  map[uint32]chan error
}

func newPending() *pendingAcks { return &pendingAcks{m: make(map[uint32]chan error)} }

func (p *pendingAcks) register(id uint32) chan error {
	ch := make(chan error, 1)
	p.mu.Lock()
	if old, ok := p.m[id]; ok {
		select {
		case old <- errors.New("replaced"):
		default:
		}
	}
	p.m[id] = ch
	p.mu.Unlock()
	return ch
}

func (p *pendingAcks) resolve(id uint32, err error) {
	p.mu.Lock()
	ch, ok := p.m[id]
	if ok {
		delete(p.m, id)
	}
	p.mu.Unlock()
	if ok {
		select {
		case ch <- err:
		default:
		}
	}
}

func (p *pendingAcks) abortAll(err error) {
	p.mu.Lock()
	all := p.m
	p.m = make(map[uint32]chan error)
	p.mu.Unlock()
	for _, ch := range all {
		select {
		case ch <- err:
		default:
		}
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	cfgFile    := flag.String("config", "", "مسیر فایل config (مثال: client.json)")
	genConfig  := flag.Bool("gen-config", false, "ساخت فایل config نمونه")
	genKey     := flag.Bool("gen-key", false, "ساخت کلید obfs تصادفی و نمایش")

	// flag‌ها — default خالی تا بشه تشخیص داد کاربر زده یا نه
	fServer    := flag.String("server", "", "آدرس سرور تونل (IP:port)")
	fUpProxy   := flag.String("upload-proxy", "", "SOCKS5 آپلود — xray/v2ray/sing-box/... (پیش‌فرض: 127.0.0.1:10808)")
	fSocks     := flag.String("local-socks", "", "SOCKS5 که مرورگر به اون وصل میشه (پیش‌فرض: 127.0.0.1:1080)")
	fDLPort    := flag.Int("download-port", 0, "پورت UDP دریافت دانلود (پیش‌فرض: 8000)")
	fMyIP      := flag.String("my-public-ip", "", "IP عمومی کلاینت — خودکار تشخیص داده میشه اگه خالی باشه")
	fTransport := flag.String("transport", "", "نوع transport: udp یا obfs (پیش‌فرض: udp)")
	fObfsKey   := flag.String("obfs-key", "", "کلید obfuscation (hex 64 کاراکتر) — فقط در حالت obfs")
	fMaxConn   := flag.Int("max-connections", 0, "حداکثر اتصال همزمان (پیش‌فرض: 512)")
	fMetrics   := flag.String("metrics-addr", "", "آدرس HTTP متریک‌ها (پیش‌فرض: 127.0.0.1:9091)")
	fVerbose   := flag.Bool("v", false, "لاگ verbose")
	flag.Parse()

	// gen-key
	if *genKey {
		key := make([]byte, 32)
		if _, err := cryptoRand.Read(key); err != nil {
			fmt.Fprintf(os.Stderr, "خطا در تولید کلید: %v\n", err)
			os.Exit(1)
		}
		hexKey := fmt.Sprintf("%x", key)
		fmt.Println("🔑 کلید obfs جدید (۳۲ بایت تصادفی):")
		fmt.Println()
		fmt.Println(hexKey)
		fmt.Println()
		fmt.Println("📋 در client.json:")
		fmt.Printf("  \"obfs_key\": \"%s\"\n", hexKey)
		fmt.Println()
		fmt.Println("📋 در server.json:")
		fmt.Printf("  \"obfs_key\": \"%s\"\n", hexKey)
		fmt.Println()
		fmt.Println("⚠  این کلید رو در جای امن نگه دار — هم کلاینت هم سرور باید یکی داشته باشن")
		os.Exit(0)
	}

	// gen-config
	if *genConfig {
		path := "client.json"
		if *cfgFile != "" {
			path = *cfgFile
		}
		if err := cfgpkg.SaveClientExample(path); err != nil {
			fmt.Fprintf(os.Stderr, "خطا: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ فایل config نمونه ساخته شد: %s\n", path)
		fmt.Println("📝 فایل رو ویرایش کن و اجرا کن:")
		fmt.Printf("   ./client --config %s\n", path)
		os.Exit(0)
	}

	// بارگذاری config
	cfg := cfgpkg.DefaultClient()
	if *cfgFile != "" {
		loaded, err := cfgpkg.LoadClient(*cfgFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "خطا در config: %v\n", err)
			os.Exit(1)
		}
		cfg = loaded
	}

	// flag‌ها override میکنن
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
		fmt.Fprintln(os.Stderr, "❌ آدرس سرور لازمه: --server IP:PORT")
		fmt.Fprintln(os.Stderr, "💡 یا ابتدا config بساز: ./client --gen-config")
		os.Exit(1)
	}

	log := makeLogger(cfg.Verbose)

	// نمایش config فعال
	log.Info("📋 config فعال",
		"server", cfg.ServerAddr,
		"upload_proxy", cfg.UploadProxy,
		"local_socks", cfg.LocalSocks,
		"download_port", cfg.DownloadPort,
		"transport", cfg.TransportMode,
	)

	// metrics
	go func() {
		if err := M.StartHTTPServer(cfg.MetricsAddr); err != nil {
			log.Warn("metrics", "err", err)
		}
	}()

	// ── IP عمومی کلاینت (auto-detect) ────────────────────────────────────────
	var realIP net.IP
	if cfg.MyPublicIP != "" {
		realIP = net.ParseIP(cfg.MyPublicIP).To4()
		if realIP == nil {
			log.Error("my-public-ip نامعتبر", "val", cfg.MyPublicIP)
			os.Exit(1)
		}
		log.Info("🌐 IP عمومی از config", "ip", realIP)
	} else {
		log.Info("🔍 تشخیص خودکار IP عمومی...")
		// اول سعی کن از outbound interface بگیر (سریع‌تر)
		if ipStr, err := cfgpkg.DetectOutboundIP(cfg.ServerAddr); err == nil {
			realIP = net.ParseIP(ipStr).To4()
			log.Info("🌐 IP خروجی تشخیص داده شد", "ip", realIP)
		}
		// اگه private بود، از اینترنت بگیر
		if realIP == nil || realIP.IsPrivate() {
			if ipStr, err := cfgpkg.DetectPublicIP(); err == nil {
				realIP = net.ParseIP(ipStr).To4()
				log.Info("🌐 IP عمومی از اینترنت تشخیص داده شد", "ip", realIP)
			} else {
				log.Warn("⚠ تشخیص IP عمومی ناموفق — از IP خروجی استفاده میشه", "err", err)
				if ipStr2, err2 := cfgpkg.DetectOutboundIP(cfg.ServerAddr); err2 == nil {
					realIP = net.ParseIP(ipStr2).To4()
				}
			}
		}
		if realIP == nil {
			log.Error("❌ IP کلاینت تشخیص داده نشد — با --my-public-ip مشخص کن")
			os.Exit(1)
		}
	}
	udpAddr := &net.UDPAddr{IP: realIP, Port: cfg.DownloadPort}
	log.Info("📥 دانلود UDP", "addr", udpAddr)

	// ── Transport ─────────────────────────────────────────────────────────────
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
			log.Error("obfs transport", "err", err)
			os.Exit(1)
		}
		log.Info("⚡ transport: obfs (QUIC-like)", "port", cfg.DownloadPort)
	default:
		var err error
		tr, err = transport.NewUDP(cfg.DownloadPort)
		if err != nil {
			log.Error("UDP transport", "err", err)
			os.Exit(1)
		}
		log.Info("⚡ transport: UDP ساده", "port", cfg.DownloadPort)
	}
	defer tr.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	state := newConnState()
	mux := newMux(state)
	defer mux.Stop()
	cryptoRand.Read(mux.sessionID[:])

	pending := newPending()

	for i := 0; i < 2; i++ {
		go udpReceiver(ctx, tr, mux, log)
	}

	ready := make(chan struct{})
	go tcpManager(ctx, cfg.UploadProxy, cfg.ServerAddr, udpAddr,
		mux, pending, state, ready, log)

	select {
	case <-ready:
	case <-ctx.Done():
		return
	}

	dialer := func(addrType byte, addr []byte, port uint16) (io.ReadWriteCloser, error) {
		w, _ := state.getWriter()
		if w == nil {
			var err error
			w, err = state.waitForWriter(ctx, time.Now().Add(30*time.Second))
			if err != nil {
				return nil, fmt.Errorf("TCP در دسترس نیست: %w", err)
			}
		}
		id := mux.nextID.Add(1)
		ackCh := pending.register(id)
		if err := w.write(id, proto.MsgConnect,
			proto.EncodeConnect(proto.ConnectPayload{AddrType: addrType, Addr: addr, Port: port}),
			true,
		); err != nil {
			pending.resolve(id, err)
			return nil, err
		}
		select {
		case err := <-ackCh:
			if err != nil {
				return nil, err
			}
		case <-time.After(15 * time.Second):
			pending.resolve(id, nil)
			return nil, errors.New("ConnAck timeout")
		case <-ctx.Done():
			pending.resolve(id, ctx.Err())
			return nil, ctx.Err()
		}
		s := newStream(id, state, addrType, addr, port)
		s.closeFn = func() { mux.remove(id) }
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
		"local_socks", cfg.LocalSocks,
		"download_port", cfg.DownloadPort,
		"upload_proxy", cfg.UploadProxy,
		"server", cfg.ServerAddr,
		"my_ip", realIP,
		"transport", cfg.TransportMode,
		"metrics", cfg.MetricsAddr,
	)

	go statsLogger(ctx, log)
	<-ctx.Done()
	s5.Close()
	mux.closeAll()
	log.Info("کلاینت خاموش")
}

// ─── TCP Manager ──────────────────────────────────────────────────────────────

func tcpManager(
	ctx context.Context,
	uploadProxy, server string,
	udpAddr *net.UDPAddr,
	mux *streamMux,
	pending *pendingAcks,
	state *connState,
	ready chan struct{},
	log *slog.Logger,
) {
	var readyOnce sync.Once
	backoff := 500 * time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		log.Info("🔌 اتصال TCP به سرور...")
		conn, err := dialViaSocks5(uploadProxy, server)
		if err != nil {
			log.Warn("اتصال ناموفق", "err", err, "retry_in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
				backoff = minDur(backoff*2, 30*time.Second)
				continue
			}
		}
		backoff = 500 * time.Millisecond
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(15 * time.Second)
			tc.SetReadBuffer(2 * 1024 * 1024)
			tc.SetWriteBuffer(2 * 1024 * 1024)
		}
		writer := newTCPWriter(conn)
		if err := writer.write(0, proto.MsgHello,
			proto.EncodeHello(mux.sessionID, udpAddr.IP, uint16(udpAddr.Port)), true,
		); err != nil {
			writer.close()
			conn.Close()
			time.Sleep(backoff)
			continue
		}
		state.setConnected(writer)
		log.Info("🟢 TCP متصل")
		readyOnce.Do(func() { close(ready) })
		go mux.reattach(writer, pending, log)
		tcpReader(ctx, conn, mux, pending, writer, log)
		state.setDisconnected()
		writer.close()
		conn.Close()
		pending.abortAll(errors.New("TCP قطع"))
		log.Warn("🔴 TCP قطع — reconnect میکنیم")
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func tcpReader(ctx context.Context, conn net.Conn, mux *streamMux,
	pending *pendingAcks, writer *tcpWriter, log *slog.Logger) {
	for {
		f, err := proto.ReadTCPFrame(conn)
		if err != nil {
			if ctx.Err() == nil {
				log.Debug("TCP read end", "err", err)
			}
			return
		}
		switch f.Type {
		case proto.MsgConnAck:
			pending.resolve(f.StreamID, nil)
		case proto.MsgConnErr:
			pending.resolve(f.StreamID, errors.New("مقصد قابل دسترس نیست"))
		case proto.MsgClose:
			mux.remove(f.StreamID)
		case proto.MsgPing:
			writer.write(0, proto.MsgPong, nil, false)
		}
	}
}

// ─── UDP receiver ─────────────────────────────────────────────────────────────

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
		hdr, pstart, err := proto.DecodeUDPHdr(buf[:n])
		if err != nil {
			log.Debug("UDP decode error", "err", err, "bytes", n, "first", fmt.Sprintf("%02x", buf[:min(4,n)]))
			continue
		}
		M.DownloadPackets.Add(1)
		M.DownloadBytes.Add(uint64(n - pstart))
		log.Debug("UDP recv", "sid", hdr.StreamID, "seq", hdr.Seq, "flags", hdr.Flags, "payload", n-pstart)
		if hdr.Flags&proto.FlagClose != 0 {
			mux.remove(hdr.StreamID)
			continue
		}
		s, ok := mux.get(hdr.StreamID)
		if !ok {
			log.Debug("UDP unknown stream", "sid", hdr.StreamID)
			continue
		}
		pay := make([]byte, n-pstart)
		copy(pay, buf[pstart:n])
		s.rx.Load().Push(hdr.Seq, hdr.Flags, pay)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
		return nil, errors.New("proxy auth fail")
	}
	req := buildConnect(host, uint16(port))
	conn.Write(req)
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("CONNECT رد شد")
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
		return nil, fmt.Errorf("obfs-key خالی است")
	}
	if len(hexKey) != 64 {
		return nil, fmt.Errorf("obfs-key باید 64 کاراکتر hex باشه، داده شده: %d", len(hexKey))
	}
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hi, lo := hexVal(hexKey[i*2]), hexVal(hexKey[i*2+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("hex نامعتبر در موقعیت %d", i*2)
		}
		key[i] = byte(hi<<4) | byte(lo)
	}
	return key, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
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
			log.Info("📊 stats",
				"streams", s.ActiveStreams,
				"up_MB", s.UploadBytes>>20,
				"dn_MB", s.DownloadBytes>>20,
				"drops", s.ReassemblyDrops,
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

func min(a, b int) int {
	if a < b { return a }
	return b
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
