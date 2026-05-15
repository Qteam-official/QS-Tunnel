package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sttunnel/internal/config"
	cfgpkg "github.com/sttunnel/internal/config"
	"github.com/sttunnel/internal/limit"
	"github.com/sttunnel/internal/metrics"
	"github.com/sttunnel/internal/pool"
	"github.com/sttunnel/internal/proto"
	"github.com/sttunnel/internal/sendpool"
	"github.com/sttunnel/internal/session"
	"github.com/sttunnel/internal/spoof"
	"github.com/sttunnel/internal/transport"
)

// ─── Globals ──────────────────────────────────────────────────────────────────

var (
	M       = metrics.New() // global metrics
	idleDur = 2 * time.Minute
)

// ─── Per-stream state ─────────────────────────────────────────────────────────

type stream struct {
	id       uint32
	conn     net.Conn      // TCP به مقصد
	seq      atomic.Uint32 // sequence number دانلود
	flow     *session.FlowState
	lastUsed atomic.Int64 // unix nano
	closed   atomic.Bool
	once     sync.Once
}

func (s *stream) touch() {
	s.lastUsed.Store(time.Now().UnixNano())
}

func (s *stream) Close() {
	s.once.Do(func() {
		s.closed.Store(true)
		s.flow.Close()
		s.conn.Close()
	})
}

// ─── Per-client state ─────────────────────────────────────────────────────────

type client struct {
	tcpConn net.Conn
	udpDst  *net.UDPAddr
	streams sync.Map // streamID → *stream
	writer  *tcpWriter
	sender  *sendpool.Pool
	tcpDial func(string) (net.Conn, error)

	log    *slog.Logger
	closed atomic.Bool
}

// tcpWriter یه TCP writer thread-safe که از channel استفاده میکنه
type tcpWriter struct {
	ch     chan tcpJob
	done   chan struct{}
	closed atomic.Bool
}

type tcpJob struct {
	streamID uint32
	msgType  byte
	payload  []byte
	errCh    chan error // nil برای async
}

func newTCPWriter(conn net.Conn) *tcpWriter {
	w := &tcpWriter{
		ch:   make(chan tcpJob, 1024),
		done: make(chan struct{}),
	}
	go w.loop(conn)
	return w
}

func (w *tcpWriter) loop(conn net.Conn) {
	defer close(w.done)
	bp := pool.Small.Get()
	defer pool.Small.Put(bp)
	hdr := (*bp)[:proto.TCPHdrSize]

	for job := range w.ch {
		proto.EncodeTCPHdr(hdr, job.streamID, job.msgType, len(job.payload))
		_, err := conn.Write(hdr)
		if err == nil && len(job.payload) > 0 {
			_, err = conn.Write(job.payload)
		}
		if job.errCh != nil {
			job.errCh <- err
		}
		if err != nil {
			M.WriteErrors.Add(1)
			// drain remaining
			for range w.ch {
			}
			return
		}
	}
}

func (w *tcpWriter) write(streamID uint32, msgType byte, payload []byte, sync bool) error {
	if w.closed.Load() {
		return io.ErrClosedPipe
	}
	if sync {
		errCh := make(chan error, 1)
		select {
		case w.ch <- tcpJob{streamID, msgType, payload, errCh}:
		case <-w.done:
			return io.ErrClosedPipe
		}
		return <-errCh
	}
	select {
	case w.ch <- tcpJob{streamID, msgType, payload, nil}:
		return nil
	case <-w.done:
		return io.ErrClosedPipe
	default:
		// queue پر — drop این job (فقط این stream، نه بقیه)
		M.WriteErrors.Add(1)
		return fmt.Errorf("write queue full")
	}
}

func (w *tcpWriter) close() {
	if w.closed.CompareAndSwap(false, true) {
		close(w.ch)
		<-w.done
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	// ── Config file (اختیاری) ─────────────────────────────────────────────────
	configFile := flag.String("config", "", "مسیر فایل config.json (اختیاری)")
	genConfig := flag.Bool("gen-config", false, "ساخت فایل config.json نمونه و خروج")

	// ── Flags (هر flag که داده بشه، config رو override میکنه) ──────────────
	fListen := flag.String("listen", "", "TCP listen (مثال: 0.0.0.0:9000)")
	fUDPSrcPort := flag.Int("udp-src-port", 0, "پورت UDP خروجی")
	fTransportMode := flag.String("transport", "", "udp یا obfs")
	fObfsKey := flag.String("obfs-key", "", "کلید obfuscation (hex 64 کاراکتر)")
	fSpoofSrc := flag.String("spoof-src", "", "IP مبدا جعلی")
	fSpoofIface := flag.String("spoof-iface", "", "interface spoof")
	fSpoofGW := flag.String("spoof-gw", "", "gateway IP")
	fBindSrc := flag.String("bind-src", "", "IP مبدا TCP خروجی")
	fMaxClients := flag.Int("max-clients", 0, "حداکثر کلاینت")
	fMaxStreamsPC := flag.Int("max-streams-per-client", 0, "حداکثر stream هر کلاینت")
	fFlowLimit := flag.Int64("flow-limit", 0, "backpressure window bytes")
	fSendWorkers := flag.Int("send-workers", 0, "تعداد worker UDP")
	fMetricsAddr := flag.String("metrics", "", "آدرس metrics HTTP")
	fDialTimeout := flag.Int("dial-timeout-sec", 0, "timeout dial (ثانیه)")
	fIdleTimeout := flag.Int("idle-timeout-sec", 0, "idle timeout (ثانیه)")
	fVerbose := flag.Bool("v", false, "verbose")
	flag.Parse()

	// ── gen-config ────────────────────────────────────────────────────────────
	if *genConfig {
		path := "server.json"
		if *configFile != "" {
			path = *configFile
		}
		if err := cfgpkg.SaveServerExample(path); err != nil {
			fmt.Fprintf(os.Stderr, "خطا: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ فایل config نمونه ساخته شد: %s\n", path)
		os.Exit(0)
	}

	// ── بارگذاری config + اعمال flag‌ها ────────────────────────────────────────
	cfg, err := config.LoadServer(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "خطا در بارگذاری config: %v\n", err)
		os.Exit(1)
	}

	// اعمال flag‌هایی که داده شدن (override config)
	if *fListen != "" {
		cfg.ListenAddr = *fListen
	}
	if *fUDPSrcPort != 0 {
		cfg.DownloadSrcPort = *fUDPSrcPort
	}
	if *fTransportMode != "" {
		cfg.TransportMode = *fTransportMode
	}
	if *fObfsKey != "" {
		cfg.ObfsKey = *fObfsKey
	}
	if *fSpoofSrc != "" {
		cfg.SpoofIP = *fSpoofSrc
	}
	if *fSpoofIface != "" {
		cfg.SpoofInterface = *fSpoofIface
	}
	if *fSpoofGW != "" {
		cfg.SpoofGateway = *fSpoofGW
	}
	if *fBindSrc != "" {
		cfg.OutboundBindIP = *fBindSrc
	}
	if *fMaxClients != 0 {
		cfg.MaxClients = *fMaxClients
	}
	if *fMaxStreamsPC != 0 {
		cfg.MaxStreamsPerClient = *fMaxStreamsPC
	}
	if *fFlowLimit != 0 {
		cfg.FlowWindowBytes = *fFlowLimit
	}
	if *fSendWorkers != 0 {
		cfg.UDPWorkers = *fSendWorkers
	}
	if *fMetricsAddr != "" {
		cfg.MetricsAddr = *fMetricsAddr
	}
	if *fDialTimeout != 0 {
		cfg.DialTimeoutSec = *fDialTimeout
	}
	if *fIdleTimeout != 0 {
		cfg.IdleTimeoutSec = *fIdleTimeout
	}
	if *fVerbose {
		cfg.Verbose = true
	}

	// alias به اسم‌های قدیمی برای بقیه کد
	tcpListen := &cfg.ListenAddr
	udpSrcPort := &cfg.DownloadSrcPort
	transportMode := &cfg.TransportMode
	obfsKey := &cfg.ObfsKey
	spoofSrc := &cfg.SpoofIP
	spoofIface := &cfg.SpoofInterface
	spoofGW := &cfg.SpoofGateway
	bindSrc := &cfg.OutboundBindIP
	maxClients := &cfg.MaxClients
	maxStreamsPC := &cfg.MaxStreamsPerClient
	flowLimit := &cfg.FlowWindowBytes
	sendWorkers := &cfg.UDPWorkers
	metricsAddr := &cfg.MetricsAddr
	dialTimeout := time.Duration(cfg.DialTimeoutSec) * time.Second
	idleTimeout := time.Duration(cfg.IdleTimeoutSec) * time.Second
	verbose := &cfg.Verbose
	_ = verbose

	idleDur = idleTimeout
	log := makeLogger(cfg.Verbose)

	// metrics server
	go func() {
		if err := M.StartHTTPServer(*metricsAddr); err != nil {
			log.Warn("metrics server", "err", err)
		}
	}()
	log.Info("metrics endpoint", "url", "http://"+*metricsAddr+"/metrics")

	if *sendWorkers <= 0 {
		*sendWorkers = runtime.NumCPU()
	}

	// ── Transport ────────────────────────────────────────────────────────────
	// ── resolve gateway و interface یه بار برای همه ──────────────────────────
	var resolvedGW string
	var resolvedIface string
	if *spoofSrc != "" {
		resolvedGW = *spoofGW
		if resolvedGW == "" {
			var err error
			resolvedGW, err = spoof.DefaultGateway()
			if err != nil {
				log.Error("gateway پیدا نشد", "err", err)
				os.Exit(1)
			}
			log.Info("🔍 gateway خودکار", "gw", resolvedGW)
		}
		resolvedIface = *spoofIface
		if resolvedIface == "" {
			var err error
			resolvedIface, err = cfgpkg.DetectDefaultInterface()
			if err != nil {
				log.Error("interface خودکار تشخیص داده نشد",
					"err", err,
					"fix", "spoof_interface رو در server.json یا --spoof-interface مشخص کن (مثلاً: eth0، ens3، enp3s0)")
				// نمایش همه interface های موجود
				ifaces, ierr := net.Interfaces()
				if ierr == nil {
					for _, i := range ifaces {
						if i.Flags&net.FlagLoopback != 0 {
							continue
						}
						addrs, _ := i.Addrs()
						log.Info("🔌 interface موجود", "name", i.Name, "flags", i.Flags, "addrs", addrs)
					}
				}
				os.Exit(1)
			}
			log.Info("🔍 interface خودکار", "iface", resolvedIface)
		}
	}

	// ── ساخت transport بر اساس ترکیب mode + spoof ─────────────────────────
	//
	//  mode=udp  + spoof=off → UDPTransport          (ساده)
	//  mode=udp  + spoof=on  → UDPWithSpoof           (UDP + AF_PACKET)
	//
	var tr transport.Transport
	switch *transportMode {
	case "obfs":
		key, err := parseObfsKey(*obfsKey)
		if err != nil {
			log.Error("obfs-key نامعتبر", "err", err)
			os.Exit(1)
		}
		if *spoofSrc != "" {
			// obfs + spoof: هم encrypt هم AF_PACKET
			tr, err = transport.NewObfsSpoof(
				*udpSrcPort,
				key,
				resolvedIface,
				net.ParseIP(resolvedGW),
				net.ParseIP(*spoofSrc).To4(),
				uint16(*udpSrcPort),
			)
			if err != nil {
				log.Error("obfs+spoof transport", "err", err)
				os.Exit(1)
			}
			log.Warn("⚡ transport: obfs + IP spoof",
				"mode", "AES-256-GCM + AF_PACKET",
				"spoof_ip", *spoofSrc,
				"iface", resolvedIface,
				"gw", resolvedGW,
				"port", *udpSrcPort,
			)
		} else {
			// obfs بدون spoof
			tr, err = transport.NewObfs(*udpSrcPort, key)
			if err != nil {
				log.Error("obfs transport", "err", err)
				os.Exit(1)
			}
			log.Info("⚡ transport: obfs (QUIC-like AES-256-GCM)", "port", *udpSrcPort)
		}
	default: // "udp"
		if *spoofSrc != "" {
			// UDP + spoof
			udpTr, err := transport.NewUDPWithSpoof(
				*udpSrcPort,
				resolvedIface,
				net.ParseIP(resolvedGW),
				net.ParseIP(*spoofSrc).To4(),
				uint16(*udpSrcPort),
			)
			if err != nil {
				log.Error("UDP+spoof transport", "err", err)
				os.Exit(1)
			}
			tr = udpTr
			log.Warn("⚡ transport: UDP + IP spoof",
				"spoof_ip", *spoofSrc,
				"iface", resolvedIface,
				"gw", resolvedGW,
				"port", *udpSrcPort,
			)
		} else {
			// UDP ساده
			var err error
			tr, err = transport.NewUDP(*udpSrcPort)
			if err != nil {
				log.Error("UDP transport", "err", err)
				os.Exit(1)
			}
			log.Info("⚡ transport: UDP ساده", "port", *udpSrcPort)
		}
	}
	defer tr.Close()

	// ── Send pool ─────────────────────────────────────────────────────────────
	sender, err := sendpool.New(sendpool.Config{
		Workers:   *sendWorkers,
		QueueSize: 8192,
		Transport: tr,
	})
	if err != nil {
		log.Error("send pool", "err", err)
		os.Exit(1)
	}
	defer sender.Close()
	log.Info("send pool", "workers", *sendWorkers)

	// ── Client connection limit ───────────────────────────────────────────────
	clientLimit := limit.NewConnCounter(*maxClients)

	// ── TCP dialer ────────────────────────────────────────────────────────────
	tcpDial := makeTCPDialer(*bindSrc, dialTimeout)

	// ── TCP listener ──────────────────────────────────────────────────────────
	ln, err := net.Listen("tcp", *tcpListen)
	if err != nil {
		log.Error("TCP listen", "err", err)
		os.Exit(1)
	}
	defer ln.Close()

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Info("▶ سرور آماده",
		"tcp", *tcpListen,
		"udp", *udpSrcPort,
		"max_clients", *maxClients,
		"flow_limit_kb", *flowLimit/1024,
	)

	// shutdown
	go func() { <-ctx.Done(); ln.Close() }()

	// stats logger
	go statsLogger(ctx, log)

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}

		if !clientLimit.Acquire() {
			log.Warn("کلاینت rejected — limit پر", "current", clientLimit.Count())
			conn.Close()
			continue
		}

		// TCP optimizations
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(20 * time.Second)
			tc.SetReadBuffer(2 * 1024 * 1024)
			tc.SetWriteBuffer(2 * 1024 * 1024)
		}

		M.ActiveClients.Add(1)
		M.TotalConnections.Add(1)

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer M.ActiveClients.Add(-1)
			defer clientLimit.Release()
			handleClient(ctx, c, sender, tcpDial, *maxStreamsPC, *flowLimit, log)
		}(conn)
	}
	wg.Wait()
	log.Info("سرور خاموش شد")
}

// ─── Handle one client ────────────────────────────────────────────────────────

func handleClient(
	ctx context.Context,
	conn net.Conn,
	sender *sendpool.Pool,
	tcpDial func(string) (net.Conn, error),
	maxStreams int,
	flowLimit int64,
	log *slog.Logger,
) {
	defer conn.Close()

	// Hello رو بخون
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	f, err := proto.ReadTCPFrame(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil || f.Type != proto.MsgHello || f.StreamID != 0 {
		log.Debug("Hello expected", "err", err)
		return
	}
	_, ip, port, err := proto.DecodeHello(f.Payload)
	if err != nil {
		return
	}
	udpDst := &net.UDPAddr{IP: ip, Port: int(port)}
	log.Info("کلاینت متصل", "udp_dst", udpDst, "remote", conn.RemoteAddr())

	streamLim := limit.NewConnCounter(maxStreams)

	c := &client{
		tcpConn: conn,
		udpDst:  udpDst,
		writer:  newTCPWriter(conn),
		sender:  sender,
		tcpDial: tcpDial,
		log:     log,
	}
	defer c.writer.close()

	// idle stream cleanup worker
	idleCtx, idleCancel := context.WithCancel(ctx)
	defer idleCancel()
	go c.idleSweeper(idleCtx)

	// read loop
	for {
		f, err := proto.ReadTCPFrame(conn)
		if err != nil {
			log.Debug("client read", "err", err)
			break
		}

		switch f.Type {
		case proto.MsgConnect:
			if !streamLim.Acquire() {
				c.writer.write(f.StreamID, proto.MsgConnErr, nil, false)
				continue
			}
			go func(sid uint32, payload []byte) {
				defer streamLim.Release()
				c.openStream(sid, payload, flowLimit)
			}(f.StreamID, f.Payload)

		case proto.MsgData:
			if v, ok := c.streams.Load(f.StreamID); ok {
				s := v.(*stream)
				M.UploadBytes.Add(uint64(len(f.Payload)))
				M.UploadPackets.Add(1)
				if _, err := s.conn.Write(f.Payload); err != nil {
					s.Close()
					c.streams.Delete(f.StreamID)
				}
				s.touch()
			}

		case proto.MsgClose:
			if v, ok := c.streams.LoadAndDelete(f.StreamID); ok {
				v.(*stream).Close()
			}

		case proto.MsgFlowAck:
			n, err := proto.DecodeFlowAck(f.Payload)
			if err == nil {
				if v, ok := c.streams.Load(f.StreamID); ok {
					s := v.(*stream)
					s.flow.Release(int(n))
					M.FlowAcksReceived.Add(1)
				}
			}

		case proto.MsgPing:
			c.writer.write(f.StreamID, proto.MsgPong, nil, false)
		}
	}

	// cleanup
	c.closed.Store(true)
	c.streams.Range(func(k, v any) bool {
		s := v.(*stream)
		s.Close()
		c.streams.Delete(k)
		M.ActiveStreams.Add(-1)
		return true
	})
	log.Info("کلاینت قطع", "udp_dst", udpDst)
}

// ─── Open a new stream ────────────────────────────────────────────────────────

func (c *client) openStream(sid uint32, payload []byte, flowLimit int64) {
	req, err := proto.DecodeConnect(payload)
	if err != nil {
		c.writer.write(sid, proto.MsgConnErr, nil, false)
		return
	}
	dst := req.HostPort()

	conn, err := c.tcpDial(dst)
	if err != nil {
		M.DialErrors.Add(1)
		c.writer.write(sid, proto.MsgConnErr, nil, false)
		return
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetReadBuffer(1 * 1024 * 1024)
	}

	s := &stream{
		id:   sid,
		conn: conn,
		flow: session.NewFlow(flowLimit),
	}
	s.touch()
	c.streams.Store(sid, s)
	M.ActiveStreams.Add(1)
	M.TotalStreams.Add(1)

	// ConnAck
	if err := c.writer.write(sid, proto.MsgConnAck, nil, true); err != nil {
		c.cleanupStream(sid, s)
		return
	}

	// شروع دانلود
	go c.downloadLoop(sid, s)
}

// ─── Download loop with flow control ──────────────────────────────────────────

func (c *client) downloadLoop(sid uint32, s *stream) {
	defer c.cleanupStream(sid, s)

	bp := pool.UDPPayload.Get()
	defer pool.UDPPayload.Put(bp)
	// payload buffer (طول دقیقاً maxPayload)
	pbuf := (*bp)[:proto.MaxPayload]

	for {
		n, err := s.conn.Read(pbuf)
		if n > 0 {
			// flow control: صبر کن تا backpressure اجازه بده
			if !s.flow.Acquire(n) {
				return // session closed
			}

			seq := s.seq.Add(1)
			var flags byte
			if err != nil {
				flags |= proto.FlagLast
			}

			// frame کامل UDP رو بساز
			ubp := pool.UDPPayload.Get()
			ubuf := (*ubp)[:proto.UDPHdrSize+n]
			proto.EncodeUDP(ubuf, sid, seq, flags, pbuf[:n])

			// به send pool بفرست — channel pure non-blocking
			c.sender.Send(sendpool.Packet{
				StreamID: sid,
				Data:     ubuf,
				Dst:      c.udpDst,
			})
			// نکته: send pool خودش buffer رو نگه میداره تا send بشه
			// نمیتونیم اینجا Put کنیم — leak جزئی، ولی pool خودکار size رو manage میکنه

			M.DownloadBytes.Add(uint64(n))
			M.DownloadPackets.Add(1)
			s.touch()
		}

		if err != nil {
			if err != io.EOF {
				c.log.Debug("read مقصد", "sid", sid, "err", err)
			}
			return
		}
	}
}

func (c *client) cleanupStream(sid uint32, s *stream) {
	if c.streams.CompareAndDelete(sid, s) {
		M.ActiveStreams.Add(-1)
	}
	s.Close()

	// send FlagClose به کلاینت
	bp := pool.UDPPayload.Get()
	defer pool.UDPPayload.Put(bp)
	buf := (*bp)[:proto.UDPHdrSize]
	proto.EncodeUDP(buf, sid, s.seq.Add(1), proto.FlagClose, nil)
	c.sender.Send(sendpool.Packet{
		StreamID: sid,
		Data:     buf,
		Dst:      c.udpDst,
	})
}

// ─── Idle sweeper ─────────────────────────────────────────────────────────────

func (c *client) idleSweeper(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			now := time.Now().UnixNano()
			threshold := int64(idleDur)
			c.streams.Range(func(k, v any) bool {
				s := v.(*stream)
				if now-s.lastUsed.Load() > threshold {
					c.cleanupStream(s.id, s)
				}
				return true
			})
		}
	}
}

// ─── Stats logger ─────────────────────────────────────────────────────────────

func statsLogger(ctx context.Context, log *slog.Logger) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s := M.Snapshot()
			log.Info("stats",
				"clients", s.ActiveClients,
				"streams", s.ActiveStreams,
				"up_MB", s.UploadBytes>>20,
				"dn_MB", s.DownloadBytes>>20,
				"dial_err", s.DialErrors,
				"write_err", s.WriteErrors,
			)
		}
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func makeTCPDialer(bindSrc string, timeout time.Duration) func(string) (net.Conn, error) {
	if bindSrc == "" {
		return func(dst string) (net.Conn, error) {
			return net.DialTimeout("tcp", dst, timeout)
		}
	}
	la := &net.TCPAddr{IP: net.ParseIP(bindSrc)}
	d := net.Dialer{LocalAddr: la, Timeout: timeout}
	return func(dst string) (net.Conn, error) {
		return d.Dial("tcp", dst)
	}
}

func makeLogger(v bool) *slog.Logger {
	lvl := slog.LevelInfo
	if v {
		lvl = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// parseObfsKey یه hex string رو به 32 بایت تبدیل میکنه
func parseObfsKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		return nil, fmt.Errorf("--obfs-key خالی است")
	}
	if len(hexKey) != 64 {
		return nil, fmt.Errorf("obfs-key باید 64 کاراکتر hex باشه (32 بایت), داده شده: %d", len(hexKey))
	}
	key := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b, err := strconv.ParseUint(hexKey[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("hex نامعتبر در موقعیت %d: %w", i*2, err)
		}
		key[i] = byte(b)
	}
	return key, nil
}
