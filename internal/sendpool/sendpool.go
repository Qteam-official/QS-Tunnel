package sendpool

import (
	"runtime"
	"sync/atomic"

	"net"

	"github.com/sttunnel/internal/transport"
)

// Packet یه پکت برای ارسال
type Packet struct {
	StreamID uint32
	Data     []byte
	Dst      *net.UDPAddr
}

// Pool چند worker با send queue جداگانه
type Pool struct {
	workers []*worker
	mask    uint32
	dropped atomic.Uint64
	sent    atomic.Uint64
}

type worker struct {
	tr    transport.Transport
	queue chan Packet
	done  chan struct{}
	pool  *Pool
}

// Config
type Config struct {
	Workers   int
	QueueSize int
	Transport transport.Transport
}

func New(cfg Config) (*Pool, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 4096
	}

	// round up to power of 2
	n := 1
	for n < cfg.Workers {
		n <<= 1
	}

	p := &Pool{
		workers: make([]*worker, n),
		mask:    uint32(n - 1),
	}

	for i := 0; i < n; i++ {
		w := &worker{
			tr:    cfg.Transport,
			queue: make(chan Packet, cfg.QueueSize),
			done:  make(chan struct{}),
			pool:  p,
		}
		p.workers[i] = w
		go w.run()
	}
	return p, nil
}

// Send یه پکت رو به worker مناسب میفرسته (non-blocking)
func (p *Pool) Send(pkt Packet) {
	w := p.workers[pkt.StreamID&p.mask]
	select {
	case w.queue <- pkt:
	default:
		p.dropped.Add(1)
	}
}

// Close
func (p *Pool) Close() {
	for _, w := range p.workers {
		close(w.queue)
		<-w.done
	}
}

func (p *Pool) Stats() (sent, dropped uint64) {
	return p.sent.Load(), p.dropped.Load()
}

func (w *worker) run() {
	defer close(w.done)
	for pkt := range w.queue {
		if err := w.tr.Send(pkt.Dst, pkt.Data); err != nil {
			w.pool.dropped.Add(1)
		} else {
			w.pool.sent.Add(1)
		}
	}
}
