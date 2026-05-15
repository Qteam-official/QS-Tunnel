package reasm

import (
	"container/heap"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxBuffered = 512
	gapTimeout  = 3 * time.Second
	chanBuf     = 512 // بزرگ — drop نمیکنیم
)

type packet struct {
	seq   uint32
	data  []byte
	at    time.Time
	flags byte
}

type pktHeap []packet

func (h pktHeap) Len() int           { return len(h) }
func (h pktHeap) Less(i, j int) bool { return h[i].seq < h[j].seq }
func (h pktHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *pktHeap) Push(x any)        { *h = append(*h, x.(packet)) }
func (h *pktHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// Reassembler
type Reassembler struct {
	mu      sync.Mutex
	heap    pktHeap
	nextSeq uint32
	ready   chan []byte
	closed  atomic.Bool

	delivered atomic.Uint64
	dropped   atomic.Uint64
}

func New(firstSeq uint32) *Reassembler {
	return &Reassembler{
		nextSeq: firstSeq,
		ready:   make(chan []byte, chanBuf),
	}
}

// Push یک packet دریافتی
func (r *Reassembler) Push(seq uint32, flags byte, data []byte) {
	if r.closed.Load() {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// duplicate یا قدیمی
	if seq < r.nextSeq {
		r.dropped.Add(1)
		return
	}

	// fast path: ترتیب درست
	if seq == r.nextSeq {
		r.put(data)
		r.nextSeq++
		r.flush()
		return
	}

	// out-of-order: heap
	if r.heap.Len() < maxBuffered {
		cp := make([]byte, len(data))
		copy(cp, data)
		heap.Push(&r.heap, packet{seq: seq, data: cp, at: time.Now(), flags: flags})
	} else {
		r.dropped.Add(1)
	}
}

// put داده رو به channel میفرسته — هیچوقت drop نمیکنه
// اگه channel پر شد، blocking میشه (با mutex رها شده)
func (r *Reassembler) put(data []byte) {
	r.delivered.Add(1)

	cp := make([]byte, len(data))
	copy(cp, data)

	// سعی non-blocking
	select {
	case r.ready <- cp:
		return
	default:
	}

	// channel پر — mutex رو رها کن و blocking بفرست
	r.mu.Unlock()
	r.ready <- cp
	r.mu.Lock()
}

func (r *Reassembler) flush() {
	for r.heap.Len() > 0 && r.heap[0].seq == r.nextSeq {
		p := heap.Pop(&r.heap).(packet)
		r.put(p.data)
		r.nextSeq++
	}
}

// Read داده‌های reassemble شده (blocking)
func (r *Reassembler) Read(p []byte) (int, error) {
	data, ok := <-r.ready
	if !ok {
		return 0, io.EOF
	}
	return copy(p, data), nil
}

func (r *Reassembler) Chan() <-chan []byte {
	return r.ready
}

func (r *Reassembler) Close() {
	if r.closed.CompareAndSwap(false, true) {
		close(r.ready)
	}
}

func (r *Reassembler) Stats() (delivered, dropped uint64) {
	return r.delivered.Load(), r.dropped.Load()
}

// ─── Manager ─────────────────────────────────────────────────────────────────

type Manager struct {
	mu   sync.RWMutex
	all  map[uint32]*Reassembler
	done chan struct{}
}

func NewManager() *Manager {
	m := &Manager{
		all:  make(map[uint32]*Reassembler),
		done: make(chan struct{}),
	}
	go m.worker()
	return m
}

func (m *Manager) Register(id uint32, r *Reassembler) {
	m.mu.Lock()
	m.all[id] = r
	m.mu.Unlock()
}

func (m *Manager) Unregister(id uint32) {
	m.mu.Lock()
	delete(m.all, id)
	m.mu.Unlock()
}

func (m *Manager) Stop() {
	close(m.done)
}

func (m *Manager) worker() {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-tick.C:
			now := time.Now()
			m.mu.RLock()
			for _, r := range m.all {
				r.gapCheck(now)
			}
			m.mu.RUnlock()
		}
	}
}

func (r *Reassembler) gapCheck(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return
	}
	for r.heap.Len() > 0 && now.Sub(r.heap[0].at) > gapTimeout {
		p := heap.Pop(&r.heap).(packet)
		r.nextSeq = p.seq + 1
		r.put(p.data)
		r.flush()
		r.dropped.Add(1)
	}
}
