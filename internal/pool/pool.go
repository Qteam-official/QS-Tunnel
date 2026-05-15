package pool

import "sync"

type Sized struct {
	size int
	p    sync.Pool
}

func NewSized(size int) *Sized {
	s := &Sized{size: size}
	s.p.New = func() any {
		b := make([]byte, size)
		return &b
	}
	return s
}

func (s *Sized) Get() *[]byte {
	return s.p.Get().(*[]byte)
}

// Put برمیگردونه به pool
func (s *Sized) Put(b *[]byte) {
	if cap(*b) >= s.size {
		*b = (*b)[:s.size]
		s.p.Put(b)
	}
}

// ─── Global pools ────────────────────────────────────────────────────────────

var (
	// UDPPayload: بافر برای UDP packet (1460 + header margin)
	UDPPayload = NewSized(1500)

	// Frame: بافر برای TCP frame (تا 64KB)
	Frame = NewSized(64 * 1024)

	// Small: بافر کوچیک برای header‌ها
	Small = NewSized(256)
)
