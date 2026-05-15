// Package limit — rate limiting و connection limit
package limit

import (
	"sync"
	"sync/atomic"
	"time"
)

// ─── Token Bucket ─────────────────────────────────────────────────────────────

type Bucket struct {
	mu     sync.Mutex
	tokens float64
	cap    float64
	rate   float64 // tokens/ns
	last   time.Time
}

func NewBucket(perSec, burst float64) *Bucket {
	if perSec <= 0 {
		return nil
	}
	return &Bucket{
		tokens: burst,
		cap:    burst,
		rate:   perSec / 1e9,
		last:   time.Now(),
	}
}

// TryConsume — non-blocking. اگه token کافی نباشه false برمیگردونه.
func (b *Bucket) TryConsume(n int) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += float64(now.Sub(b.last)) * b.rate
	if b.tokens > b.cap {
		b.tokens = b.cap
	}
	b.last = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// Wait — blocking. صبر میکنه تا token کافی بشه.
func (b *Bucket) Wait(n int) {
	if b == nil {
		return
	}
	for !b.TryConsume(n) {
		time.Sleep(1 * time.Millisecond)
	}
}

// ─── Connection counter (per-client) ──────────────────────────────────────────

type ConnCounter struct {
	max int32
	cur atomic.Int32
}

func NewConnCounter(max int) *ConnCounter {
	return &ConnCounter{max: int32(max)}
}

// Acquire سعی میکنه یه slot بگیره. اگه پر باشه false.
func (c *ConnCounter) Acquire() bool {
	if c.max <= 0 {
		c.cur.Add(1)
		return true
	}
	for {
		cur := c.cur.Load()
		if cur >= c.max {
			return false
		}
		if c.cur.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (c *ConnCounter) Release() {
	c.cur.Add(-1)
}

func (c *ConnCounter) Count() int32 {
	return c.cur.Load()
}
