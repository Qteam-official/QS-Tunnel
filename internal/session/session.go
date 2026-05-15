// Package session — مدیریت stream‌های یک کلاینت
//
// مسئولیت‌ها:
//   - یه TCP connection مشترک
//   - چند stream با ID جداگانه
//   - flow control (backpressure) از کلاینت به سرور
//   - idle timeout روی stream‌ها
//   - cleanup خودکار وقتی stream یا client قطع میشه
package session

import (
	"sync"
	"sync/atomic"
)

// FlowState وضعیت backpressure یک stream (سمت سرور)
//
// سرور تا InflightLimit بایت میتونه بفرسته بدون Ack.
// کلاینت با MsgFlowAck تأیید میکنه. سرور inflight رو کم میکنه.
type FlowState struct {
	inflight atomic.Int64
	limit    int64
	cond     *sync.Cond
	mu       sync.Mutex
	closed   atomic.Bool
}

// InflightLimit پیش‌فرض: 256KB
const DefaultInflightLimit = 256 * 1024

func NewFlow(limit int64) *FlowState {
	if limit <= 0 {
		limit = DefaultInflightLimit
	}
	fs := &FlowState{limit: limit}
	fs.cond = sync.NewCond(&fs.mu)
	return fs
}

// Acquire — قبل از فرستادن n بایت صبر میکنه تا ظرفیت داشته باشیم
// اگه session بسته شده باشه false برمیگردونه
func (f *FlowState) Acquire(n int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.inflight.Load()+int64(n) > f.limit && !f.closed.Load() {
		f.cond.Wait()
	}
	if f.closed.Load() {
		return false
	}
	f.inflight.Add(int64(n))
	return true
}

// Release — وقتی Ack از کلاینت اومد
func (f *FlowState) Release(n int) {
	f.inflight.Add(-int64(n))
	f.mu.Lock()
	f.cond.Broadcast()
	f.mu.Unlock()
}

// Close
func (f *FlowState) Close() {
	if f.closed.CompareAndSwap(false, true) {
		f.mu.Lock()
		f.cond.Broadcast()
		f.mu.Unlock()
	}
}

func (f *FlowState) Inflight() int64 { return f.inflight.Load() }
