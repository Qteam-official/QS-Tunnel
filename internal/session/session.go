// Package session — flow control هوشمند با timeout
//
// مشکلاتی که حل میکنه:
//   1. deadlock وقتی upload proxy ضعیفه — timeout بعد از N ثانیه window آزاد میشه
//   2. بعد از TCP reconnect — Reset() همه inflight رو صفر میکنه
//   3. قطع و وصل — هیچوقت forever بلاک نمیکنه
package session

import (
	"sync"
	"sync/atomic"
	"time"
)

const DefaultInflightLimit = 512 * 1024 // 512KB

type FlowState struct {
	mu       sync.Mutex
	cond     *sync.Cond
	inflight int64
	limit    int64
	closed   atomic.Bool
}

func NewFlow(limit int64) *FlowState {
	if limit <= 0 {
		limit = DefaultInflightLimit
	}
	fs := &FlowState{limit: limit}
	fs.cond = sync.NewCond(&fs.mu)
	return fs
}

// Acquire صبر میکنه تا ظرفیت باشه — حداکثر timeout
// اگه timeout بشه window رو نصف میکنه و ادامه میده (بهتر از deadlock)
func (f *FlowState) Acquire(n int, timeout time.Duration) bool {
	if f.closed.Load() {
		return false
	}

	deadline := time.Now().Add(timeout)
	f.mu.Lock()
	defer f.mu.Unlock()

	for f.inflight+int64(n) > f.limit {
		if f.closed.Load() {
			return false
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			// timeout — window رو نصف کن تا deadlock نشه
			f.inflight = f.limit / 2
			break
		}
		// یه timer کوتاه تا cond.Wait رو بیدار کنه
		wait := remaining
		if wait > 300*time.Millisecond {
			wait = 300 * time.Millisecond
		}
		go func(d time.Duration) {
			time.Sleep(d)
			f.cond.Broadcast()
		}(wait)
		f.cond.Wait()
	}

	if f.closed.Load() {
		return false
	}
	f.inflight += int64(n)
	return true
}

// Release وقتی ack از کلاینت اومد
func (f *FlowState) Release(n int) {
	f.mu.Lock()
	f.inflight -= int64(n)
	if f.inflight < 0 {
		f.inflight = 0
	}
	f.cond.Broadcast()
	f.mu.Unlock()
}

// Reset بعد از TCP reconnect — همه inflight رو صفر میکنه
func (f *FlowState) Reset() {
	f.mu.Lock()
	f.inflight = 0
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

func (f *FlowState) Inflight() int64 {
	f.mu.Lock()
	v := f.inflight
	f.mu.Unlock()
	return v
}
