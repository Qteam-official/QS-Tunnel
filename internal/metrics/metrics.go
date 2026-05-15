// Package metrics — متریک‌های سبک با endpoint HTTP
package metrics

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// Counters تمام شمارنده‌های runtime
type Counters struct {
	// تعداد
	ActiveStreams      atomic.Int64
	ActiveClients      atomic.Int64
	TotalStreams       atomic.Uint64
	TotalConnections   atomic.Uint64

	// آپلود
	UploadBytes        atomic.Uint64
	UploadPackets      atomic.Uint64

	// دانلود
	DownloadBytes      atomic.Uint64
	DownloadPackets    atomic.Uint64

	// خطا
	DialErrors         atomic.Uint64
	WriteErrors        atomic.Uint64
	ReassemblyDrops    atomic.Uint64

	// flow control
	FlowAcksSent       atomic.Uint64
	FlowAcksReceived   atomic.Uint64

	startTime time.Time
}

func New() *Counters {
	return &Counters{startTime: time.Now()}
}

// Snapshot یه snapshot از همه counter‌ها
type Snapshot struct {
	UptimeSec        float64 `json:"uptime_sec"`
	ActiveStreams    int64   `json:"active_streams"`
	ActiveClients    int64   `json:"active_clients"`
	TotalStreams     uint64  `json:"total_streams"`
	TotalConnections uint64  `json:"total_connections"`
	UploadBytes      uint64  `json:"upload_bytes"`
	UploadPackets    uint64  `json:"upload_packets"`
	DownloadBytes    uint64  `json:"download_bytes"`
	DownloadPackets  uint64  `json:"download_packets"`
	DialErrors       uint64  `json:"dial_errors"`
	WriteErrors      uint64  `json:"write_errors"`
	ReassemblyDrops  uint64  `json:"reassembly_drops"`
	FlowAcksSent     uint64  `json:"flow_acks_sent"`
	FlowAcksReceived uint64  `json:"flow_acks_received"`
}

func (c *Counters) Snapshot() Snapshot {
	return Snapshot{
		UptimeSec:        time.Since(c.startTime).Seconds(),
		ActiveStreams:    c.ActiveStreams.Load(),
		ActiveClients:    c.ActiveClients.Load(),
		TotalStreams:     c.TotalStreams.Load(),
		TotalConnections: c.TotalConnections.Load(),
		UploadBytes:      c.UploadBytes.Load(),
		UploadPackets:    c.UploadPackets.Load(),
		DownloadBytes:    c.DownloadBytes.Load(),
		DownloadPackets:  c.DownloadPackets.Load(),
		DialErrors:       c.DialErrors.Load(),
		WriteErrors:      c.WriteErrors.Load(),
		ReassemblyDrops:  c.ReassemblyDrops.Load(),
		FlowAcksSent:     c.FlowAcksSent.Load(),
		FlowAcksReceived: c.FlowAcksReceived.Load(),
	}
}

// ServeHTTP endpoint برای متریک‌ها
func (c *Counters) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c.Snapshot())
}

// StartHTTPServer یه HTTP server روی addr که متریک‌ها رو serve میکنه
func (c *Counters) StartHTTPServer(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", c)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	return http.ListenAndServe(addr, mux)
}
