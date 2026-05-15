// Package config — مدیریت config با اولویت‌بندی
//
// اولویت: flag > config.json > auto-detect > default
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ─── Client Config ────────────────────────────────────────────────────────────

type ClientConfig struct {
	// اتصال به سرور
	ServerAddr    string `json:"server_addr"`     // آدرس سرور تونل (IP:port)
	UploadProxy   string `json:"upload_proxy"`    // SOCKS5 آپلود (xray/v2ray/هر چیزی)
	LocalSocks    string `json:"local_socks"`     // SOCKS5 که مرورگر به اون وصل میشه
	DownloadPort  int    `json:"download_port"`   // پورت UDP دریافت دانلود
	MyPublicIP    string `json:"my_public_ip"`    // IP عمومی کلاینت (خودکار اگه خالی)

	// Transport
	TransportMode string `json:"transport_mode"`  // "udp" یا "obfs"
	ObfsKey       string `json:"obfs_key"`        // کلید obfuscation (hex 64 کاراکتر)

	// محدودیت‌ها
	MaxStreams     int    `json:"max_streams"`     // حداکثر اتصال همزمان

	// Observability
	MetricsAddr   string `json:"metrics_addr"`    // آدرس HTTP متریک‌ها
	Verbose       bool   `json:"verbose"`
}

func DefaultClient() ClientConfig {
	return ClientConfig{
		UploadProxy:   "127.0.0.1:10808",
		LocalSocks:    "127.0.0.1:1080",
		DownloadPort:  8000,
		TransportMode: "udp",
		MaxStreams:     512,
		MetricsAddr:   "127.0.0.1:9091",
	}
}

// ─── Server Config ────────────────────────────────────────────────────────────

type ServerConfig struct {
	// اتصال
	ListenAddr         string `json:"listen_addr"`          // آدرس TCP listen
	DownloadSrcPort    int    `json:"download_src_port"`    // پورت UDP برای ارسال دانلود

	// Transport
	TransportMode      string `json:"transport_mode"`       // "udp" یا "obfs"
	ObfsKey            string `json:"obfs_key"`

	// IP Spoof (فقط حالت udp)
	SpoofIP            string `json:"spoof_ip"`             // IP جعلی برای دانلود UDP
	SpoofInterface     string `json:"spoof_interface"`      // interface خروجی (مثل eth0)
	SpoofGateway       string `json:"spoof_gateway"`        // gateway (خودکار اگه خالی)

	// TCP خروجی
	OutboundBindIP     string `json:"outbound_bind_ip"`     // IP مبدا برای اتصال TCP به مقصد

	// محدودیت‌ها
	MaxClients          int   `json:"max_clients"`
	MaxStreamsPerClient  int   `json:"max_streams_per_client"`
	FlowWindowBytes     int64 `json:"flow_window_bytes"`    // پنجره flow control
	UDPWorkers          int   `json:"udp_workers"`          // تعداد worker UDP

	// Timeouts
	DialTimeoutSec      int   `json:"dial_timeout_sec"`
	IdleTimeoutSec      int   `json:"idle_timeout_sec"`

	// Observability
	MetricsAddr         string `json:"metrics_addr"`
	Verbose             bool   `json:"verbose"`
}

func DefaultServer() ServerConfig {
	return ServerConfig{
		ListenAddr:         "0.0.0.0:9000",
		DownloadSrcPort:    9001,
		TransportMode:      "udp",
		SpoofInterface:     "eth0",
		MaxClients:         1000,
		MaxStreamsPerClient: 256,
		FlowWindowBytes:    256 * 1024,
		DialTimeoutSec:     8,
		IdleTimeoutSec:     120,
		MetricsAddr:        "127.0.0.1:9090",
	}
}

// ─── Auto-detect ──────────────────────────────────────────────────────────────

// DetectPublicIP IP عمومی رو از اینترنت تشخیص میده
func DetectPublicIP() (string, error) {
	// چند سرویس — اولی که جواب داد استفاده میشه
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, svc := range services {
		resp, err := client.Get(svc)
		if err != nil {
			continue
		}
		body := make([]byte, 64)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		ip := strings.TrimSpace(string(body[:n]))
		if net.ParseIP(ip) != nil {
			return ip, nil
		}
	}
	return "", fmt.Errorf("تشخیص IP عمومی ناموفق")
}

// DetectOutboundIP IP خروجی به سمت server رو پیدا میکنه (بدون اینترنت)
func DetectOutboundIP(serverAddr string) (string, error) {
	c, err := net.Dial("udp4", serverAddr)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// DetectDefaultInterface اسم interface خروجی پیش‌فرض رو پیدا میکنه
// از /proc/net/route میخونه — مطمئن‌ترین روش روی Linux
func DetectDefaultInterface() (string, error) {
	// روش ۱: از /proc/net/route (مطمئن‌ترین)
	data, err := os.ReadFile("/proc/net/route")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 4 {
				continue
			}
			// destination=00000000 یعنی default route
			if f[1] == "00000000" && f[7] == "00000000" {
				iface := strings.TrimSpace(f[0])
				if iface != "" {
					return iface, nil
				}
			}
		}
	}

	// روش ۲: اولین interface غیر loopback با IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipNet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
					return iface.Name, nil
				}
			}
		}
	}
	return "", fmt.Errorf("interface خروجی پیدا نشد — دستی تنظیم کن: spoof_interface")
}

// DetectDefaultGateway gateway پیش‌فرض رو از /proc/net/route میخونه
func DetectDefaultGateway() (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		if f[1] == "00000000" {
			var b [4]byte
			fmt.Sscanf(f[2][6:8], "%02x", &b[0])
			fmt.Sscanf(f[2][4:6], "%02x", &b[1])
			fmt.Sscanf(f[2][2:4], "%02x", &b[2])
			fmt.Sscanf(f[2][0:2], "%02x", &b[3])
			return net.IP(b[:]).String(), nil
		}
	}
	return "", fmt.Errorf("default route پیدا نشد")
}

// ─── Load/Save ────────────────────────────────────────────────────────────────

func LoadClient(path string) (ClientConfig, error) {
	cfg := DefaultClient()
	if err := loadJSON(path, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func LoadServer(path string) (ServerConfig, error) {
	cfg := DefaultServer()
	if err := loadJSON(path, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func loadJSON(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("باز کردن %s: %w", path, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func SaveClientExample(path string) error {
	cfg := ClientConfig{
		ServerAddr:    "VPS_IP:9000",
		UploadProxy:   "127.0.0.1:10808",
		LocalSocks:    "127.0.0.1:1080",
		DownloadPort:  8000,
		MyPublicIP:    "",
		TransportMode: "udp",
		ObfsKey:       "",
		MaxStreams:     512,
		MetricsAddr:   "127.0.0.1:9091",
		Verbose:       false,
	}
	return saveJSON(path, cfg)
}

func SaveServerExample(path string) error {
	cfg := ServerConfig{
		ListenAddr:         "0.0.0.0:9000",
		DownloadSrcPort:    9001,
		TransportMode:      "udp",
		ObfsKey:            "",
		SpoofIP:            "",
		SpoofInterface:     "",
		SpoofGateway:       "",
		OutboundBindIP:     "",
		MaxClients:         1000,
		MaxStreamsPerClient: 256,
		FlowWindowBytes:    262144,
		UDPWorkers:         0,
		DialTimeoutSec:     8,
		IdleTimeoutSec:     120,
		MetricsAddr:        "127.0.0.1:9090",
		Verbose:            false,
	}
	return saveJSON(path, cfg)
}

func saveJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ─── Apply: flag روی config override میکنه ────────────────────────────────────

func ApplyString(cfg *string, flagVal, defaultVal string) {
	if flagVal != defaultVal && flagVal != "" {
		*cfg = flagVal
	}
}

func ApplyInt(cfg *int, flagVal, defaultVal int) {
	if flagVal != defaultVal && flagVal != 0 {
		*cfg = flagVal
	}
}

func ApplyInt64(cfg *int64, flagVal, defaultVal int64) {
	if flagVal != defaultVal && flagVal != 0 {
		*cfg = flagVal
	}
}

func ApplyBool(cfg *bool, flagVal bool) {
	if flagVal {
		*cfg = true
	}
}
