<div align="center">

<br/>

```
 ██████╗ ███████╗    ████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗
██╔═══██╗██╔════╝    ╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║
██║   ██║███████╗       ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║
██║▄▄ ██║╚════██║       ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║
╚██████╔╝███████║       ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗
 ╚══▀▀═╝ ╚══════╝       ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

**`SPLIT-TUNNEL · TCP UPLOAD · UDP DOWNLOAD · IP SPOOF · OBFS`**

<br/>

![QS-Tunnel demo](q.jpg)

<br/>

[![Version](https://img.shields.io/badge/VERSION-1.0.1-00f5ff?style=for-the-badge&logo=github&logoColor=white&labelColor=020510)](https://github.com/Qteam-official/QS-Tunnel/releases)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white&labelColor=020510)](https://golang.org)
[![Platform](https://img.shields.io/badge/Linux-supported-ff9500?style=for-the-badge&logo=linux&logoColor=white&labelColor=020510)](https://github.com/Qteam-official/QS-Tunnel)
[![License](https://img.shields.io/badge/License-MIT-00ff9f?style=for-the-badge&labelColor=020510)](LICENSE)

[![Stars](https://img.shields.io/github/stars/Qteam-official/QS-Tunnel?style=for-the-badge&color=ff2d78&labelColor=020510&logo=github&label=⭐%20STARS)](https://github.com/Qteam-official/QS-Tunnel/stargazers)
[![Issues](https://img.shields.io/github/issues/Qteam-official/QS-Tunnel?style=for-the-badge&color=bf5fff&labelColor=020510&logo=github&label=🐛%20ISSUES)](https://github.com/Qteam-official/QS-Tunnel/issues)
[![Telegram](https://img.shields.io/badge/💬%20Telegram-@Q__teams-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white&labelColor=020510)](https://t.me/Q_teams)
[![YouTube](https://img.shields.io/badge/▶%20YouTube-@Q--TEAM-FF0000?style=for-the-badge&logo=youtube&logoColor=white&labelColor=020510)](https://youtube.com/@Q-TEAM-official)

<br/>

> `🇮🇷` [**مستندات فارسی**](#-مستندات-فارسی) &nbsp;`|`&nbsp; `🇬🇧` [**English Docs**](#-english-documentation)

<br/>

---

### ⚠️ Research & Educational Use Only

This project is intended **strictly for research and educational purposes**.  
We bear no responsibility for misuse or illegal activities. Users are solely responsible for how they use this software.  
In some regions, improper use may carry **legal consequences**.

---

</div>

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             ARCHITECTURE OVERVIEW                                │
├──────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│   Browser ──SOCKS5──▶ CLIENT ──TCP──▶ xray/v2ray ──TCP──▶ SERVER ──▶ 🌍 Net   │
│                          ▲                                      │                │
│                          └───────── UDP Direct + IP Spoof ◀────┘                │
│                                                                                  │
│   Upload  : TCP via local proxy (xray/v2ray/sing-box)   →  censorship bypass   │
│   Download: UDP direct from VPS                          →  high speed          │
│   Spoof   : Server forges source IP on UDP packets       →  identity control    │
│   Obfs    : AES-256-GCM + QUIC-like header, port 443    →  DPI evasion         │
│                                                                                  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## `🇬🇧` English Documentation

### What is QS-Tunnel?

**QS-Tunnel** is a high-performance **split-tunnel** proxy that routes upload and download through **completely separate paths**. Unlike traditional proxies where all traffic shares one route, QS-Tunnel gives you independent control over each direction — combining censorship bypass, raw speed, and deep traffic obfuscation.

| Path | Protocol | Route | Benefit |
|------|----------|-------|---------|
| ⬆ **Upload** | TCP | Client → xray/v2ray → Server | Censorship bypass |
| ⬇ **Download** | UDP | Server → Client (direct) | Maximum speed |
| 🎭 **IP Spoof** | AF_PACKET | Forged source IP on UDP | Traffic obfuscation |
| 🔐 **Obfs** | AES-256-GCM | QUIC-like header, port 443 | DPI evasion |

---

### Feature Matrix

```
┌──────────────────────────────┬────────┬────────────────────────────────────────┐
│ FEATURE                      │ STATUS │ DESCRIPTION                            │
├──────────────────────────────┼────────┼────────────────────────────────────────┤
│ Split upload / download      │  [ON]  │ TCP up · UDP down                      │
│ IP Spoof  (AF_PACKET)        │  [ON]  │ Raw socket · forge any source IP       │
│ Obfs mode (QUIC-like)        │  [ON]  │ AES-256-GCM · port 443 · beats DPI    │
│ Per-stream TCP               │  [ON]  │ Each user gets independent TCP tunnel  │
│ Auto reconnect               │  [ON]  │ One stream drops? others stay alive    │
│ Flow control                 │  [ON]  │ Window-based · no flooding             │
│ Auto IP / gateway detection  │  [ON]  │ Zero manual config needed              │
│ JSON config + CLI flags      │  [ON]  │ Priority merge · --gen-config          │
│ Random key generator         │  [ON]  │ --gen-key → cryptographically random   │
│ Metrics HTTP endpoint        │  [ON]  │ /metrics JSON · real-time stats        │
│ High concurrency             │  [ON]  │ 2000+ concurrent streams tested        │
│ Idle timeout                 │  [ON]  │ Auto-cleanup of stale streams          │
└──────────────────────────────┴────────┴────────────────────────────────────────┘
```

---

### Quick Start

```bash
# Clone & build
git clone https://github.com/Qteam-official/QS-Tunnel
cd QS-Tunnel
go build -o bin/server ./cmd/server
go build -o bin/client ./cmd/client

# Generate shared obfs key (keep secret — both sides need the same key)
./bin/client --gen-key

# Generate config templates
./bin/server --gen-config   # → server.json
./bin/client --gen-config   # → client.json

# Deploy
sudo ./bin/server --config server.json   # on VPS
     ./bin/client --config client.json   # on local machine

# Point your browser SOCKS5 proxy → 127.0.0.1:1080
```

---

### Server Config (`server.json`)

```jsonc
{
  "listen_addr":            "0.0.0.0:9000",
  "download_src_port":      9001,

  // Transport: "udp" = fast (default)  |  "obfs" = AES-256-GCM, DPI-resistant
  "transport_mode":         "udp",
  "obfs_key":               "",          // 64-char hex — generate with --gen-key

  // IP Spoof: server forges this IP as UDP source (optional, requires root)
  "spoof_ip":               "",          // e.g. "1.2.3.4"
  "spoof_interface":        "",          // e.g. "eth0" — auto-detect if empty
  "spoof_gateway":          "",          // auto-detect from /proc/net/route

  "outbound_bind_ip":       "",
  "max_clients":            1000,
  "max_streams_per_client": 256,
  "flow_window_bytes":      131072,      // 128 KB
  "udp_workers":            0,           // 0 = NumCPU
  "dial_timeout_sec":       8,
  "idle_timeout_sec":       120,
  "metrics_addr":           "127.0.0.1:9090",
  "verbose":                false
}
```

---

### Client Config (`client.json`)

```jsonc
{
  "server_addr":    "VPS_IP:9000",
  "upload_proxy":   "127.0.0.1:10808",  // your local xray / v2ray / sing-box
  "local_socks":    "127.0.0.1:1080",   // browser proxy listener
  "download_port":  8000,               // UDP port for incoming downloads

  "my_public_ip":   "",                 // auto-detected if empty ✨

  // Transport: "udp" or "obfs" — must match server, obfs_key must be identical
  "transport_mode": "udp",
  "obfs_key":       "",

  "max_streams":    512,
  "metrics_addr":   "127.0.0.1:9091",
  "verbose":        false
}
```

---

### Transport Modes

<details>
<summary><b>▶ UDP — fast, any port (default)</b></summary>

No encryption overhead. Best when speed is the priority.

```bash
# Server
sudo ./bin/server --listen-addr 0.0.0.0:9000 --download-src-port 9001

# Client
./bin/client --server VPS_IP:9000 --download-port 8000
```
</details>

<details>
<summary><b>▶ OBFS — AES-256-GCM, looks like QUIC/HTTPS to DPI</b></summary>

Downloads are encrypted and wrapped in a QUIC Short Header. Deep packet inspection sees standard HTTPS traffic on port 443. The key must match on both sides.

```
Packet on the wire:
  [ 0x4X | 8B connID | 8B pktNum | AES-256-GCM ciphertext ]
      ↑                               ↑
    QUIC Short Header bit pattern   indistinguishable from real QUIC
```

```bash
# 1. Generate shared key
./bin/client --gen-key
# → e.g. a3f8c2d1e4b5a6f7c8d9e0f1a2b3c4d5...

# 2. Server (port 443 for best DPI bypass)
sudo ./bin/server \
  --listen-addr 0.0.0.0:9000 \
  --download-src-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY

# 3. Client
./bin/client \
  --server VPS_IP:9000 \
  --download-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY
```
</details>

<details>
<summary><b>▶ IP Spoof — forge UDP source IP (requires root)</b></summary>

The server uses raw **AF_PACKET** sockets to send UDP download packets with a forged source IP. The client receives traffic that appears to come from any IP you choose — making traffic analysis and correlation attacks significantly harder.

```bash
# Server — interface and gateway auto-detected if left empty
sudo ./bin/server \
  --listen-addr 0.0.0.0:9000 \
  --download-src-port 9001 \
  --spoof-ip 1.2.3.4 \
  --spoof-interface eth0

# Maximum stealth: combine Spoof + Obfs
sudo ./bin/server \
  --download-src-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY \
  --spoof-ip 1.2.3.4
```

> Requires `CAP_NET_RAW` capability or running as root on the VPS.
</details>

---

### CLI Reference

<details>
<summary><b>Client flags</b></summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | — | JSON config file |
| `--server` | — | Server `IP:port` |
| `--upload-proxy` | `127.0.0.1:10808` | Local SOCKS5 (xray/v2ray) |
| `--local-socks` | `127.0.0.1:1080` | Browser proxy listener |
| `--download-port` | `8000` | UDP download port |
| `--my-public-ip` | auto | Your public IP |
| `--transport-mode` | `udp` | `udp` or `obfs` |
| `--obfs-key` | — | 64-char hex key |
| `--max-connections` | `512` | Max concurrent streams |
| `--metrics-addr` | `127.0.0.1:9091` | Metrics HTTP |
| `--gen-config` | — | Write `client.json` template |
| `--gen-key` | — | Generate random obfs key |
| `-v` | — | Verbose logging |

</details>

<details>
<summary><b>Server flags</b></summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | — | JSON config file |
| `--listen-addr` | `0.0.0.0:9000` | TCP listen address |
| `--download-src-port` | `9001` | UDP source port |
| `--transport-mode` | `udp` | `udp` or `obfs` |
| `--obfs-key` | — | 64-char hex key |
| `--spoof-ip` | — | Fake UDP source IP |
| `--spoof-interface` | auto | Network interface |
| `--spoof-gateway` | auto | Gateway MAC lookup |
| `--max-clients` | `1000` | Max connected clients |
| `--metrics-addr` | `127.0.0.1:9090` | Metrics HTTP |
| `--gen-config` | — | Write `server.json` template |
| `--gen-key` | — | Generate random obfs key |
| `-v` | — | Verbose logging |

</details>

---

### Metrics

```bash
curl http://127.0.0.1:9090/metrics | python3 -m json.tool
```

```json
{
  "active_streams":    42,
  "active_clients":    8,
  "total_streams":     1024,
  "upload_bytes":      52428800,
  "download_bytes":    524288000,
  "reconnects":        3,
  "reassembly_drops":  0,
  "flow_acks_sent":    32768,
  "uptime_sec":        3600
}
```

---

### High Concurrency Tuning

For thousands of users, apply these on the VPS before starting the server:

```bash
# /etc/sysctl.conf
net.core.somaxconn        = 65535
net.ipv4.tcp_tw_reuse     = 1
net.ipv4.tcp_fin_timeout  = 15
net.core.rmem_max         = 134217728
net.core.wmem_max         = 134217728
sysctl -p

# /etc/security/limits.conf
* soft nofile 1000000
* hard nofile 1000000
```

`server.json` for large deployments:

```jsonc
{
  "max_clients":            5000,
  "max_streams_per_client": 32,
  "flow_window_bytes":      131072,
  "idle_timeout_sec":       60,
  "dial_timeout_sec":       5
}
```

---

## `🇮🇷` مستندات فارسی

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              معماری سیستم                                  │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   مرورگر ──SOCKS5──▶ کلاینت ──TCP──▶ xray/v2ray ──TCP──▶ سرور ──▶ 🌍     │
│                          ▲                                    │              │
│                          └──────── UDP مستقیم + IP Spoof ◀───┘              │
│                                                                             │
│   آپلود  : TCP از طریق پروکسی محلی   ←  دور زدن فیلتر                    │
│   دانلود : UDP مستقیم از سرور        ←  سرعت بالا                         │
│   Spoof  : سرور IP جعلی روی UDP      ←  پنهان‌کاری هویت                   │
│   Obfs   : رمزنگاری AES-256-GCM      ←  مقاوم در برابر DPI               │
│                                                                             │
└────────────────────────────────────────────────────────────────────────────┘
```

### چرا QS-Tunnel؟

در پروکسی‌های معمول، آپلود و دانلود هر دو از یک مسیر رد می‌شوند. QS-Tunnel این دو را **کاملاً جدا** می‌کند و قابلیت‌های اضافی مثل IP Spoof و رمزنگاری obfs را هم ارائه می‌دهد:

```
معمولی:     مرورگر ──▶ proxy ──▶ سرور ──▶ مقصد ──▶ proxy ──▶ مرورگر
                           [ همه از یک مسیر ]

QS-Tunnel:  آپلود  ──▶ xray ──▶ سرور ──▶ مقصد
            دانلود ◀── UDP مستقیم (با IP Spoof + Obfs اختیاری) ────
```

---

### جدول ویژگی‌ها

```
┌────────────────────────────┬───────────────────────────────────────────────┐
│ ویژگی                      │ توضیح                                         │
├────────────────────────────┼───────────────────────────────────────────────┤
│ مسیر آپلود جداگانه         │ TCP از xray / v2ray / sing-box                │
│ مسیر دانلود جداگانه        │ UDP مستقیم از سرور                            │
│ IP Spoof (AF_PACKET)       │ جعل IP مبدا با raw socket                     │
│ حالت Obfs (QUIC-like)      │ AES-256-GCM · پورت 443 · شبیه HTTPS          │
│ TCP مستقل per-stream       │ قطع یه proxy فقط اون stream رو تحت تأثیر      │
│ reconnect خودکار           │ هر stream مستقل reconnect میکنه               │
│ تشخیص خودکار               │ IP عمومی، gateway، interface خودکار           │
│ Config JSON + CLI          │ اولویت‌بندی هوشمند · --gen-config             │
│ کلید تصادفی                │ --gen-key → 32 بایت رمزنگاری                  │
│ متریک realtime             │ /metrics JSON                                  │
│ مقیاس بالا                 │ تست شده با 2000+ stream همزمان               │
└────────────────────────────┴───────────────────────────────────────────────┘
```

---

### شروع سریع

```bash
# ساخت
git clone https://github.com/Qteam-official/QS-Tunnel
cd QS-Tunnel
go build -o bin/server ./cmd/server
go build -o bin/client ./cmd/client

# ساخت کلید obfs — هر دو طرف باید یکی داشته باشن
./bin/client --gen-key

# ساخت فایل‌های config
./bin/server --gen-config   # → server.json
./bin/client --gen-config   # → client.json

# اجرا روی VPS
sudo ./bin/server --config server.json

# اجرا روی سیستم خودت
./bin/client --config client.json

# تنظیم مرورگر: SOCKS5 → 127.0.0.1:1080
```

---

### حالت‌های Transport

<details>
<summary><b>▶ UDP — سریع، هر پورت (پیش‌فرض)</b></summary>

بدون overhead رمزنگاری. بهترین گزینه برای شبکه‌های معمولی.

```bash
./bin/server --download-src-port 9001
./bin/client --download-port 8000
```
</details>

<details>
<summary><b>▶ Obfs — رمزنگاری AES-256-GCM، از دید DPI شبیه HTTPS</b></summary>

پکت‌های دانلود رمز می‌شوند و با header شبیه QUIC Short Header ارسال می‌شوند. فایروال‌ها ترافیک HTTPS معمولی روی پورت 443 می‌بینند. کلید باید در هر دو طرف یکسان باشد.

```bash
# ساخت کلید مشترک
./bin/client --gen-key

# سرور (پورت 443 بهترین گزینه)
sudo ./bin/server \
  --download-src-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY

# کلاینت
./bin/client \
  --download-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY
```
</details>

<details>
<summary><b>▶ IP Spoof — جعل IP مبدا UDP (نیاز به root)</b></summary>

سرور با **AF_PACKET raw socket**، پکت‌های UDP دانلود را با IP مبدا دلخواه می‌فرستد. کلاینت ترافیک را از IP جعلی دریافت می‌کند — تحلیل ترافیک و correlation attack بسیار سخت‌تر می‌شود.

Interface و gateway اگر خالی باشند **خودکار تشخیص داده می‌شوند**.

```bash
# سرور
sudo ./bin/server \
  --download-src-port 9001 \
  --spoof-ip 1.2.3.4

# حداکثر پنهان‌کاری: Spoof + Obfs با هم
sudo ./bin/server \
  --download-src-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY \
  --spoof-ip 1.2.3.4
```
</details>

---

### اولویت تنظیمات

```
--flag صریح   ◀── بالاترین اولویت
config.json   ◀── میانی
auto-detect   ◀── هوشمند (IP، gateway، interface)
default       ◀── پایین‌ترین
```

```bash
# ترکیب config + override با flag
./bin/client --config client.json --server NEW_VPS:9000 --v
```

---

### نیازمندی‌ها

```
• Go 1.21+
• Linux
• VPS با IP عمومی
• xray / v2ray / sing-box روی کلاینت (برای آپلود)
• برای IP Spoof: root یا CAP_NET_RAW روی سرور
```

---

<div align="center">

<br/>

[![Telegram](https://img.shields.io/badge/💬%20کانال%20تلگرام-@Q__teams-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white&labelColor=020510)](https://t.me/Q_teams)
[![YouTube](https://img.shields.io/badge/▶%20یوتیوب-@Q--TEAM--official-FF0000?style=for-the-badge&logo=youtube&logoColor=white&labelColor=020510)](https://youtube.com/@Q-TEAM-official)
[![Issues](https://img.shields.io/badge/🐛%20گزارش%20باگ-GitHub-bf5fff?style=for-the-badge&logo=github&logoColor=white&labelColor=020510)](https://github.com/Qteam-official/QS-Tunnel/issues)

<br/>

**`⭐ اگه پروژه مفید بود ستاره بدید — Star if useful ⭐`**

<br/>

`MIT License — free to use, modify, and distribute`

</div>
