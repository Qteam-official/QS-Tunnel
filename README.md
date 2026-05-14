<div align="center">


**`[ SPLIT-TUNNEL · UPLOAD:TCP · DOWNLOAD:UDP · IP-SPOOF ]`**

<br/>

![QS-Tunnel demo](QS-Tunnel-demo.gif)

<br/>

[![Version](https://img.shields.io/badge/▶ VERSION-1.0.0-00f5ff?style=for-the-badge&labelColor=020510)](https://github.com/Qteam-official/QS-Tunnel/releases)
[![Go](https://img.shields.io/badge/▶ BUILT_WITH-Go_1.21+-00ADD8?style=for-the-badge&labelColor=020510&logo=go&logoColor=white)](https://golang.org)
[![Platform](https://img.shields.io/badge/▶ PLATFORM-Linux-ff9500?style=for-the-badge&labelColor=020510&logo=linux&logoColor=white)](https://github.com/Qteam-official/QS-Tunnel)
[![License](https://img.shields.io/badge/▶ LICENSE-MIT-00ff9f?style=for-the-badge&labelColor=020510)](LICENSE)

[![Stars](https://img.shields.io/github/stars/Qteam-official/QS-Tunnel?style=for-the-badge&color=ff2d78&labelColor=020510&logo=github&label=★ STARS)](https://github.com/Qteam-official/QS-Tunnel/stargazers)
[![Issues](https://img.shields.io/github/issues/Qteam-official/QS-Tunnel?style=for-the-badge&color=bf5fff&labelColor=020510&logo=github&label=⚡ ISSUES)](https://github.com/Qteam-official/QS-Tunnel/issues)
[![Telegram](https://img.shields.io/badge/TELEGRAM-@Q_teams-2CA5E0?style=for-the-badge&labelColor=020510&logo=telegram)](https://t.me/Q_teams)
[![YouTube](https://img.shields.io/badge/YOUTUBE-@Q-TEAM-official-FF0000?style=for-the-badge&labelColor=020510&logo=youtube)](https://youtube.com/@Q-TEAM-official)

<br/>

> **`🇮🇷`** [**مستندات فارسی**](#-مستندات-فارسی) &nbsp;`//`&nbsp; **`🇬🇧`** [**English Docs**](#-english-documentation)

</div>

<br/>

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  SYSTEM OVERVIEW                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Browser ──SOCKS5──▶ CLIENT ──TCP──▶ xray/v2ray ──TCP──▶ SERVER ──▶ Net    │
│                                                              │               │
│                      CLIENT ◀───────── UDP + Spoof ─────────┘               │
│                                                                              │
│  Upload  : TCP via local proxy (bypass censorship)                          │
│  Download: UDP direct from VPS  (optional IP spoof)                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## `// 🇬🇧` English Documentation

### `▸` What is QS-Tunnel?

**QS-Tunnel** is a production-grade **split-tunnel** proxy that routes upload and download through **completely separate paths**:

| Path | Protocol | Route | Purpose |
|------|----------|-------|---------|
| ⬆ **Upload** | TCP | Client → xray → Server | Bypass censorship |
| ⬇ **Download** | UDP | Server → Client (direct) | High performance |
| 🎭 **Spoof** | AF_PACKET | Custom src IP on UDP | Identity control |

> This architecture gives you **full independent control** over both paths — something no traditional proxy offers.

---

### `▸` Feature Matrix

```
┌────────────────────────────┬────────┬──────────────────────────────────────┐
│ FEATURE                    │ STATUS │ DESCRIPTION                          │
├────────────────────────────┼────────┼──────────────────────────────────────┤
│ Split upload/download      │  [ON]  │ TCP up · UDP down                    │
│ IP Spoof (AF_PACKET)       │  [ON]  │ Raw socket · like hping3             │
│ Obfs mode (QUIC-like)      │  [ON]  │ AES-256-GCM · port 443              │
│ Auto reconnect             │  [ON]  │ TCP drops? streams survive           │
│ Flow control               │  [ON]  │ AIMD window + token bucket           │
│ Auto IP detection          │  [ON]  │ public IP · gateway · interface      │
│ JSON config + CLI flags    │  [ON]  │ priority merge · --gen-config        │
│ Random key generator       │  [ON]  │ --gen-key → 32-byte random           │
│ Metrics HTTP endpoint      │  [ON]  │ /metrics JSON · /healthz             │
│ Stream multiplexing        │  [ON]  │ multiple streams on one TCP          │
│ Per-client limits          │  [ON]  │ max clients · max streams            │
│ Idle timeout               │  [ON]  │ auto cleanup stale streams           │
└────────────────────────────┴────────┴──────────────────────────────────────┘
```

---

### `▸` Quick Start

```bash
# ── Clone & Build ──────────────────────────────────────────────
git clone https://github.com/Qteam-official/QS-Tunnel
cd QS-Tunnel
go build -o bin/server ./cmd/server
go build -o bin/client ./cmd/client

# ── Generate obfs key (copy to both configs) ───────────────────
./bin/client --gen-key
# → 🔑 a3f8c2d1e4b5...

# ── Generate config files ──────────────────────────────────────
./bin/server --gen-config   # → server.json
./bin/client --gen-config   # → client.json

# ── Deploy server (VPS) ────────────────────────────────────────
sudo ./bin/server --config server.json

# ── Run client (local) ─────────────────────────────────────────
./bin/client --config client.json

# ── Set browser proxy: SOCKS5 → 127.0.0.1:1080 ────────────────
```

---

### `▸` Server Config (`server.json`)

```jsonc
{
  "listen_addr":            "0.0.0.0:9000",   // TCP listen
  "download_src_port":      9001,              // UDP output port
  "transport_mode":         "udp",             // "udp" | "obfs"
  "obfs_key":               "",               // 64-char hex (gen-key)
  "spoof_ip":               "",               // fake source IP for UDP
  "spoof_interface":        "",               // auto-detect if empty
  "spoof_gateway":          "",               // auto-detect if empty
  "outbound_bind_ip":       "",               // TCP bind IP for outbound
  "max_clients":            1000,
  "max_streams_per_client": 256,
  "flow_window_bytes":      262144,           // 256 KB
  "udp_workers":            0,               // 0 = NumCPU
  "dial_timeout_sec":       8,
  "idle_timeout_sec":       120,
  "metrics_addr":           "127.0.0.1:9090",
  "verbose":                false
}
```

---

### `▸` Client Config (`client.json`)

```jsonc
{
  "server_addr":    "VPS_IP:9000",            // QS-Tunnel server
  "upload_proxy":   "127.0.0.1:10808",        // local SOCKS5 (xray/v2ray)
  "local_socks":    "127.0.0.1:1080",         // browser connects here
  "download_port":  8000,                     // UDP listen port
  "my_public_ip":   "",                       // auto-detected if empty ✨
  "transport_mode": "udp",                    // "udp" | "obfs"
  "obfs_key":       "",                       // must match server
  "max_streams":    512,
  "metrics_addr":   "127.0.0.1:9091",
  "verbose":        false
}
```

> 💡 **`my_public_ip`** left empty = auto-detected via `api.ipify.org` + fallback to outbound interface.

---

### `▸` Transport Modes

<details>
<summary><code>▶ MODE: UDP (default)</code></summary>

```bash
# Fast, minimal overhead, any port
# Server:
./bin/server --listen-addr 0.0.0.0:9000 --download-src-port 9001

# Client:
./bin/client --server VPS:9000 --download-port 8000
```
</details>

<details>
<summary><code>▶ MODE: OBFS — looks like QUIC/HTTPS to DPI</code></summary>

```
Packet structure:
  [0x4X] [8B connID] [4B pktNum] [AES-256-GCM encrypted payload]
    ↑                                ↑
  QUIC Short Header bit pattern    indistinguishable from QUIC
```

```bash
# Generate shared key:
./bin/client --gen-key
# → 🔑 a3f8c2d1e4b5a6f7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1

# Server (port 443 UDP):
sudo ./bin/server \
  --listen-addr 0.0.0.0:9000 \
  --download-src-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY_HERE

# Client:
./bin/client \
  --server VPS:9000 \
  --download-port 443 \
  --transport-mode obfs \
  --obfs-key YOUR_KEY_HERE
```
</details>

<details>
<summary><code>▶ IP SPOOF mode</code></summary>

```bash
# Requires root + CAP_NET_RAW
# Server sends UDP downloads with fake source IP

sudo ./bin/server \
  --listen-addr 0.0.0.0:9000 \
  --download-src-port 9001 \
  --spoof-ip 94.130.50.12 \
  --spoof-interface eth0
  # --spoof-gateway auto-detected from /proc/net/route
```
</details>

---

### `▸` CLI Reference

<details>
<summary><b>Client flags</b></summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | — | JSON config file path |
| `--server` | — | Server address `IP:port` |
| `--upload-proxy` | `:10808` | Local SOCKS5 for upload |
| `--local-socks` | `:1080` | SOCKS5 listener for browser |
| `--download-port` | `8000` | UDP download port |
| `--my-public-ip` | auto | Your public IP |
| `--transport-mode` | `udp` | `udp` or `obfs` |
| `--obfs-key` | — | 64-char hex key |
| `--max-connections` | `512` | Max concurrent streams |
| `--metrics-addr` | `:9091` | Metrics HTTP |
| `--gen-config` | — | Write example `client.json` |
| `--gen-key` | — | Generate random obfs key |
| `-v` | — | Verbose logs |

</details>

<details>
<summary><b>Server flags</b></summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | — | JSON config file path |
| `--listen-addr` | `:9000` | TCP listen address |
| `--download-src-port` | `9001` | UDP source port |
| `--transport-mode` | `udp` | `udp` or `obfs` |
| `--obfs-key` | — | 64-char hex key |
| `--spoof-ip` | — | Fake UDP source IP |
| `--spoof-interface` | auto | Network interface |
| `--spoof-gateway` | auto | Gateway for ARP |
| `--max-clients` | `1000` | Max clients |
| `--metrics-addr` | `:9090` | Metrics HTTP |
| `--gen-config` | — | Write example `server.json` |
| `--gen-key` | — | Generate random obfs key |
| `-v` | — | Verbose logs |

</details>

---

### `▸` Metrics

```bash
curl http://127.0.0.1:9090/metrics | python3 -m json.tool
```

```json
{
  "uptime_sec":          3600,
  "active_streams":      42,
  "active_clients":      8,
  "total_streams":       1024,
  "upload_bytes":        52428800,
  "download_bytes":      524288000,
  "dial_errors":         0,
  "reassembly_drops":    0,
  "flow_acks_sent":      32768,
  "flow_acks_received":  32768
}
```

---

## `// 🇮🇷` مستندات فارسی

```
┌──────────────────────────────────────────────────────────────────┐
│  معماری سیستم                                                     │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  مرورگر ──SOCKS5──▶ کلاینت ──TCP──▶ xray ──TCP──▶ سرور ──▶ 🌍  │
│                                              │                    │
│              کلاینت ◀──── UDP + Spoof ───────┘                   │
│                                                                   │
│  آپلود:   TCP از طریق پروکسی محلی (دور زدن فیلتر)               │
│  دانلود:  UDP مستقیم از VPS  (IP Spoof اختیاری)                 │
└──────────────────────────────────────────────────────────────────┘
```

### `▸` چرا QS-Tunnel؟

در سیستم‌های معمول، آپلود و دانلود از **یک مسیر** رد می‌شوند. QS-Tunnel این دو را **کاملاً جدا** می‌کند:

```
حالت معمولی:   مرورگر → proxy → سرور → مقصد → سرور → proxy → مرورگر
                              [همه چیز از یک مسیر]

QS-Tunnel:       آپلود  → xray → سرور → مقصد
                دانلود ←────── UDP مستقیم ──────
                              [مسیر جداگانه، سریع‌تر]
```

### `▸` جدول ویژگی‌ها

```
┌──────────────────────────┬──────────────────────────────────────┐
│ ویژگی                    │ توضیح                                │
├──────────────────────────┼──────────────────────────────────────┤
│ مسیر آپلود جداگانه       │ TCP از xray/v2ray                   │
│ مسیر دانلود جداگانه      │ UDP مستقیم از سرور                  │
│ IP Spoof                 │ AF_PACKET raw socket                 │
│ حالت Obfs                │ AES-256-GCM شبیه QUIC/HTTPS         │
│ اتصال مجدد خودکار        │ TCP قطع شد؟ stream‌ها زنده می‌مانند │
│ تشخیص خودکار IP          │ بدون نیاز به تنظیم دستی             │
│ Config JSON + Flag       │ اولویت‌بندی هوشمند                  │
│ کلید تصادفی              │ --gen-key → 32 بایت رمزنگاری        │
│ متریک HTTP               │ /metrics JSON در realtime           │
└──────────────────────────┴──────────────────────────────────────┘
```

### `▸` شروع سریع

```bash
# ساخت
git clone https://github.com/Qteam-official/QS-Tunnel
cd QS-Tunnel
go build -o bin/server ./cmd/server
go build -o bin/client ./cmd/client

# ساخت کلید obfs (یک بار — در هر دو config بذار)
./bin/client --gen-key

# ساخت فایل‌های config
./bin/server --gen-config   # → server.json
./bin/client --gen-config   # → client.json

# اجرای سرور (روی VPS)
sudo ./bin/server --config server.json

# اجرای کلاینت
./bin/client --config client.json

# تنظیم مرورگر: proxy → SOCKS5 → 127.0.0.1:1080
```

### `▸` اولویت‌بندی تنظیمات

```
flag صریح   ◀── بالاترین اولویت
config.json ◀── میانی
auto-detect ◀── هوشمند (IP، gateway، interface)
default     ◀── پایین‌ترین
```

```bash
# config + override با flag
./bin/client --config client.json --v --server NEW_IP:9000
```

### `▸` نیازمندی‌ها

```
• Go 1.21 به بالا
• Linux (برای IP spoof: root یا CAP_NET_RAW)
• VPS با IP عمومی
• xray/v2ray/sing-box روی کلاینت (برای آپلود)
```

---

<div align="center">

```
╔══════════════════════════════════════════════════════════╗
║              ارتباط با ما / Contact                      ║
╚══════════════════════════════════════════════════════════╝
```

[![Telegram](https://img.shields.io/badge/Telegram-@Q_teams-2CA5E0?style=for-the-badge&labelColor=020510&logo=telegram)](https://t.me/Q_teams)
[![YouTube](https://img.shields.io/badge/Youtube-@Q-TEAM-official-FF0000?style=for-the-badge&labelColor=020510&logo=youtube)](https://youtube.com/@Q-TEAM-official)
[![Issues](https://img.shields.io/badge/GitHub_Issues-bf5fff?style=for-the-badge&labelColor=020510&logo=github)](https://github.com/Qteam-official/QS-Tunnel/issues)

<br/>

```
[ ⭐ اگه پروژه مفید بود، ستاره بدید ! / Star if useful! ⭐ ]
```

```
MIT License — free to use, modify, and distribute
```

</div>
