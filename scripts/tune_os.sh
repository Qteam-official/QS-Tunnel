#!/bin/bash
# تنظیم OS برای هزاران connection همزمان
# روی سرور اجرا کن: sudo bash tune_os.sh

echo "── تنظیم OS ──"

# file descriptors
ulimit -n 1000000
sysctl -w fs.file-max=1000000

# TCP
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sysctl -w net.ipv4.tcp_fin_timeout=15
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# UDP buffer بزرگ (برای هزاران stream)
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728
sysctl -w net.core.rmem_default=4194304
sysctl -w net.core.wmem_default=4194304

echo "✅ OS tuned for high concurrency"
