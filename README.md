# paping - High Performance Network Ping Tool

High-performance C version of the network ping tool.

## 🚀 Installation

Single command:

```bash
curl -fsSL "https://raw.githubusercontent.com/Dolyyyy/linux_paping/main/install.sh?t=$(date +%s)" | sudo bash
```

## 🛠️ Usage

```bash
paping 8.8.8.8              # ICMP ping (no sudo needed)
paping 8.8.8.8 -p 443        # TCP ping
paping 8.8.8.8 -p 53 -u      # UDP ping
paping 8.8.8.8 -p 443 -c 5   # 5 TCP pings
```

## 📋 Options

```
-p, --port PORT     Port number (enables TCP mode)
-u, --udp           Use UDP instead of TCP
-c, --count COUNT   Number of probes (default: infinite)
-i, --interval SEC  Interval between probes (default: 1.0)
-t, --timeout SEC   Timeout in seconds (default: 3.0)
-h, --help          Show help
```

## ⚡ Features

- **Faster** than Python version
- **Instant installation** - no compilation needed
- **Multi-architecture support** - x86_64, ARM64, ARM32
- **ICMP without root** - thanks to Linux capabilities
- **Same interface** as original
- **No dependencies** - static binary
- **No gcc needed** - downloads binary directly
