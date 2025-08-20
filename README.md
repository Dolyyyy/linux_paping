# paping - High Performance Network Ping Tool

Version C haute performance de l'outil de ping réseau.

## 🚀 Installation

Une seule commande :

```bash
curl -fsSL "https://raw.githubusercontent.com/Dolyyyy/linux_paping/main/install.sh?t=$(date +%s)" | sudo bash
```

## 🛠️ Utilisation

```bash
paping 8.8.8.8              # ICMP ping (sans sudo)
paping 8.8.8.8 -p 443        # TCP ping
paping 8.8.8.8 -p 53 -u      # UDP ping
paping 8.8.8.8 -p 443 -c 5   # 5 pings TCP
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

## ⚡ Avantages

- **Plus rapide** que la version Python
- **Installation instantanée** - pas de compilation
- **Support multi-architecture** - x86_64, ARM64, ARM32
- **ICMP sans root** - grâce aux capabilities Linux
- **Même interface** que l'original
- **Pas de dépendances** - binaire statique
- **Pas besoin de gcc** - télécharge directement le binaire
