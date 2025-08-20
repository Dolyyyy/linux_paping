#!/bin/bash

# paping C version - Multi-architecture installer
# Usage: curl -fsSL https://raw.githubusercontent.com/Dolyyyy/linux_paping/main/install.sh | sudo bash

set -e

echo "🚀 Installing paping C version..."

# Detect architecture and select appropriate binary
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        BINARY="paping-x86_64"
        ;;
    aarch64|arm64)
        BINARY="paping-aarch64"
        ;;
    armv7l|armv6l|arm)
        BINARY="paping-arm"
        ;;
    *)
        echo "❌ Error: Unsupported architecture: $ARCH"
        echo "Supported architectures: x86_64, aarch64, arm"
        exit 1
        ;;
esac

echo "📥 Downloading binary for $ARCH..."

# Download binary directly (with timestamp to avoid cache)
curl -fsSL "https://raw.githubusercontent.com/Dolyyyy/linux_paping/main/binaries/$BINARY?t=$(date +%s)" -o /tmp/paping

# Make executable and install
chmod +x /tmp/paping
sudo cp /tmp/paping /usr/bin/paping

# Set capabilities for ICMP without root
echo "🔧 Setting capabilities for ICMP without root..."
sudo setcap cap_net_raw+ep /usr/bin/paping

# Cleanup
rm -f /tmp/paping

echo "✅ paping C version installed successfully!"
echo ""
echo "Usage examples:"
echo "  paping 8.8.8.8                    # ICMP ping (sans sudo)"
echo "  paping 8.8.8.8 -p 443                  # TCP ping"
echo "  paping 8.8.8.8 -p 53 -u                # UDP ping"
echo "  paping 8.8.8.8 -p 443 -c 5 -i 0.5     # 5 pings with 0.5s interval"
