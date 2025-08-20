#!/bin/bash

# paping C version - All-in-one installer
# Usage: curl -fsSL https://raw.githubusercontent.com/Dolyyyy/linux_paping/main/install.sh | sudo bash

set -e

echo "🚀 Installing paping C version..."

# Check if gcc is available
if ! command -v gcc &> /dev/null; then
    echo "❌ Error: gcc is required but not installed"
    echo "Install with: sudo apt-get install gcc (Debian/Ubuntu) or sudo yum install gcc (RHEL/CentOS)"
    exit 1
fi

# Create temporary directory
TMPDIR=$(mktemp -d)
cd "$TMPDIR"

# Download source code
echo "📥 Downloading source..."
curl -fsSL https://raw.githubusercontent.com/Dolyyyy/linux_paping/main/paping.c -o paping.c

# Compile
echo "🔨 Compiling..."
gcc -O2 -Wall -Wextra -std=c99 -static -o paping paping.c

# Install
echo "📦 Installing..."
sudo cp paping /usr/bin/
sudo chmod +x /usr/bin/paping

# Cleanup
cd /
rm -rf "$TMPDIR"

echo "✅ paping C version installed successfully!"
echo ""
echo "Usage examples:"
echo "  sudo paping 8.8.8.8                    # ICMP ping"
echo "  paping 8.8.8.8 -p 443                  # TCP ping"
echo "  paping 8.8.8.8 -p 53 -u                # UDP ping"
echo "  paping 8.8.8.8 -p 443 -c 5 -i 0.5     # 5 pings with 0.5s interval"
