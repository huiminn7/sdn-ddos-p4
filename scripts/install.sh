#!/bin/bash

echo "========================================"
echo "     Installing DDoS Project Tools      "
echo "========================================"

# Update package list
sudo apt-get update

# Install hping3 for SYN flood attacks
echo "📦 Installing hping3..."
sudo apt-get install -y hping3

# Install additional tools
echo "📦 Installing other tools..."
sudo apt-get install -y tcpdump iperf3

# Install Python dependencies
echo "📦 Installing Python packages..."
pip3 install scapy

# Check if simple_switch is installed
if ! command -v simple_switch &> /dev/null; then
    echo "⚠️  BMv2 (simple_switch) not found!"
    echo "Please install P4 tools first:"
    echo "  cd ~/p4-tutorials/tutorials/exercises/basic"
    echo "  make deps"
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "  1. ./scripts/compile.sh  (compile P4 program)"
echo "  2. ./scripts/run.sh      (start Mininet)"
