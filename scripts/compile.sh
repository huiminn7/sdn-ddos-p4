#!/bin/bash
set -e

cd ~/testing/p4/ddos

echo "🔨 Compiling P4 program..."
p4c-bm2-ss -o p4/ddos_detect.json --p4runtime-files p4/p4info.txt p4/ddos_detect.p4

if [ $? -eq 0 ]; then
    echo "✅ Compilation successful!"
    ls -la p4/ddos_detect.json p4/p4info.txt
else
    echo "❌ Compilation failed"
    exit 1
fi
