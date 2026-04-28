#!/bin/bash

echo "🧹 Cleaning up..."

# Kill BMv2 processes
sudo pkill -f simple_switch 2>/dev/null

# Kill Mininet
sudo mn -c 2>/dev/null


for i in 1 2 3 4; do
    sudo ip link del s1-eth$i 2>/dev/null
done

# Remove log files
rm -f /tmp/s1.log 2>/dev/null

echo "✅ Cleanup complete"

