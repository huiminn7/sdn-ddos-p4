#!/bin/bash
set -e

cd ~/testing/p4/ddos
TOPO_CONFIG_FILE=${1:-config/topology_single.json}

clear
echo "========================================"
echo "   DDoS Detection with P4 + BMv2 Switch"
echo "========================================"
echo ""

echo "[1/4] Cleaning old processes..."
sudo pkill -f simple_switch 2>/dev/null || true
sudo mn -c >/tmp/mininet-cleanup.log 2>&1 || true
echo "      Cleanup complete"

echo ""
echo "[2/4] Compiling P4 program..."
./scripts/compile.sh

echo ""
echo "[3/4] Starting Mininet + BMv2 switch..."
#sudo python3 mininet/topology.py
#sudo env TOPO_CONFIG="$TOPO_CONFIG_FILE" python3 mininet/topology.py
sudo env TOPO_CONFIG=config/topology_3switch.json python3 mininet/topology.py



echo ""
echo "[4/4] Finished"
