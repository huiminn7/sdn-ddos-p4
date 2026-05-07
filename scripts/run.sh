#!/bin/bash
set -e

cd ~/testing/p4/ddos

TOPO_CONFIG_FILE="config/topology_3switch.json"
STATIC_FORWARDING_VALUE="0"
RUN_TRAFFIC="1"

clear
echo "========================================"
echo "   DDoS Detection with P4 + BMv2 Switch"
echo "========================================"
echo ""

echo "Topology config    : $TOPO_CONFIG_FILE"
echo "Static forwarding  : $STATIC_FORWARDING_VALUE"
echo ""

echo "[1/4] Cleaning old processes..."
sudo pkill -f simple_switch 2>/dev/null || true
sudo pkill -f p4runtime_controller.py 2>/dev/null || true
sudo pkill -f install_forwarding_p4runtime.py 2>/dev/null || true
sudo mn -c >/tmp/mininet-cleanup.log 2>&1 || true
echo "      Cleanup complete"

echo ""
echo "[2/4] Compiling P4 program..."
./scripts/compile.sh

echo ""
echo "[3/4] Starting Mininet + BMv2 3-switch topology..."
sudo env TOPO_CONFIG="$TOPO_CONFIG_FILE" STATIC_FORWARDING="$STATIC_FORWARDING_VALUE" RUN_TRAFFIC="$RUN_TRAFFIC" python3 mininet/topology.py

echo ""
echo "[4/4] Finished"
