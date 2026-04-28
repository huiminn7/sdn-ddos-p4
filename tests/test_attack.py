#!/usr/bin/env python3
"""
Test script for DDoS attack simulation
Run this from within Mininet CLI
"""

def test_normal_traffic():
    """Test normal ping between hosts"""
    print("\n📡 Testing normal traffic...")
    print("In Mininet, run: victim ping normal -c 5")

def test_syn_flood():
    """Test SYN flood attack"""
    print("\n🔥 Testing SYN flood attack...")
    print("In Mininet, run: attacker1 hping3 -S --flood victim")

def test_add_block_rule():
    """Add block rule in BMv2 CLI"""
    print("\n🔒 Adding block rule...")
    print("In another terminal, run:")
    print("  simple_switch_CLI --thrift-port 9090")
    print("  table_add ddos_table drop 10.0.0.1")

def test_check_counters():
    """Check packet counters"""
    print("\n📊 Checking counters...")
    print("In BMv2 CLI:")
    print("  table_dump ddos_table")
    print("  counter_read ddos_table")

if __name__ == "__main__":
    print("\n" + "="*50)
    print("DDoS Test Commands Reference")
    print("="*50)
    test_normal_traffic()
    test_syn_flood()
    test_add_block_rule()
    test_check_counters()
