#!/usr/bin/env python3

import os
import csv
import time
import subprocess
from datetime import datetime

import pandas as pd
import joblib

# =========================
# Configuration
# =========================
INTERVAL = 1
THRESHOLD_PPS = 30
THRESHOLD_BPS = 50000
THRIFT_PORT = 9090
VICTIM_IP = "10.0.0.100"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "..", "dataset")
MODEL_DIR = os.path.join(BASE_DIR, "..", "models")

CSV_FILE = os.path.join(DATASET_DIR, "traffic_log.csv")
MODEL_PATH = os.path.join(MODEL_DIR, "ddos_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

FEATURE_COLUMNS = [
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "syn_count",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
]

PORTS = {
    "s1-eth1": ("host1", "10.0.0.1"),
    "s1-eth2": ("host2", "10.0.0.2"),
    "s1-eth3": ("host3", "10.0.0.3"),
    "s1-eth4": ("host4", "10.0.0.100"),
}

blocked = set()


# =========================
# Basic helpers
# =========================
def sh(cmd):
    return subprocess.getoutput(cmd)


def safe_int(value):
    try:
        return int(str(value).strip())
    except ValueError:
        return 0


# =========================
# Load ML model
# =========================
def load_ml_model():
    if not os.path.exists(MODEL_PATH):
        print(f"⚠️  ML model not found: {MODEL_PATH}")
        print("⚠️  Controller will use rule-based detection only.")
        return None, None

    if not os.path.exists(SCALER_PATH):
        print(f"⚠️  Scaler not found: {SCALER_PATH}")
        print("⚠️  Controller will use rule-based detection only.")
        return None, None

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    print("✔ ML model loaded successfully")
    print(f"  Model : {MODEL_PATH}")
    print(f"  Scaler: {SCALER_PATH}")

    return model, scaler


# =========================
# Interface counter method
# =========================
def read_counter(interface, counter):
    path = f"/sys/class/net/{interface}/statistics/{counter}"

    try:
        with open(path, "r") as f:
            return int(f.read().strip())
    except Exception:
        return 0


def get_port_stats(interface):
    return {
        "rx_packets": read_counter(interface, "rx_packets"),
        "rx_bytes": read_counter(interface, "rx_bytes"),
        "tx_packets": read_counter(interface, "tx_packets"),
        "tx_bytes": read_counter(interface, "tx_bytes"),
    }


# =========================
# Protocol counting
# =========================
def count_tcp(interface):
    cmd = f"sudo timeout {INTERVAL} tcpdump -i {interface} -nn -q 'ip dst {VICTIM_IP} and tcp' 2>/dev/null | wc -l"
    return safe_int(sh(cmd))


def count_udp(interface):
    cmd = f"sudo timeout {INTERVAL} tcpdump -i {interface} -nn -q 'ip dst {VICTIM_IP} and udp' 2>/dev/null | wc -l"
    return safe_int(sh(cmd))


def count_icmp(interface):
    cmd = f"sudo timeout {INTERVAL} tcpdump -i {interface} -nn -q 'ip dst {VICTIM_IP} and icmp' 2>/dev/null | wc -l"
    return safe_int(sh(cmd))


def count_syn(interface):
    cmd = f"sudo timeout {INTERVAL} tcpdump -i {interface} -nn -q 'ip dst {VICTIM_IP} and tcp[tcpflags] & tcp-syn != 0' 2>/dev/null | wc -l"
    return safe_int(sh(cmd))


def get_protocol_features(interface):
    tcp_count = count_tcp(interface)
    udp_count = count_udp(interface)
    icmp_count = count_icmp(interface)
    syn_count = count_syn(interface)

    proto_total = tcp_count + udp_count + icmp_count

    if proto_total == 0:
        tcp_ratio = udp_ratio = icmp_ratio = 0
    else:
        tcp_ratio = tcp_count / proto_total
        udp_ratio = udp_count / proto_total
        icmp_ratio = icmp_count / proto_total

    return {
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "icmp_count": icmp_count,
        "syn_count": syn_count,
        "tcp_ratio": round(tcp_ratio, 3),
        "udp_ratio": round(udp_ratio, 3),
        "icmp_ratio": round(icmp_ratio, 3),
    }


# =========================
# ML prediction
# =========================
def predict_attack_type(model, scaler, packet_rate, byte_rate, avg_packet_size, proto):
    if model is None or scaler is None:
        return None

    data = pd.DataFrame([{
        "packet_rate": packet_rate,
        "byte_rate": byte_rate,
        "avg_packet_size": avg_packet_size,
        "tcp_count": proto["tcp_count"],
        "udp_count": proto["udp_count"],
        "icmp_count": proto["icmp_count"],
        "syn_count": proto["syn_count"],
        "tcp_ratio": proto["tcp_ratio"],
        "udp_ratio": proto["udp_ratio"],
        "icmp_ratio": proto["icmp_ratio"],
    }], columns=FEATURE_COLUMNS)

    data_scaled = scaler.transform(data)
    prediction = model.predict(data_scaled)[0]

    return prediction


# =========================
# CSV logging
# =========================
def init_csv():
    os.makedirs(DATASET_DIR, exist_ok=True)

    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "interface",
                "host_name",
                "src_ip",
                "packet_rate",
                "byte_rate",
                "avg_packet_size",
                "tcp_count",
                "udp_count",
                "icmp_count",
                "syn_count",
                "tcp_ratio",
                "udp_ratio",
                "icmp_ratio",
                "severity",
                "attack_type",
                "action",
                "is_blocked",
                "label",
                "detector"
            ])


def log_to_csv(interface, name, ip, packet_rate, byte_rate, avg_packet_size,
               proto, severity, attack_type, action, label, detector):
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            interface,
            name,
            ip,
            packet_rate,
            byte_rate,
            avg_packet_size,
            proto["tcp_count"],
            proto["udp_count"],
            proto["icmp_count"],
            proto["syn_count"],
            proto["tcp_ratio"],
            proto["udp_ratio"],
            proto["icmp_ratio"],
            severity,
            attack_type,
            action,
            1 if ip in blocked else 0,
            label,
            detector
        ])


# =========================
# Agentic decision logic
# =========================
def classify_severity(packet_rate, byte_rate):
    if packet_rate <= THRESHOLD_PPS and byte_rate <= THRESHOLD_BPS:
        return "normal"
    elif packet_rate <= THRESHOLD_PPS * 3:
        return "low"
    elif packet_rate <= THRESHOLD_PPS * 10:
        return "medium"
    else:
        return "high"


def classify_attack_type_rule(severity, proto):
    if severity == "normal":
        return "normal"

    if proto["syn_count"] > 0 and proto["tcp_ratio"] >= 0.5:
        return "tcp_syn_flood"

    if proto["udp_ratio"] >= 0.6:
        return "udp_flood"

    if proto["icmp_ratio"] >= 0.6:
        return "icmp_flood"

    if proto["tcp_ratio"] >= 0.6:
        return "tcp_flood"

    return "mixed_or_unknown"


def decide_action(severity, attack_type):
    if attack_type == "normal" or severity == "normal":
        return "allow"

    if severity == "low":
        return "monitor"

    if severity == "medium":
        return "alert"

    if severity == "high":
        return "block"

    return "allow"


# =========================
# P4 mitigation action
# =========================
def block_ip(ip, name):
    if ip in blocked:
        return False

    print(f"🚫 Blocking {name} ({ip})")

    cmd = (
        f'echo "table_add MyIngress.ddos_table drop {ip} =>" '
        f"| simple_switch_CLI --thrift-port {THRIFT_PORT} >/dev/null 2>&1"
    )

    sh(cmd)
    blocked.add(ip)
    return True


# =========================
# Display
# =========================
def print_startup():
    print("========================================")
    print(" Agentic AI SDN DDoS Monitor")
    print("========================================")
    print(f"Interval      : {INTERVAL}s")
    print(f"PPS Threshold : {THRESHOLD_PPS} pkt/s")
    print(f"BPS Threshold : {THRESHOLD_BPS} bytes/s")
    print(f"Victim IP     : {VICTIM_IP}")
    print(f"CSV Log       : {CSV_FILE}")
    print("Method        : interface counter + protocol filter + ML model")
    print("Detection     : ML first, rule-based fallback")
    print("========================================\n")


# =========================
# Main loop
# =========================
def main():
    init_csv()
    print_startup()

    model, scaler = load_ml_model()

    previous = {}

    for intf in PORTS:
        previous[intf] = get_port_stats(intf)

    try:
        while True:
            time.sleep(INTERVAL)
            print("\n--- Traffic Report ---")

            for intf, (name, ip) in PORTS.items():
                current = get_port_stats(intf)
                prev = previous[intf]

                packet_rate = max(0, current["rx_packets"] - prev["rx_packets"])
                byte_rate = max(0, current["rx_bytes"] - prev["rx_bytes"])
                avg_packet_size = round(byte_rate / packet_rate, 2) if packet_rate > 0 else 0

                previous[intf] = current

                proto = get_protocol_features(intf)

                # Step 1: severity still based on live traffic intensity
                severity = classify_severity(packet_rate, byte_rate)

                # Step 2: ML predicts attack type
                ml_attack_type = predict_attack_type(
                    model,
                    scaler,
                    packet_rate,
                    byte_rate,
                    avg_packet_size,
                    proto
                )

                # Step 3: fallback if ML unavailable
                if ml_attack_type is None:
                    attack_type = classify_attack_type_rule(severity, proto)
                    detector = "rule"
                else:
                    attack_type = ml_attack_type
                    detector = "ml"

                # Step 4: safety override
                # If ML says attack but traffic is basically idle, keep it normal.
                if packet_rate == 0 and byte_rate == 0:
                    severity = "normal"
                    attack_type = "normal"

                # If ML says normal but traffic is very high, do not ignore it.
                if attack_type == "normal" and severity in ["medium", "high"]:
                    attack_type = classify_attack_type_rule(severity, proto)
                    detector = detector + "+rule_override"

                action = decide_action(severity, attack_type)
                label = "normal" if attack_type == "normal" else "attack"

                print(
                    f"{name:8s} ({ip:12s}) via {intf:7s}: "
                    f"{packet_rate:7d} pkt/s | "
                    f"{byte_rate:9d} B/s | "
                    f"TCP:{proto['tcp_count']:5d} "
                    f"UDP:{proto['udp_count']:5d} "
                    f"ICMP:{proto['icmp_count']:5d} "
                    f"SYN:{proto['syn_count']:5d} | "
                    f"severity={severity:6s} | "
                    f"type={attack_type:15s} | "
                    f"action={action:7s} | "
                    f"detector={detector}"
                )

                if action == "block":
                    if ip not in blocked:
                        print(f"⚠️  High severity {attack_type} detected from {name} ({ip})")
                        block_ip(ip, name)
                    else:
                        print(f"✅ {name} ({ip}) already blocked")

                log_to_csv(
                    intf,
                    name,
                    ip,
                    packet_rate,
                    byte_rate,
                    avg_packet_size,
                    proto,
                    severity,
                    attack_type,
                    action,
                    label,
                    detector
                )

    except KeyboardInterrupt:
        print("\n\n🛑 Stopping controller gracefully...")
        print(f"✔ Data saved to: {CSV_FILE}")
        print(f"✔ Total blocked hosts: {len(blocked)}")
        print("✔ Exiting cleanly\n")


if __name__ == "__main__":
    main()
