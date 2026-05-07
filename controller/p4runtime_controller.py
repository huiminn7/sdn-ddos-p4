#!/usr/bin/env python3

import os
os.environ["GRPC_ENABLE_FORK_SUPPORT"] = "0"

import sys
import time
import json
import logging
import ipaddress
import threading

BASE_DIR = "/home/huimin/testing/p4/ddos"

LOCAL_LIB = os.path.join(BASE_DIR, "lib")
if os.path.isdir(os.path.join(LOCAL_LIB, "p4runtime_lib")):
    sys.path.insert(0, LOCAL_LIB)
else:
    sys.path.append("/home/huimin/tutorials/utils")

from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.bmv2 as bmv2
import p4runtime_lib.helper as helper
from p4.v1 import p4runtime_pb2

# Local telemetry module.
# Put telemetry.py in the same folder as this controller file.
from telemetry import (
    TelemetryManager,
    ip_to_register_index,
    read_p4_register,
    reset_p4_register,
)


P4INFO_FILE = f"{BASE_DIR}/p4/p4info.txt"
BMV2_JSON_FILE = f"{BASE_DIR}/p4/ddos_detect.json"

LOG_FILE = f"{BASE_DIR}/logs/controller.log"
#CSV_FILE = f"{BASE_DIR}/dataset/traffic_log
CSV_FILE = f"{BASE_DIR}/experiments/interval_5s/traffic_log_5s.csv"

SYN_THRESHOLD = int(os.environ.get("SYN_THRESHOLD", "30"))
ACK_MIN_THRESHOLD = int(os.environ.get("ACK_MIN_THRESHOLD", "5"))
NORMAL_BASELINE_INTERVAL = float(os.environ.get("NORMAL_BASELINE_INTERVAL", "5"))
REG_SIZE = 1024

# observe  = data collection only, do NOT install drop rules
# enforce  = install drop rules when decision action is drop
MITIGATION_MODE = os.environ.get("MITIGATION_MODE", "observe").lower()

# For current 3-switch topology:
# attacker1/attacker2 are attached to s1, so detect/drop near the source.
MONITOR_SWITCHES = []

blocked = {}
switches = {}
topo_cfg = {}
telemetry = None


def load_topology_config():
    config_file = os.environ.get("TOPO_CONFIG", f"{BASE_DIR}/config/topology_single.json")

    if not config_file.startswith("/"):
        config_file = os.path.join(BASE_DIR, config_file)

    print(f"📄 Loading topology config: {config_file}")

    with open(config_file, "r") as f:
        return json.load(f)


def infer_monitor_switches(cfg):
    """
    Monitor all switches that have directly attached hosts.
    This allows telemetry collection from all edge/host-facing switches.
    """
    monitor = set()

    for host_name, host_cfg in cfg.get("hosts", {}).items():
        monitor.add(host_cfg["switch"])

    return sorted(monitor)


def setup_files():
    global telemetry

    telemetry = TelemetryManager(
        base_dir=BASE_DIR,
        log_file=LOG_FILE,
        csv_file=CSV_FILE,
    )
    telemetry.setup()


def log_event(event_type, **kwargs):
    """
    Wrapper so the rest of the controller can keep calling log_event(...)
    while the actual telemetry writing lives inside telemetry.py.
    """
    if telemetry is None:
        raise RuntimeError("TelemetryManager is not initialized. Call setup_files() first.")

    telemetry.log_event(event_type, **kwargs)


def bytes_to_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return int.from_bytes(value, byteorder="big")
    return int(value)


def int_to_ip(value):
    return str(ipaddress.IPv4Address(value))


def get_port_context(cfg, switch_name, ingress_port):
    """
    Map switch ingress port to topology context.

    Example:
    s1 port 1 -> host-facing port owned by attacker1
    s1 port 3 -> switch-facing port connected to s2 port 2
    """
    try:
        port = int(ingress_port)
    except Exception:
        return {
            "port_type": "unknown",
            "port_owner": "",
            "peer_switch": "",
            "peer_port": "",
        }

    # Host-facing port
    for host_name, host_cfg in cfg.get("hosts", {}).items():
        if host_cfg["switch"] == switch_name and int(host_cfg["switch_port"]) == port:
            return {
                "port_type": "host",
                "port_owner": host_name,
                "peer_switch": "",
                "peer_port": "",
            }

    # Switch-facing port
    for link in cfg.get("links", []):
        if link["node1"] == switch_name and int(link["port1"]) == port:
            return {
                "port_type": "switch",
                "port_owner": "",
                "peer_switch": link["node2"],
                "peer_port": link["port2"],
            }

        if link["node2"] == switch_name and int(link["port2"]) == port:
            return {
                "port_type": "switch",
                "port_owner": "",
                "peer_switch": link["node1"],
                "peer_port": link["port1"],
            }

    return {
        "port_type": "unknown",
        "port_owner": "",
        "peer_switch": "",
        "peer_port": "",
    }


def write_table_entry(p4info_helper, sw, table_name, match_fields, action_name, action_params):
    entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        action_name=action_name,
        action_params=action_params,
    )
    sw.WriteTableEntry(entry)


def agent_decide(
    event_type,
    src_ip="",
    dst_ip="unknown",
    syn_count=0,
    ack_count=0,
    switch_name="",
    ingress_port="",
    decision_source="agent_rule_based",
):
    try:
        syn = int(syn_count)
    except Exception:
        syn = 0

    try:
        ack = int(ack_count)
    except Exception:
        ack = 0

    key = (switch_name, src_ip)

    if key in blocked:
        return {
            "action": "skip_install",
            "severity": "HIGH",
            "label": "attack",
            "blocked_status": "already_blocked",
            "reason": "source_already_blocked",
        }

    if event_type == "digest_received":
        return {
            "action": "drop",
            "severity": "HIGH",
            "label": "attack",
            "blocked_status": "pending",
            "reason": "p4_digest_syn_high_ack_low",
        }

    if syn >= SYN_THRESHOLD and ack <= ACK_MIN_THRESHOLD:
        return {
            "action": "drop",
            "severity": "HIGH",
            "label": "attack",
            "blocked_status": "pending",
            "reason": "syn_high_ack_low",
        }

    if syn >= SYN_THRESHOLD and ack > ACK_MIN_THRESHOLD:
        return {
            "action": "monitor",
            "severity": "MEDIUM",
            "label": "suspicious",
            "blocked_status": "not_blocked",
            "reason": "syn_high_but_ack_present",
        }

    return {
        "action": "allow",
        "severity": "LOW",
        "label": "normal",
        "blocked_status": "allowed",
        "reason": "below_syn_threshold",
    }


def connect_switches(cfg, p4info_helper):
    connected = {}

    for sw_name, sw_cfg in cfg["switches"].items():
        grpc_port = sw_cfg["grpc_port"]
        device_id = sw_cfg["device_id"]

        print(f"🔌 Connecting to {sw_name}: device_id={device_id}, grpc=127.0.0.1:{grpc_port}")

        sw = bmv2.Bmv2SwitchConnection(
            name=sw_name,
            address=f"127.0.0.1:{grpc_port}",
            device_id=device_id,
            proto_dump_file=f"{BASE_DIR}/logs/{sw_name}-p4runtime-requests.txt",
        )

        sw.MasterArbitrationUpdate()

        sw.SetForwardingPipelineConfig(
            p4info=p4info_helper.p4info,
            bmv2_json_file_path=BMV2_JSON_FILE,
        )

        connected[sw_name] = sw
        print(f"✅ {sw_name}: pipeline installed")

    return connected


def install_forwarding_rules(cfg, p4info_helper):
    """
    Install MAC forwarding rules.

    Priority:
    1. Use cfg["forwarding"] if it exists.
    2. If not, auto-generate host-facing MAC forwarding from cfg["hosts"].

    This is useful because topology_single.json may only define hosts/switches/links,
    without a separate forwarding section.
    """

    forwarding = cfg.get("forwarding", {})

    # Auto-generate forwarding rules if "forwarding" section is missing
    if not forwarding:
        print("\n⚠️ No forwarding section found in topology config.")
        print("🔧 Auto-generating host MAC forwarding rules from hosts section...")

        forwarding = {}

        for host_name, host_cfg in cfg.get("hosts", {}).items():
            sw_name = host_cfg.get("switch")
            port = host_cfg.get("switch_port")

            # Try common MAC field names
            mac = (
                host_cfg.get("mac")
                or host_cfg.get("mac_addr")
                or host_cfg.get("mac_plain")
                or host_cfg.get("mac_address")
            )

            if not sw_name or port is None or not mac:
                print(f"⚠️ Skipping host {host_name}: missing switch/port/mac in config")
                continue

            forwarding.setdefault(sw_name, {})
            forwarding[sw_name][mac] = int(port)

            print(f"  inferred: {sw_name}: {mac} -> port {port} ({host_name})")

    if not forwarding:
        print("⚠️ No forwarding rules available. Skipping MAC rule installation.")
        print("⚠️ Connectivity may fail unless rules are installed elsewhere.")
        log_event(
            "forwarding_rules_skipped",
            switch_name="all",
            decision_source="controller_setup",
            action="skip_mac_rules",
            decision_reason="no_forwarding_rules_available",
        )
        return

    print("\n📌 Installing MAC forwarding rules via P4Runtime...")

    for sw_name, mac_rules in forwarding.items():
        if sw_name not in switches:
            print(f"⚠️ Switch {sw_name} not connected; skipping forwarding rules.")
            continue

        sw = switches[sw_name]

        for mac, port in mac_rules.items():
            write_table_entry(
                p4info_helper,
                sw,
                table_name="MyIngress.mac_table",
                match_fields={"h.ethernet.dst_addr": mac},
                action_name="MyIngress.forward",
                action_params={"port": int(port)},
            )

            print(f"  {sw_name}: {mac} -> port {port}")

    print("✅ Forwarding rules installed.\n")

    log_event(
        "forwarding_rules_installed",
        switch_name="all",
        decision_source="controller_setup",
        action="install_mac_rules",
    )


def get_digest_id(p4info_helper, digest_name="ddos_digest_t"):
    for digest in p4info_helper.p4info.digests:
        if digest.preamble.name == digest_name:
            return digest.preamble.id

    raise Exception(f"Digest '{digest_name}' not found in P4Info")


def enable_digest(p4info_helper, sw_name, sw, digest_name="ddos_digest_t"):
    digest_id = get_digest_id(p4info_helper, digest_name)
    device_id = topo_cfg["switches"][sw_name]["device_id"]

    req = p4runtime_pb2.WriteRequest()
    req.device_id = device_id
    req.election_id.high = 0
    req.election_id.low = 1

    update = req.updates.add()
    update.type = p4runtime_pb2.Update.INSERT

    digest_entry = update.entity.digest_entry
    digest_entry.digest_id = digest_id
    digest_entry.config.max_timeout_ns = 100000000
    digest_entry.config.max_list_size = 1
    digest_entry.config.ack_timeout_ns = 1000000000

    sw.client_stub.Write(req)

    print(f"✅ {sw_name}: Digest enabled: {digest_name} id={digest_id}")

    log_event(
        "digest_enabled",
        switch_name=sw_name,
        decision_source="controller_setup",
        action=f"digest_id={digest_id}",
    )


def send_digest_ack(sw, digest_list):
    req = p4runtime_pb2.StreamMessageRequest()
    req.digest_ack.digest_id = digest_list.digest_id
    req.digest_ack.list_id = digest_list.list_id
    sw.requests_stream.put(req)


def parse_ddos_digest(digest_data):
    members = digest_data.struct.members

    src_ip_int = bytes_to_int(members[0].bitstring)
    dst_ip_int = bytes_to_int(members[1].bitstring)
    syn_count = bytes_to_int(members[2].bitstring)
    ack_count = bytes_to_int(members[3].bitstring)
    ingress_port = bytes_to_int(members[4].bitstring)

    syn_ack_gap = max(syn_count - ack_count, 0)
    ack_ratio = round(ack_count / syn_count, 4) if syn_count > 0 else 1.0

    return {
        "src_ip": int_to_ip(src_ip_int),
        "dst_ip": int_to_ip(dst_ip_int),
        "syn_count": syn_count,
        "ack_count": ack_count,
        "syn_ack_gap": syn_ack_gap,
        "ack_ratio": ack_ratio,
        "ingress_port": ingress_port,
    }


def install_drop_rule(
    p4info_helper,
    sw_name,
    sw,
    ip,
    dst_ip="unknown",
    syn_count="",
    ack_count="",
    syn_ack_gap="",
    ack_ratio="",
    ingress_port="",
    port_type="",
    port_owner="",
    peer_switch="",
    peer_port="",
    decision_reason="syn_threshold_exceeded",
):
    key = (sw_name, ip)

    if key in blocked:
        blocked[key]["last_attack_time"] = time.time()

        log_event(
            "drop_rule_exists",
            switch_name=sw_name,
            src_ip=ip,
            dst_ip=dst_ip,
            syn_count=syn_count,
            ack_count=ack_count,
            syn_ack_gap=syn_ack_gap,
            ack_ratio=ack_ratio,
            ingress_port=ingress_port,
            port_type=port_type,
            port_owner=port_owner,
            peer_switch=peer_switch,
            peer_port=peer_port,
            threshold=SYN_THRESHOLD,
            decision_source="controller_policy",
            action="skip_install",
            severity="HIGH",
            label="attack",
            blocked_status="already_blocked",
            decision_reason="source_already_blocked",
        )
        return

    print(f"🚫 Installing DROP rule on {sw_name} for {ip}")

    write_table_entry(
        p4info_helper,
        sw,
        table_name="MyIngress.ddos_table",
        match_fields={"h.ipv4.src_addr": ip},
        action_name="MyIngress.drop",
        action_params={},
    )

    blocked[key] = {
        "installed_time": time.time(),
        "last_attack_time": time.time(),
    }

    log_event(
        "drop_rule_installed",
        switch_name=sw_name,
        src_ip=ip,
        dst_ip=dst_ip,
        syn_count=syn_count,
        ack_count=ack_count,
        syn_ack_gap=syn_ack_gap,
        ack_ratio=ack_ratio,
        ingress_port=ingress_port,
        port_type=port_type,
        port_owner=port_owner,
        peer_switch=peer_switch,
        peer_port=peer_port,
        threshold=SYN_THRESHOLD,
        decision_source="controller_policy",
        action="drop",
        severity="HIGH",
        label="attack",
        blocked_status="blocked",
        decision_reason=decision_reason,
    )


def handle_drop_decision(
    p4info_helper,
    sw_name,
    sw,
    src_ip,
    dst_ip,
    syn_count,
    ack_count,
    syn_ack_gap,
    ack_ratio,
    ingress_port,
    port_ctx,
    decision,
):
    """
    Central place to choose observe vs enforce mode.

    observe mode:
        log that the system WOULD drop, but do not install drop rule.
    enforce mode:
        install drop rule into MyIngress.ddos_table.
    """
    if decision["action"] != "drop":
        return

    if MITIGATION_MODE == "enforce":
        install_drop_rule(
            p4info_helper,
            sw_name,
            sw,
            src_ip,
            dst_ip=dst_ip,
            syn_count=syn_count,
            ack_count=ack_count,
            syn_ack_gap=syn_ack_gap,
            ack_ratio=ack_ratio,
            ingress_port=ingress_port,
            port_type=port_ctx["port_type"],
            port_owner=port_ctx["port_owner"],
            peer_switch=port_ctx["peer_switch"],
            peer_port=port_ctx["peer_port"],
            decision_reason=decision["reason"],
        )
        return

    print(f"👀 OBSERVE MODE: drop decision for {src_ip}, but drop rule is NOT installed")

    log_event(
        "drop_rule_skipped_observe_mode",
        switch_name=sw_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        syn_count=syn_count,
        ack_count=ack_count,
        syn_ack_gap=syn_ack_gap,
        ack_ratio=ack_ratio,
        ingress_port=ingress_port,
        port_type=port_ctx["port_type"],
        port_owner=port_ctx["port_owner"],
        peer_switch=port_ctx["peer_switch"],
        peer_port=port_ctx["peer_port"],
        threshold=SYN_THRESHOLD,
        decision_source="controller_policy",
        action="observe_only",
        severity=decision["severity"],
        label=decision["label"],
        blocked_status="not_blocked",
        decision_reason="drop_decision_detected_but_mitigation_mode_observe",
    )


def monitor_digest(p4info_helper, sw_name, sw):
    print(f"🚀 {sw_name}: Waiting for P4 digest events...")

    while True:
        try:
            digest_list = sw.DigestList()

            for data in digest_list.data:
                d = parse_ddos_digest(data)

                src_ip = d["src_ip"]
                dst_ip = d["dst_ip"]
                syn_count = d["syn_count"]
                ack_count = d["ack_count"]
                syn_ack_gap = d["syn_ack_gap"]
                ack_ratio = d["ack_ratio"]
                ingress_port = d["ingress_port"]
                port_ctx = get_port_context(topo_cfg, sw_name, ingress_port)

                decision = agent_decide(
                    event_type="digest_received",
                    switch_name=sw_name,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    syn_count=syn_count,
                    ack_count=ack_count,
                    ingress_port=ingress_port,
                    decision_source="p4_data_plane",
                )

                log_event(
                    "digest_received",
                    switch_name=sw_name,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    syn_count=syn_count,
                    ack_count=ack_count,
                    syn_ack_gap=syn_ack_gap,
                    ack_ratio=ack_ratio,
                    ingress_port=ingress_port,
                    port_type=port_ctx["port_type"],
                    port_owner=port_ctx["port_owner"],
                    peer_switch=port_ctx["peer_switch"],
                    peer_port=port_ctx["peer_port"],
                    threshold=SYN_THRESHOLD,
                    decision_source="agent_rule_based",
                    action=decision["action"],
                    severity=decision["severity"],
                    label=decision["label"],
                    blocked_status=decision["blocked_status"],
                    decision_reason=decision["reason"],
                )

                handle_drop_decision(
                    p4info_helper,
                    sw_name,
                    sw,
                    src_ip,
                    dst_ip,
                    syn_count,
                    ack_count,
                    syn_ack_gap,
                    ack_ratio,
                    ingress_port,
                    port_ctx,
                    decision,
                )

            send_digest_ack(sw, digest_list)

        except Exception as e:
            print(f"❌ {sw_name}: Digest/controller error: {repr(e)}")
            logging.exception(e)
            time.sleep(1)


def baseline_logger_for_switch(p4info_helper, sw_name, sw):
    thrift_port = topo_cfg["switches"][sw_name]["thrift_port"]

    # Only monitor hosts attached to this switch.
    attached_hosts = {
        hname: hcfg
        for hname, hcfg in topo_cfg["hosts"].items()
        if hcfg["switch"] == sw_name
    }

    print(f"📊 {sw_name}: Baseline telemetry for hosts: {list(attached_hosts.keys())}")
    print(f"📊 {sw_name}: Baseline interval = {NORMAL_BASELINE_INTERVAL}s")

    while True:
        time.sleep(NORMAL_BASELINE_INTERVAL)

        for hname, hcfg in attached_hosts.items():
            ip = hcfg["ip_plain"]
            index = ip_to_register_index(ip, REG_SIZE)

            syn_count = read_p4_register(thrift_port, "syn_counter", index)
            ack_count = read_p4_register(thrift_port, "ack_counter", index)

            if syn_count is None or ack_count is None:
                continue

            syn_ack_gap = max(syn_count - ack_count, 0)
            ack_ratio = round(ack_count / syn_count, 4) if syn_count > 0 else 1.0

            decision = agent_decide(
                event_type="baseline_counter",
                switch_name=sw_name,
                src_ip=ip,
                dst_ip="unknown",
                syn_count=syn_count,
                ack_count=ack_count,
                ingress_port=hcfg["switch_port"],
                decision_source="p4_register_polling",
            )

            port_ctx = get_port_context(topo_cfg, sw_name, hcfg["switch_port"])

            log_event(
                "baseline_counter",
                switch_name=sw_name,
                src_ip=ip,
                dst_ip="unknown",
                syn_count=syn_count,
                ack_count=ack_count,
                syn_ack_gap=syn_ack_gap,
                ack_ratio=ack_ratio,
                ingress_port=hcfg["switch_port"],
                port_type=port_ctx["port_type"],
                port_owner=port_ctx["port_owner"],
                peer_switch=port_ctx["peer_switch"],
                peer_port=port_ctx["peer_port"],
                threshold=SYN_THRESHOLD,
                decision_source="agent_rule_based",
                action=decision["action"],
                severity=decision["severity"],
                label=decision["label"],
                blocked_status=decision["blocked_status"],
                decision_reason=decision["reason"],
            )

            handle_drop_decision(
                p4info_helper,
                sw_name,
                sw,
                ip,
                "unknown",
                syn_count,
                ack_count,
                syn_ack_gap,
                ack_ratio,
                hcfg["switch_port"],
                port_ctx,
                decision,
            )

            reset_p4_register(thrift_port, "syn_counter", index)
            reset_p4_register(thrift_port, "ack_counter", index)


def main():
    global topo_cfg
    global switches

    setup_files()
    topo_cfg = load_topology_config()
    monitor_switches = infer_monitor_switches(topo_cfg)

    p4info_helper = helper.P4InfoHelper(P4INFO_FILE)

    switches = connect_switches(topo_cfg, p4info_helper)

    time.sleep(1)

    install_forwarding_rules(topo_cfg, p4info_helper)

    for sw_name in monitor_switches:
        if sw_name not in switches:
            print(f"⚠️ Monitor switch {sw_name} not found; skipping.")
            continue

        enable_digest(p4info_helper, sw_name, switches[sw_name])

        digest_thread = threading.Thread(
            target=monitor_digest,
            args=(p4info_helper, sw_name, switches[sw_name]),
            daemon=True,
        )
        digest_thread.start()

        baseline_thread = threading.Thread(
            target=baseline_logger_for_switch,
            args=(p4info_helper, sw_name, switches[sw_name]),
            daemon=True,
        )
        baseline_thread.start()

    print("\n✅ Multi-switch P4Runtime controller started.")
    print(f"Monitoring switches: {monitor_switches}")
    print(f"Mitigation mode: {MITIGATION_MODE}")
    print(f"Baseline interval: {NORMAL_BASELINE_INTERVAL}s")
    print(f"SYN threshold: {SYN_THRESHOLD}")
    print(f"ACK min threshold: {ACK_MIN_THRESHOLD}")
    print(f"Log file: {LOG_FILE}")
    print(f"CSV file: {CSV_FILE}\n")

    while True:
        time.sleep(10)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Controller stopped.")
    except Exception as e:
        print(f"\n❌ Error: {repr(e)}")
        logging.exception(e)
    finally:
        ShutdownAllSwitchConnections()



# #!/usr/bin/env python3

# import os
# os.environ["GRPC_ENABLE_FORK_SUPPORT"] = "0"

# import sys
# import time
# import csv
# import json
# import logging
# import ipaddress
# import subprocess
# import threading
# from datetime import datetime

# BASE_DIR = "/home/huimin/testing/p4/ddos"

# LOCAL_LIB = os.path.join(BASE_DIR, "lib")
# if os.path.isdir(os.path.join(LOCAL_LIB, "p4runtime_lib")):
#     sys.path.insert(0, LOCAL_LIB)
# else:
#     sys.path.append("/home/huimin/tutorials/utils")

# from p4runtime_lib.switch import ShutdownAllSwitchConnections
# import p4runtime_lib.bmv2 as bmv2
# import p4runtime_lib.helper as helper
# from p4.v1 import p4runtime_pb2


# P4INFO_FILE = f"{BASE_DIR}/p4/p4info.txt"
# BMV2_JSON_FILE = f"{BASE_DIR}/p4/ddos_detect.json"

# LOG_FILE = f"{BASE_DIR}/logs/controller.log"
# CSV_FILE = f"{BASE_DIR}/dataset/traffic_log.csv"

# SYN_THRESHOLD = 30
# ACK_MIN_THRESHOLD = 5
# NORMAL_BASELINE_INTERVAL = 5
# REG_SIZE = 1024

# # For current 3-switch topology:
# # attacker1/attacker2 are attached to s1, so detect/drop near the source.
# MONITOR_SWITCHES = []

# blocked = {}
# switches = {}
# topo_cfg = {}


# def load_topology_config():
#     config_file = os.environ.get("TOPO_CONFIG", f"{BASE_DIR}/config/topology_single.json")

#     if not config_file.startswith("/"):
#         config_file = os.path.join(BASE_DIR, config_file)

#     print(f"📄 Loading topology config: {config_file}")

#     with open(config_file, "r") as f:
#         return json.load(f)

# def infer_monitor_switches(cfg):
#     """
#     Monitor all switches that have directly attached hosts.
#     This allows telemetry collection from all edge/host-facing switches.
#     """
#     monitor = set()

#     for host_name, host_cfg in cfg.get("hosts", {}).items():
#         monitor.add(host_cfg["switch"])

#     return sorted(monitor)


# def setup_files():
#     os.makedirs(f"{BASE_DIR}/logs", exist_ok=True)
#     os.makedirs(f"{BASE_DIR}/dataset", exist_ok=True)

#     logging.basicConfig(
#         filename=LOG_FILE,
#         level=logging.INFO,
#         format="%(asctime)s - %(levelname)s - %(message)s",
#     )

#     if not os.path.exists(CSV_FILE):
#         with open(CSV_FILE, "w", newline="") as f:
#             writer = csv.writer(f)
#             writer.writerow([
#                 "timestamp",
#                 "timestamp_readable",
#                 "event_type",
#                 "switch_name",
#                 "src_ip",
#                 "dst_ip",
#                 "syn_count",
#                 "ack_count",
#                 "syn_ack_gap",
#                 "ack_ratio",
#                 "ingress_port",
#                 "port_type",
#                 "port_owner",
#                 "peer_switch",
#                 "peer_port",
#                 "threshold",
#                 "decision_source",
#                 "action",
#                 "severity",
#                 "label",
#                 "blocked_status",
#                 "decision_reason",
#             ])


# def log_event(
#     event_type,
#     switch_name="",
#     src_ip="",
#     dst_ip="",
#     syn_count="",
#     ack_count="",
#     syn_ack_gap="",
#     ack_ratio="",
#     ingress_port="",
#     port_type="",
#     port_owner="",
#     peer_switch="",
#     peer_port="",
#     threshold="",
#     decision_source="controller",
#     action="",
#     severity="",
#     label="",
#     blocked_status="",
#     decision_reason=""
# ):
#     ts = time.time()
#     ts_readable = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

#     with open(CSV_FILE, "a", newline="") as f:
#         writer = csv.writer(f)
#         writer.writerow([
#             ts,
#             ts_readable,
#             event_type,
#             switch_name,
#             src_ip,
#             dst_ip,
#             syn_count,
#             ack_count,
#             syn_ack_gap,
#             ack_ratio,
#             ingress_port,
#             port_type,
#             port_owner,
#             peer_switch,
#             peer_port,
#             threshold,
#             decision_source,
#             action,
#             severity,
#             label,
#             blocked_status,
#             decision_reason,
#         ])

#     msg = (
#         f"time={ts_readable}, event={event_type}, switch={switch_name}, "
#         f"src_ip={src_ip}, dst_ip={dst_ip}, syn_count={syn_count}, "
#         f"ack_count={ack_count}, syn_ack_gap={syn_ack_gap}, ack_ratio={ack_ratio}, "
#         f"ingress_port={ingress_port}, threshold={threshold}, "
#         f"port_type={port_type}, port_owner={port_owner}, "
#         f"peer_switch={peer_switch}, peer_port={peer_port}, "
#         f"decision_source={decision_source}, action={action}, severity={severity}, "
#         f"label={label}, blocked_status={blocked_status}, decision_reason={decision_reason}"
#     )

#     logging.info(msg)
#     print(msg)


# def bytes_to_int(value):
#     if isinstance(value, int):
#         return value
#     if isinstance(value, bytes):
#         return int.from_bytes(value, byteorder="big")
#     return int(value)


# def int_to_ip(value):
#     return str(ipaddress.IPv4Address(value))


# def ip_to_register_index(ip):
#     return int(ipaddress.IPv4Address(ip)) & (REG_SIZE - 1)

# def get_port_context(cfg, switch_name, ingress_port):
#     """
#     Map switch ingress port to topology context.

#     Example:
#     s1 port 1 -> host-facing port owned by attacker1
#     s1 port 3 -> switch-facing port connected to s2 port 2
#     """
#     try:
#         port = int(ingress_port)
#     except Exception:
#         return {
#             "port_type": "unknown",
#             "port_owner": "",
#             "peer_switch": "",
#             "peer_port": "",
#         }

#     # Host-facing port
#     for host_name, host_cfg in cfg.get("hosts", {}).items():
#         if host_cfg["switch"] == switch_name and int(host_cfg["switch_port"]) == port:
#             return {
#                 "port_type": "host",
#                 "port_owner": host_name,
#                 "peer_switch": "",
#                 "peer_port": "",
#             }

#     # Switch-facing port
#     for link in cfg.get("links", []):
#         if link["node1"] == switch_name and int(link["port1"]) == port:
#             return {
#                 "port_type": "switch",
#                 "port_owner": "",
#                 "peer_switch": link["node2"],
#                 "peer_port": link["port2"],
#             }

#         if link["node2"] == switch_name and int(link["port2"]) == port:
#             return {
#                 "port_type": "switch",
#                 "port_owner": "",
#                 "peer_switch": link["node1"],
#                 "peer_port": link["port1"],
#             }

#     return {
#         "port_type": "unknown",
#         "port_owner": "",
#         "peer_switch": "",
#         "peer_port": "",
#     }


# def write_table_entry(p4info_helper, sw, table_name, match_fields, action_name, action_params):
#     entry = p4info_helper.buildTableEntry(
#         table_name=table_name,
#         match_fields=match_fields,
#         action_name=action_name,
#         action_params=action_params,
#     )
#     sw.WriteTableEntry(entry)


# def read_p4_register(thrift_port, register_name, index):
#     cmd = (
#         f'echo "register_read MyIngress.{register_name} {index}" '
#         f'| simple_switch_CLI --thrift-port {thrift_port}'
#     )

#     try:
#         output = subprocess.check_output(
#             cmd,
#             shell=True,
#             stderr=subprocess.DEVNULL,
#             text=True,
#             timeout=3,
#         )

#         for line in output.splitlines():
#             if f"MyIngress.{register_name}" in line and "=" in line:
#                 return int(line.split("=")[-1].strip())

#     except Exception as e:
#         logging.warning(
#             f"Failed to read register={register_name}, index={index}, thrift={thrift_port}: {repr(e)}"
#         )

#     return None


# def reset_p4_register(thrift_port, register_name, index):
#     cmd = (
#         f'echo "register_write MyIngress.{register_name} {index} 0" '
#         f'| simple_switch_CLI --thrift-port {thrift_port}'
#     )

#     try:
#         subprocess.check_output(
#             cmd,
#             shell=True,
#             stderr=subprocess.DEVNULL,
#             text=True,
#             timeout=3,
#         )
#     except Exception as e:
#         logging.warning(
#             f"Failed to reset register={register_name}, index={index}, thrift={thrift_port}: {repr(e)}"
#         )


# def agent_decide(
#     event_type,
#     src_ip="",
#     dst_ip="unknown",
#     syn_count=0,
#     ack_count=0,
#     switch_name="",
#     ingress_port="",
#     decision_source="agent_rule_based"
# ):
#     try:
#         syn = int(syn_count)
#     except Exception:
#         syn = 0

#     try:
#         ack = int(ack_count)
#     except Exception:
#         ack = 0

#     key = (switch_name, src_ip)

#     if key in blocked:
#         return {
#             "action": "skip_install",
#             "severity": "HIGH",
#             "label": "attack",
#             "blocked_status": "already_blocked",
#             "reason": "source_already_blocked",
#         }

#     if event_type == "digest_received":
#         return {
#             "action": "drop",
#             "severity": "HIGH",
#             "label": "attack",
#             "blocked_status": "pending",
#             "reason": "p4_digest_syn_high_ack_low",
#         }

#     if syn >= SYN_THRESHOLD and ack <= ACK_MIN_THRESHOLD:
#         return {
#             "action": "drop",
#             "severity": "HIGH",
#             "label": "attack",
#             "blocked_status": "pending",
#             "reason": "syn_high_ack_low",
#         }

#     if syn >= SYN_THRESHOLD and ack > ACK_MIN_THRESHOLD:
#         return {
#             "action": "monitor",
#             "severity": "MEDIUM",
#             "label": "suspicious",
#             "blocked_status": "not_blocked",
#             "reason": "syn_high_but_ack_present",
#         }

#     return {
#         "action": "allow",
#         "severity": "LOW",
#         "label": "normal",
#         "blocked_status": "allowed",
#         "reason": "below_syn_threshold",
#     }


# def connect_switches(cfg, p4info_helper):
#     connected = {}

#     for sw_name, sw_cfg in cfg["switches"].items():
#         grpc_port = sw_cfg["grpc_port"]
#         device_id = sw_cfg["device_id"]

#         print(f"🔌 Connecting to {sw_name}: device_id={device_id}, grpc=127.0.0.1:{grpc_port}")

#         sw = bmv2.Bmv2SwitchConnection(
#             name=sw_name,
#             address=f"127.0.0.1:{grpc_port}",
#             device_id=device_id,
#             proto_dump_file=f"{BASE_DIR}/logs/{sw_name}-p4runtime-requests.txt",
#         )

#         sw.MasterArbitrationUpdate()

#         sw.SetForwardingPipelineConfig(
#             p4info=p4info_helper.p4info,
#             bmv2_json_file_path=BMV2_JSON_FILE,
#         )

#         connected[sw_name] = sw
#         print(f"✅ {sw_name}: pipeline installed")

#     return connected


# def install_forwarding_rules(cfg, p4info_helper):
#     forwarding = cfg.get("forwarding", {})

#     if not forwarding:
#         raise ValueError("No forwarding section found in topology config.")

#     print("\n📌 Installing MAC forwarding rules via P4Runtime...")

#     for sw_name, mac_rules in forwarding.items():
#         sw = switches[sw_name]

#         for mac, port in mac_rules.items():
#             write_table_entry(
#                 p4info_helper,
#                 sw,
#                 table_name="MyIngress.mac_table",
#                 match_fields={"h.ethernet.dst_addr": mac},
#                 action_name="MyIngress.forward",
#                 action_params={"port": int(port)},
#             )

#             print(f"  {sw_name}: {mac} -> port {port}")

#     print("✅ Forwarding rules installed.\n")

#     log_event(
#         "forwarding_rules_installed",
#         switch_name="all",
#         decision_source="controller_setup",
#         action="install_mac_rules",
#     )


# def get_digest_id(p4info_helper, digest_name="ddos_digest_t"):
#     for digest in p4info_helper.p4info.digests:
#         if digest.preamble.name == digest_name:
#             return digest.preamble.id

#     raise Exception(f"Digest '{digest_name}' not found in P4Info")


# def enable_digest(p4info_helper, sw_name, sw, digest_name="ddos_digest_t"):
#     digest_id = get_digest_id(p4info_helper, digest_name)
#     device_id = topo_cfg["switches"][sw_name]["device_id"]

#     req = p4runtime_pb2.WriteRequest()
#     req.device_id = device_id
#     req.election_id.high = 0
#     req.election_id.low = 1

#     update = req.updates.add()
#     update.type = p4runtime_pb2.Update.INSERT

#     digest_entry = update.entity.digest_entry
#     digest_entry.digest_id = digest_id
#     digest_entry.config.max_timeout_ns = 100000000
#     digest_entry.config.max_list_size = 1
#     digest_entry.config.ack_timeout_ns = 1000000000

#     sw.client_stub.Write(req)

#     print(f"✅ {sw_name}: Digest enabled: {digest_name} id={digest_id}")

#     log_event(
#         "digest_enabled",
#         switch_name=sw_name,
#         decision_source="controller_setup",
#         action=f"digest_id={digest_id}",
#     )


# def send_digest_ack(sw, digest_list):
#     req = p4runtime_pb2.StreamMessageRequest()
#     req.digest_ack.digest_id = digest_list.digest_id
#     req.digest_ack.list_id = digest_list.list_id
#     sw.requests_stream.put(req)


# def parse_ddos_digest(digest_data):
#     members = digest_data.struct.members

#     src_ip_int = bytes_to_int(members[0].bitstring)
#     dst_ip_int = bytes_to_int(members[1].bitstring)
#     syn_count = bytes_to_int(members[2].bitstring)
#     ack_count = bytes_to_int(members[3].bitstring)
#     ingress_port = bytes_to_int(members[4].bitstring)

#     syn_ack_gap = max(syn_count - ack_count, 0)
#     ack_ratio = round(ack_count / syn_count, 4) if syn_count > 0 else 1.0

#     return {
#         "src_ip": int_to_ip(src_ip_int),
#         "dst_ip": int_to_ip(dst_ip_int),
#         "syn_count": syn_count,
#         "ack_count": ack_count,
#         "syn_ack_gap": syn_ack_gap,
#         "ack_ratio": ack_ratio,
#         "ingress_port": ingress_port,
#     }


# def install_drop_rule(
#     p4info_helper,
#     sw_name,
#     sw,
#     ip,
#     dst_ip="unknown",
#     syn_count="",
#     ack_count="",
#     syn_ack_gap="",
#     ack_ratio="",
#     ingress_port="",
#     port_type="",
#     port_owner="",
#     peer_switch="",
#     peer_port="",
#     decision_reason="syn_threshold_exceeded"
# ):
#     key = (sw_name, ip)

#     if key in blocked:
#         blocked[key]["last_attack_time"] = time.time()

#         log_event(
#             "drop_rule_exists",
#             switch_name=sw_name,
#             src_ip=ip,
#             dst_ip=dst_ip,
#             syn_count=syn_count,
#             ack_count=ack_count,
#             syn_ack_gap=syn_ack_gap,
#             ack_ratio=ack_ratio,
#             ingress_port=ingress_port,
#             port_type=port_type,
#             port_owner=port_owner,
#             peer_switch=peer_switch,
#             peer_port=peer_port,
#             threshold=SYN_THRESHOLD,
#             decision_source="controller_policy",
#             action="skip_install",
#             severity="HIGH",
#             label="attack",
#             blocked_status="already_blocked",
#             decision_reason="source_already_blocked",
#         )
#         return

#     print(f"🚫 Installing DROP rule on {sw_name} for {ip}")

#     write_table_entry(
#         p4info_helper,
#         sw,
#         table_name="MyIngress.ddos_table",
#         match_fields={"h.ipv4.src_addr": ip},
#         action_name="MyIngress.drop",
#         action_params={},
#     )

#     blocked[key] = {
#         "installed_time": time.time(),
#         "last_attack_time": time.time(),
#     }

#     log_event(
#         "drop_rule_installed",
#         switch_name=sw_name,
#         src_ip=ip,
#         dst_ip=dst_ip,
#         syn_count=syn_count,
#         ack_count=ack_count,
#         syn_ack_gap=syn_ack_gap,
#         ack_ratio=ack_ratio,
#         ingress_port=ingress_port,
#         port_type=port_type,
#         port_owner=port_owner,
#         peer_switch=peer_switch,
#         peer_port=peer_port,
#         threshold=SYN_THRESHOLD,
#         decision_source="controller_policy",
#         action="drop",
#         severity="HIGH",
#         label="attack",
#         blocked_status="blocked",
#         decision_reason=decision_reason,
#     )


# def monitor_digest(p4info_helper, sw_name, sw):
#     print(f"🚀 {sw_name}: Waiting for P4 digest events...")

#     while True:
#         try:
#             digest_list = sw.DigestList()

#             for data in digest_list.data:
#                 d = parse_ddos_digest(data)

#                 src_ip = d["src_ip"]
#                 dst_ip = d["dst_ip"]
#                 syn_count = d["syn_count"]
#                 ack_count = d["ack_count"]
#                 syn_ack_gap = d["syn_ack_gap"]
#                 ack_ratio = d["ack_ratio"]
#                 ingress_port = d["ingress_port"]
#                 port_ctx = get_port_context(topo_cfg, sw_name, ingress_port)

#                 decision = agent_decide(
#                     event_type="digest_received",
#                     switch_name=sw_name,
#                     src_ip=src_ip,
#                     dst_ip=dst_ip,
#                     syn_count=syn_count,
#                     ack_count=ack_count,
#                     ingress_port=ingress_port,
#                     decision_source="p4_data_plane",
#                 )

#                 log_event(
#                     "digest_received",
#                     switch_name=sw_name,
#                     src_ip=src_ip,
#                     dst_ip=dst_ip,
#                     syn_count=syn_count,
#                     ack_count=ack_count,
#                     syn_ack_gap=syn_ack_gap,
#                     ack_ratio=ack_ratio,
#                     ingress_port=ingress_port,
#                     port_type=port_ctx["port_type"],
#                     port_owner=port_ctx["port_owner"],
#                     peer_switch=port_ctx["peer_switch"],
#                     peer_port=port_ctx["peer_port"],
#                     threshold=SYN_THRESHOLD,
#                     decision_source="agent_rule_based",
#                     action=decision["action"],
#                     severity=decision["severity"],
#                     label=decision["label"],
#                     blocked_status=decision["blocked_status"],
#                     decision_reason=decision["reason"],
#                 )

#                 if decision["action"] == "drop":
#                     install_drop_rule(
#                         p4info_helper,
#                         sw_name,
#                         sw,
#                         src_ip,
#                         dst_ip=dst_ip,
#                         syn_count=syn_count,
#                         ack_count=ack_count,
#                         syn_ack_gap=syn_ack_gap,
#                         ack_ratio=ack_ratio,
#                         ingress_port=ingress_port,
#                         port_type=port_ctx["port_type"],
#                         port_owner=port_ctx["port_owner"],
#                         peer_switch=port_ctx["peer_switch"],
#                         peer_port=port_ctx["peer_port"],
#                         decision_reason=decision["reason"],
#                     )

#             send_digest_ack(sw, digest_list)

#         except Exception as e:
#             print(f"❌ {sw_name}: Digest/controller error: {repr(e)}")
#             logging.exception(e)
#             time.sleep(1)


# def baseline_logger_for_switch(p4info_helper, sw_name, sw):
#     thrift_port = topo_cfg["switches"][sw_name]["thrift_port"]

#     # Only monitor hosts attached to this switch.
#     attached_hosts = {
#         hname: hcfg
#         for hname, hcfg in topo_cfg["hosts"].items()
#         if hcfg["switch"] == sw_name
#     }

#     print(f"📊 {sw_name}: Baseline telemetry for hosts: {list(attached_hosts.keys())}")

#     while True:
#         time.sleep(NORMAL_BASELINE_INTERVAL)

#         for hname, hcfg in attached_hosts.items():
#             ip = hcfg["ip_plain"]
#             index = ip_to_register_index(ip)

#             syn_count = read_p4_register(thrift_port, "syn_counter", index)
#             ack_count = read_p4_register(thrift_port, "ack_counter", index)

#             if syn_count is None or ack_count is None:
#                 continue

#             syn_ack_gap = max(syn_count - ack_count, 0)
#             ack_ratio = round(ack_count / syn_count, 4) if syn_count > 0 else 1.0

#             decision = agent_decide(
#                 event_type="baseline_counter",
#                 switch_name=sw_name,
#                 src_ip=ip,
#                 dst_ip="unknown",
#                 syn_count=syn_count,
#                 ack_count=ack_count,
#                 ingress_port=hcfg["switch_port"],
#                 decision_source="p4_register_polling",
#             )
            
#             port_ctx = get_port_context(topo_cfg, sw_name, hcfg["switch_port"])

#             log_event(
#                 "baseline_counter",
#                 switch_name=sw_name,
#                 src_ip=ip,
#                 dst_ip="unknown",
#                 syn_count=syn_count,
#                 ack_count=ack_count,
#                 syn_ack_gap=syn_ack_gap,
#                 ack_ratio=ack_ratio,
#                 ingress_port=hcfg["switch_port"],
#                 port_type=port_ctx["port_type"],
#                 port_owner=port_ctx["port_owner"],
#                 peer_switch=port_ctx["peer_switch"],
#                 peer_port=port_ctx["peer_port"],
#                 threshold=SYN_THRESHOLD,
#                 decision_source="agent_rule_based",
#                 action=decision["action"],
#                 severity=decision["severity"],
#                 label=decision["label"],
#                 blocked_status=decision["blocked_status"],
#                 decision_reason=decision["reason"],
#             )

#             if decision["action"] == "drop":
#                 install_drop_rule(
#                     p4info_helper,
#                     sw_name,
#                     sw,
#                     ip,
#                     dst_ip="unknown",
#                     syn_count=syn_count,
#                     ack_count=ack_count,
#                     syn_ack_gap=syn_ack_gap,
#                     ack_ratio=ack_ratio,
#                     ingress_port=hcfg["switch_port"],
#                     port_type=port_ctx["port_type"],
#                     port_owner=port_ctx["port_owner"],
#                     peer_switch=port_ctx["peer_switch"],
#                     peer_port=port_ctx["peer_port"],
#                     decision_reason=decision["reason"],
#                 )

#             reset_p4_register(thrift_port, "syn_counter", index)
#             reset_p4_register(thrift_port, "ack_counter", index)


# def main():
#     global topo_cfg
#     global switches

#     setup_files()
#     topo_cfg = load_topology_config()
#     monitor_switches = infer_monitor_switches(topo_cfg)

#     p4info_helper = helper.P4InfoHelper(P4INFO_FILE)

#     switches = connect_switches(topo_cfg, p4info_helper)

#     time.sleep(1)

#     install_forwarding_rules(topo_cfg, p4info_helper)

#     for sw_name in monitor_switches:
#         if sw_name not in switches:
#             print(f"⚠️ Monitor switch {sw_name} not found; skipping.")
#             continue

#         enable_digest(p4info_helper, sw_name, switches[sw_name])

#         digest_thread = threading.Thread(
#             target=monitor_digest,
#             args=(p4info_helper, sw_name, switches[sw_name]),
#             daemon=True,
#         )
#         digest_thread.start()

#         baseline_thread = threading.Thread(
#             target=baseline_logger_for_switch,
#             args=(p4info_helper, sw_name, switches[sw_name]),
#             daemon=True,
#         )
#         baseline_thread.start()

#     print("\n✅ Multi-switch P4Runtime controller started.")
#     print(f"Monitoring switches: {monitor_switches}")
#     print(f"Log file: {LOG_FILE}")
#     print(f"CSV file: {CSV_FILE}\n")

#     while True:
#         time.sleep(10)


# if __name__ == "__main__":
#     try:
#         main()
#     except KeyboardInterrupt:
#         print("\n🛑 Controller stopped.")
#     except Exception as e:
#         print(f"\n❌ Error: {repr(e)}")
#         logging.exception(e)
#     finally:
#         ShutdownAllSwitchConnections()
