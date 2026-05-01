#!/usr/bin/env python3

import os
os.environ["GRPC_ENABLE_FORK_SUPPORT"] = "0"

import sys
import time
import csv
import logging
import ipaddress
import threading
import subprocess
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.bmv2 as bmv2
import p4runtime_lib.helper as helper
from p4.v1 import p4runtime_pb2
from datetime import datetime


BASE_DIR = "/home/huimin/testing/p4/ddos"

# Prefer local project library for FYP reproducibility.
LOCAL_LIB = os.path.join(BASE_DIR, "lib")
if os.path.isdir(os.path.join(LOCAL_LIB, "p4runtime_lib")):
    sys.path.insert(0, LOCAL_LIB)
else:
    sys.path.append("/home/huimin/tutorials/utils")


P4INFO_FILE = f"{BASE_DIR}/p4/p4info.txt"
BMV2_JSON_FILE = f"{BASE_DIR}/p4/ddos_detect.json"

LOG_FILE = f"{BASE_DIR}/logs/controller.log"
CSV_FILE = f"{BASE_DIR}/dataset/traffic_log.csv"

SWITCH_NAME = "s1"
SWITCH_ADDR = "127.0.0.1:50051"
DEVICE_ID = 0

SYN_THRESHOLD = 30
NORMAL_BASELINE_INTERVAL = 5
THRIFT_PORT = 9090
REG_SIZE = 1024

HOSTS = {
    "attacker1": {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "port": 1},
    "attacker2": {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "port": 2},
    "normal":    {"ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "port": 3},
    "victim":    {"ip": "10.0.0.100", "mac": "00:00:00:00:00:04", "port": 4},
}

blocked = {}


def setup_files():
    os.makedirs(f"{BASE_DIR}/logs", exist_ok=True)
    os.makedirs(f"{BASE_DIR}/dataset", exist_ok=True)

    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    # Always create a fresh header only if file does not exist.
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "timestamp_readable",
                "event_type",
                "src_ip",
                "dst_ip",
                "syn_count",
                "ack_count",
                "syn_ack_gap",
                "ack_ratio",
                "ingress_port",
                "threshold",
                "decision_source",
                "action",
                "severity",
                "label",
                "blocked_status",
                "decision_reason",
            ])


def log_event(
    event_type,
    src_ip="",
    dst_ip="",
    syn_count="",
    ack_count="",
    syn_ack_gap="",
    ack_ratio="",
    ingress_port="",
    threshold="",
    decision_source="controller",
    action="",
    severity="",
    label="",
    blocked_status="",
    decision_reason=""
):
    ts = time.time()
    ts_readable = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            ts,
            ts_readable,
            event_type,
            src_ip,
            dst_ip,
            syn_count,
            ack_count,
            syn_ack_gap,
            ack_ratio,
            ingress_port,
            threshold,
            decision_source,
            action,
            severity,
            label,
            blocked_status,
            decision_reason,
        ])

    msg = (
        f"time={ts_readable}, event={event_type}, src_ip={src_ip}, dst_ip={dst_ip}, "
        f"syn_count={syn_count}, ack_count={ack_count}, "
        f"syn_ack_gap={syn_ack_gap}, ack_ratio={ack_ratio}, "
        f"ingress_port={ingress_port}, threshold={threshold}, "
        f"decision_source={decision_source}, action={action}, "
        f"severity={severity}, label={label}, blocked_status={blocked_status}, "
        f"decision_reason={decision_reason}"
    )
    
    logging.info(msg)
    print(msg)
 

def read_p4_register(register_name, index):
    cmd = (
        f'echo "register_read MyIngress.{register_name} {index}" '
        f'| simple_switch_CLI --thrift-port {THRIFT_PORT}'
    )

    try:
        output = subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
        )

        for line in output.splitlines():
            if f"MyIngress.{register_name}" in line and "=" in line:
                return int(line.split("=")[-1].strip())

    except Exception as e:
        logging.warning(
            f"Failed to read register={register_name}, index={index}: {repr(e)}"
        )

    return None


def reset_p4_register(register_name, index):
    cmd = (
        f'echo "register_write MyIngress.{register_name} {index} 0" '
        f'| simple_switch_CLI --thrift-port {THRIFT_PORT}'
    )

    try:
        subprocess.check_output(
            cmd,
            shell=True,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
        )
    except Exception as e:
        logging.warning(
            f"Failed to reset register={register_name}, index={index}: {repr(e)}"
        )


def read_syn_register(index):
    return read_p4_register("syn_counter", index)


def read_ack_register(index):
    return read_p4_register("ack_counter", index)


def reset_syn_register(index):
    reset_p4_register("syn_counter", index)


def reset_ack_register(index):
    reset_p4_register("ack_counter", index)


def ip_to_register_index(ip):
    """
    Must match P4 logic:
    idx = h.ipv4.src_addr & 32w1023;
    """
    return int(ipaddress.IPv4Address(ip)) & (REG_SIZE - 1)




def agent_decide(
    event_type,
    src_ip="",
    dst_ip="unknown",
    syn_count=0,
    ack_count=0,
    ingress_port="",
    decision_source="agent_rule_based"
):
    """
    Agentic AI v0: rule-based decision agent.

    Observe:
        Receives telemetry from P4 register polling or digest event.

    Analyze:
        Compares SYN count with threshold and checks blocked state.

    Plan:
        Chooses allow / monitor / drop.

    Act:
        Controller executes the action by updating P4 table rules.

    Later:
        This function can be replaced by ML model inference.
    """
    try:
        count = int(syn_count)
    except Exception:
        count = 0

    try:
        ack = int(ack_count)
    except Exception:
        ack = 0

    gap = max(count - ack, 0)
    ack_ratio = ack / count if count > 0 else 1

    if src_ip in blocked:
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

    if count >= SYN_THRESHOLD and ack <= 5:
        return {
            "action": "drop",
            "severity": "HIGH",
            "label": "attack",
            "blocked_status": "pending",
            "reason": "syn_high_ack_low",
        }

    if count >= SYN_THRESHOLD and ack > 5:
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


def normal_baseline_logger(p4info_helper, sw):
    """
    Phase 1 normal + fallback attack telemetry.

    Reads real SYN counter values from the P4 data plane.
    The counter is reset after each reading, so syn_count represents one monitoring window.

    Primary path:
        P4 digest triggers attack notification.

    Fallback path:
        If register polling observes syn_count >= threshold, controller also installs drop rule.
    """
    while True:
        time.sleep(NORMAL_BASELINE_INTERVAL)

        for name, host in HOSTS.items():
            # Skip lab server / destination-only host.
#            if name == "victim" or host["ip"] == HOSTS["victim"]["ip"]:
#                continue

            index = ip_to_register_index(host["ip"])
            syn_count = read_syn_register(index)
            ack_count = read_ack_register(index)

            if syn_count is None or ack_count is None:
                continue

            syn_ack_gap = max(syn_count - ack_count, 0)
            ack_ratio = round(ack_count / syn_count, 4) if syn_count > 0 else 1.0

            decision = agent_decide(
                event_type="baseline_counter",
                src_ip=host["ip"],
                dst_ip="unknown",
                syn_count=syn_count,
                ack_count=ack_count,
                ingress_port=host["port"],
                decision_source="p4_register_polling",
            )

            # Fallback mitigation:
            # If polling sees threshold reached and digest/drop has not happened yet,
            # treat it as an attack and install a drop rule.
            if syn_count >= SYN_THRESHOLD and host["ip"] not in blocked:
                decision = {
                    "action": "drop",
                    "severity": "HIGH",
                    "label": "attack",
                    "blocked_status": "pending",
                    "reason": "register_threshold_reached_fallback",
                }

            log_event(
                "baseline_counter",
                src_ip=host["ip"],
                dst_ip="unknown",
                syn_count=syn_count,
                ack_count=ack_count,
                syn_ack_gap=syn_ack_gap,
                ack_ratio=ack_ratio,
                ingress_port=host["port"],
                threshold=SYN_THRESHOLD,
                decision_source="agent_rule_based",
                action=decision["action"],
                severity=decision["severity"],
                label=decision["label"],
                blocked_status=decision["blocked_status"],
                decision_reason=decision["reason"],
            )

            if decision["action"] == "drop":
                install_drop_rule(
                    p4info_helper,
                    sw,
                    host["ip"],
                    dst_ip="unknown",
                    syn_count=syn_count,
                    ack_count=ack_count,
                    syn_ack_gap=syn_ack_gap,
                    ack_ratio=ack_ratio,
                    ingress_port=host["port"],
                    decision_reason=decision["reason"],
                )

            # Reset each host counter after logging.
            # This makes syn_count a window-based value, not lifetime total.
            reset_syn_register(index)
            reset_ack_register(index)


def bytes_to_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return int.from_bytes(value, byteorder="big")
    return int(value)


def int_to_ip(value):
    return str(ipaddress.IPv4Address(value))


def write_table_entry(p4info_helper, sw, table_name, match_fields, action_name, action_params):
    entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        action_name=action_name,
        action_params=action_params,
    )
    sw.WriteTableEntry(entry)


def delete_table_entry(p4info_helper, sw, table_name, match_fields, action_name, action_params):
    entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        action_name=action_name,
        action_params=action_params,
    )
    sw.DeleteTableEntry(entry)


def install_forwarding_rules(p4info_helper, sw):
    print("📌 Installing proactive forwarding rules...")

    for name, info in HOSTS.items():
        write_table_entry(
            p4info_helper,
            sw,
            table_name="MyIngress.mac_table",
            match_fields={"h.ethernet.dst_addr": info["mac"]},
            action_name="MyIngress.forward",
            action_params={"port": info["port"]},
        )
        print(f"  {name:10} {info['mac']} -> port {info['port']}")

    print("✅ Basic forwarding rules installed.\n")
    log_event(
        "forwarding_rules_installed",
        decision_source="controller_setup",
        action="install_mac_rules",
    )


def install_drop_rule(
    p4info_helper,
    sw,
    ip,
    dst_ip="unknown",
    syn_count="",
    ack_count="",
    syn_ack_gap="",
    ack_ratio="",
    ingress_port="",
    decision_reason="syn_threshold_exceeded"
):
    if ip in blocked:
        blocked[ip]["last_attack_time"] = time.time()
        log_event(
            "drop_rule_exists",
            src_ip=ip,
            dst_ip=dst_ip,
            syn_count=syn_count,
            ack_count=ack_count,
            syn_ack_gap=syn_ack_gap,
            ack_ratio=ack_ratio,
            ingress_port=ingress_port,
            threshold=SYN_THRESHOLD,
            decision_source="controller_policy",
            action="skip_install",
            severity="HIGH",
            label="attack",
            blocked_status="already_blocked",
            decision_reason="source_already_blocked",
        )
        return

    print(f"🚫 Installing DROP rule for {ip}")

    write_table_entry(
        p4info_helper,
        sw,
        table_name="MyIngress.ddos_table",
        match_fields={"h.ipv4.src_addr": ip},
        action_name="MyIngress.drop",
        action_params={},
    )

    blocked[ip] = {
        "installed_time": time.time(),
        "last_attack_time": time.time(),
    }

    log_event(
        "drop_rule_installed",
        src_ip=ip,
        dst_ip=dst_ip,
        syn_count=syn_count,
        ack_count=ack_count,
        syn_ack_gap=syn_ack_gap,
        ack_ratio=ack_ratio,
        ingress_port=ingress_port,
        threshold=SYN_THRESHOLD,
        decision_source="controller_policy",
        action="drop",
        severity="HIGH",
        label="attack",
        blocked_status="blocked",
        decision_reason=decision_reason,
    )



def get_digest_id(p4info_helper, digest_name="ddos_digest_t"):
    for digest in p4info_helper.p4info.digests:
        if digest.preamble.name == digest_name:
            return digest.preamble.id

    print("Available digests:")
    for digest in p4info_helper.p4info.digests:
        print(f"- {digest.preamble.name} id={digest.preamble.id}")

    raise Exception(f"Digest '{digest_name}' not found in P4Info")


def enable_digest(p4info_helper, sw, digest_name="ddos_digest_t"):
    digest_id = get_digest_id(p4info_helper, digest_name)

    req = p4runtime_pb2.WriteRequest()
    req.device_id = DEVICE_ID
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

    print(f"✅ Digest enabled: {digest_name} id={digest_id}")
    log_event(
        "digest_enabled",
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


def monitor_digest(p4info_helper, sw):
    print("🚀 Waiting for P4 digest events...")
    print(f"Log file: {LOG_FILE}")
    print(f"CSV file: {CSV_FILE}")
    print(f"Normal baseline interval: {NORMAL_BASELINE_INTERVAL}s\n")

    while True:
        try:
            digest_list = sw.DigestList()

            for data in digest_list.data:
                d = parse_ddos_digest(data)

                src_ip = d["src_ip"]
                dst_ip = d["dst_ip"]
                syn_count = d["syn_count"]
                ingress_port = d["ingress_port"]
                ack_count = d["ack_count"]
                syn_ack_gap = d["syn_ack_gap"]
                ack_ratio = d["ack_ratio"]
                
                decision = agent_decide(
                    event_type="digest_received",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    syn_count=syn_count,
                    ack_count=ack_count,
                    ingress_port=ingress_port,
                    decision_source="p4_data_plane",
                )
                
                log_event(
                    "digest_received",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    syn_count=syn_count,
                    ack_count=ack_count,
                    syn_ack_gap=syn_ack_gap,
                    ack_ratio=ack_ratio,
                    ingress_port=ingress_port,
                    threshold=SYN_THRESHOLD,
                    decision_source="agent_rule_based",
                    action=decision["action"],
                    severity=decision["severity"],
                    label=decision["label"],
                    blocked_status=decision["blocked_status"],
                    decision_reason=decision["reason"],
                )

                if decision["action"] == "drop":
                  install_drop_rule(
                    p4info_helper,
                    sw,
                    src_ip,
                    dst_ip=dst_ip,
                    syn_count=syn_count,
                    ack_count=ack_count,
                    syn_ack_gap=syn_ack_gap,
                    ack_ratio=ack_ratio,
                    ingress_port=ingress_port,
                    decision_reason=decision["reason"],
                )
                else:
                  log_event(
                    "agent_no_drop_action",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    syn_count=syn_count,
                    ingress_port=ingress_port,
                    threshold=SYN_THRESHOLD,
                    decision_source="agent_rule_based",
                    action=decision["action"],
                    severity=decision["severity"],
                    label=decision["label"],
                    blocked_status=decision["blocked_status"],
                    decision_reason=decision["reason"],
                  )

            send_digest_ack(sw, digest_list)

        except Exception as e:
            print(f"❌ Digest/controller error: {repr(e)}")
            logging.exception(e)
            time.sleep(1)


def main():
    setup_files()

    p4info_helper = helper.P4InfoHelper(P4INFO_FILE)

    sw = bmv2.Bmv2SwitchConnection(
        name=SWITCH_NAME,
        address=SWITCH_ADDR,
        device_id=DEVICE_ID,
        proto_dump_file=f"{BASE_DIR}/logs/p4runtime-requests.txt",
    )

    sw.MasterArbitrationUpdate()

    sw.SetForwardingPipelineConfig(
        p4info=p4info_helper.p4info,
        bmv2_json_file_path=BMV2_JSON_FILE,
    )

    print("✅ Connected to simple_switch_grpc.")
    print("✅ Pipeline config installed.\n")

    install_forwarding_rules(p4info_helper, sw)
    enable_digest(p4info_helper, sw)

    # Start normal baseline logging in the background.
    baseline_thread = threading.Thread(
      target=normal_baseline_logger,
      args=(p4info_helper, sw),
      daemon=True,
    )
    baseline_thread.start()

    monitor_digest(p4info_helper, sw)


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
