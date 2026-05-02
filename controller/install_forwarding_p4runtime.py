#!/usr/bin/env python3

import os
import sys
import json
import time
import logging

BASE_DIR = "/home/huimin/testing/p4/ddos"

LOCAL_LIB = os.path.join(BASE_DIR, "lib")
if os.path.isdir(os.path.join(LOCAL_LIB, "p4runtime_lib")):
    sys.path.insert(0, LOCAL_LIB)
else:
    sys.path.append("/home/huimin/tutorials/utils")

from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.bmv2 as bmv2
import p4runtime_lib.helper as helper


P4INFO_FILE = f"{BASE_DIR}/p4/p4info.txt"
BMV2_JSON_FILE = f"{BASE_DIR}/p4/ddos_detect.json"

LOG_DIR = f"{BASE_DIR}/logs"
os.makedirs(LOG_DIR, exist_ok=True)


def load_config():
    config_file = os.environ.get(
        "TOPO_CONFIG",
        f"{BASE_DIR}/config/topology_single.json"
    )

    if not config_file.startswith("/"):
        config_file = os.path.join(BASE_DIR, config_file)

    print(f"📄 Loading topology config: {config_file}")

    with open(config_file, "r") as f:
        return json.load(f)


def write_table_entry(p4info_helper, sw, table_name, match_fields, action_name, action_params):
    entry = p4info_helper.buildTableEntry(
        table_name=table_name,
        match_fields=match_fields,
        action_name=action_name,
        action_params=action_params,
    )
    sw.WriteTableEntry(entry)


def connect_and_configure_switches(cfg, p4info_helper):
    switches = {}

    for sw_name, sw_cfg in cfg["switches"].items():
        grpc_port = sw_cfg["grpc_port"]
        device_id = sw_cfg["device_id"]

        print(f"🔌 Connecting to {sw_name}: device_id={device_id}, grpc=127.0.0.1:{grpc_port}")

        sw = bmv2.Bmv2SwitchConnection(
            name=sw_name,
            address=f"127.0.0.1:{grpc_port}",
            device_id=device_id,
            proto_dump_file=f"{LOG_DIR}/{sw_name}-p4runtime-requests.txt",
        )

        sw.MasterArbitrationUpdate()

        sw.SetForwardingPipelineConfig(
            p4info=p4info_helper.p4info,
            bmv2_json_file_path=BMV2_JSON_FILE,
        )

        switches[sw_name] = sw
        print(f"✅ {sw_name}: pipeline installed")

    return switches


def install_forwarding_rules(cfg, p4info_helper, switches):
    forwarding = cfg.get("forwarding", {})

    if not forwarding:
        raise ValueError("No 'forwarding' section found in topology config.")

    print("\n📌 Installing MAC forwarding rules via P4Runtime...")

    for sw_name, mac_rules in forwarding.items():
        if sw_name not in switches:
            print(f"⚠️ Skipping {sw_name}: switch not connected")
            continue

        sw = switches[sw_name]

        for mac, port in mac_rules.items():
            write_table_entry(
                p4info_helper,
                sw,
                table_name="MyIngress.mac_table",
                match_fields={
                    "h.ethernet.dst_addr": mac
                },
                action_name="MyIngress.forward",
                action_params={
                    "port": int(port)
                },
            )

            print(f"  {sw_name}: {mac} -> port {port}")

    print("\n✅ P4Runtime MAC forwarding rules installed.")


def main():
    cfg = load_config()
    p4info_helper = helper.P4InfoHelper(P4INFO_FILE)

    switches = connect_and_configure_switches(cfg, p4info_helper)

    # Small pause after pipeline installation.
    time.sleep(1)

    install_forwarding_rules(cfg, p4info_helper, switches)

    print("\n🎉 Forwarding installer finished.")
    print("You can now run pingall in Mininet.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Stopped.")
    except Exception as e:
        print(f"\n❌ Error: {repr(e)}")
        logging.exception(e)
    finally:
        ShutdownAllSwitchConnections()
