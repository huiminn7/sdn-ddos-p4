import os
import csv
import time
import logging
import subprocess
import ipaddress
from datetime import datetime


class TelemetryManager:
    """
    Handles telemetry logging for the P4Runtime controller.

    This module is only responsible for:
    - creating log/dataset folders
    - writing telemetry events into CSV
    - writing readable controller logs
    - reading/resetting BMv2 registers through simple_switch_CLI

    It should NOT decide mitigation.
    It should NOT install P4 table rules.
    """

    CSV_HEADER = [
        "timestamp",
        "timestamp_readable",
        "event_type",
        "switch_name",
        "src_ip",
        "dst_ip",
        "syn_count",
        "ack_count",
        "syn_ack_gap",
        "ack_ratio",
        "ingress_port",
        "port_type",
        "port_owner",
        "peer_switch",
        "peer_port",
        "threshold",
        "decision_source",
        "action",
        "severity",
        "label",
        "blocked_status",
        "decision_reason",
    ]

    def __init__(self, base_dir, log_file, csv_file):
        self.base_dir = base_dir
        self.log_file = log_file
        self.csv_file = csv_file

    def setup(self):
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.csv_file), exist_ok=True)

        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )

        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(self.CSV_HEADER)

    def log_event(
        self,
        event_type,
        switch_name="",
        src_ip="",
        dst_ip="",
        syn_count="",
        ack_count="",
        syn_ack_gap="",
        ack_ratio="",
        ingress_port="",
        port_type="",
        port_owner="",
        peer_switch="",
        peer_port="",
        threshold="",
        decision_source="controller",
        action="",
        severity="",
        label="",
        blocked_status="",
        decision_reason=""
    ):
        ts = time.time()
        ts_readable = datetime.fromtimestamp(ts).isoformat(timespec="milliseconds")

        row = [
            ts,
            ts_readable,
            event_type,
            switch_name,
            src_ip,
            dst_ip,
            syn_count,
            ack_count,
            syn_ack_gap,
            ack_ratio,
            ingress_port,
            port_type,
            port_owner,
            peer_switch,
            peer_port,
            threshold,
            decision_source,
            action,
            severity,
            label,
            blocked_status,
            decision_reason,
        ]

        with open(self.csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(row)

        msg = (
            f"time={ts_readable}, event={event_type}, switch={switch_name}, "
            f"src_ip={src_ip}, dst_ip={dst_ip}, syn_count={syn_count}, "
            f"ack_count={ack_count}, syn_ack_gap={syn_ack_gap}, ack_ratio={ack_ratio}, "
            f"ingress_port={ingress_port}, threshold={threshold}, "
            f"port_type={port_type}, port_owner={port_owner}, "
            f"peer_switch={peer_switch}, peer_port={peer_port}, "
            f"decision_source={decision_source}, action={action}, severity={severity}, "
            f"label={label}, blocked_status={blocked_status}, decision_reason={decision_reason}"
        )

        logging.info(msg)
        print(msg)


def ip_to_register_index(ip, reg_size):
    return int(ipaddress.IPv4Address(ip)) & (reg_size - 1)


def read_p4_register(thrift_port, register_name, index):
    cmd = (
        f'echo "register_read MyIngress.{register_name} {index}" '
        f'| simple_switch_CLI --thrift-port {thrift_port}'
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
            f"Failed to read register={register_name}, index={index}, thrift={thrift_port}: {repr(e)}"
        )

    return None


def reset_p4_register(thrift_port, register_name, index):
    cmd = (
        f'echo "register_write MyIngress.{register_name} {index} 0" '
        f'| simple_switch_CLI --thrift-port {thrift_port}'
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
            f"Failed to reset register={register_name}, index={index}, thrift={thrift_port}: {repr(e)}"
        )

