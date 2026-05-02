#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Switch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import json
import time
import os


#CONFIG_FILE = "config/topology_single.json"
CONFIG_FILE = os.environ.get("TOPO_CONFIG", "config/topology_single.json")

class BMv2Switch(Switch):
    """BMv2 simple_switch_grpc for P4Runtime"""

    def __init__(self, name, **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.sw_path = kwargs.get("sw_path", "/usr/local/bin/simple_switch_grpc")
        self.json_path = kwargs.get("json_path", "p4/ddos_detect.json")
        self.thrift_port = kwargs.get("thrift_port", 9090)
        self.grpc_port = kwargs.get("grpc_port", 50051)
        self.device_id = kwargs.get("device_id", 0)

    def start(self, controllers):
        info(f"*** Starting BMv2 switch {self.name}\n")

        # Build interface arguments dynamically based on actual switch ports.
        intf_args = []
        for port_no, intf in sorted(self.intfs.items()):
            if port_no == 0:
                continue
            intf_args.append(f"-i {port_no}@{intf.name}")

        intf_args_str = " ".join(intf_args)

        cmd = (
            f"{self.sw_path} "
            f"--device-id {self.device_id} "
            f"--thrift-port {self.thrift_port} "
            f"{intf_args_str} "
            f"--log-console "
            f"{self.json_path} "
            f"-- "
            f"--grpc-server-addr 0.0.0.0:{self.grpc_port} "
            f"> /tmp/{self.name}.log 2>&1 &"
        )

        self.cmd(cmd)
        time.sleep(2)

    def stop(self):
        info(f"*** Stopping BMv2 switch {self.name}\n")
        self.cmd("pkill -9 -f simple_switch")
        Switch.stop(self)


def load_config():
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


class ConfigTopo(Topo):
    def build(self):
        cfg = load_config()
        json_path = cfg["p4"]["json_path"]

        switches = {}

        for sw_name, sw_cfg in cfg["switches"].items():
            switches[sw_name] = self.addSwitch(
                sw_name,
                cls=BMv2Switch,
                json_path=json_path,
                thrift_port=sw_cfg["thrift_port"],
                grpc_port=sw_cfg["grpc_port"],
                device_id=sw_cfg["device_id"],
            )

        hosts = {}

        for host_name, host_cfg in cfg["hosts"].items():
            hosts[host_name] = self.addHost(
                host_name,
                ip=host_cfg["ip"],
                mac=host_cfg["mac"],
            )

            self.addLink(
                hosts[host_name],
                switches[host_cfg["switch"]],
                port1=host_cfg.get("host_port", 1),
                port2=host_cfg["switch_port"],
            )

        for link in cfg.get("links", []):
            self.addLink(
                switches[link["node1"]],
                switches[link["node2"]],
                port1=link["port1"],
                port2=link["port2"],
            )


def disable_offloading(net):
    info("*** Disabling checksum/segmentation offloading on host interfaces\n")

    for host in net.hosts:
        intf = host.defaultIntf()
        cmd = f"ethtool -K {intf} tx off rx off tso off gso off gro off"
        result = host.cmd(cmd)

        print(f"  {host.name:10} {intf}: offloading disabled")

        if result.strip():
            print(result.strip())


def configure_static_arp(net, cfg):
    info("*** Configuring static ARP entries\n")

    host_info = cfg["hosts"]

    for hname, hcfg in host_info.items():
        host = net.get(hname)

        for other_name, other_cfg in host_info.items():
            if hname == other_name:
                continue

            host.cmd(f"arp -s {other_cfg['ip_plain']} {other_cfg['mac']}")


def print_summary(cfg):
    print("\n" + "=" * 60)
    print("Config-Driven P4 DDoS Test Network Ready")
    print("=" * 60)

    print("Switches:")
    for sw_name, sw_cfg in cfg["switches"].items():
        print(
            f"  {sw_name}: device_id={sw_cfg['device_id']}, "
            f"thrift={sw_cfg['thrift_port']}, grpc={sw_cfg['grpc_port']}"
        )

    print("\nHosts:")
    for hname, hcfg in cfg["hosts"].items():
        print(
            f"  {hname:10}: {hcfg['ip_plain']:12} "
            f"MAC {hcfg['mac']} connected to {hcfg['switch']}:{hcfg['switch_port']}"
        )

    print("\nTest:")
    print("  pingall")
    print("  normal ping victim")
    print("  normal curl http://10.0.0.100:80")
    print("  attacker1 hping3 -S -p 80 --flood 10.0.0.100")

    print("\nCheck BMv2:")
    print("  simple_switch_CLI --thrift-port 9090")
    print("=" * 60 + "\n")


def configure_static_forwarding(cfg):
    info("*** Installing static MAC forwarding rules from config\n")

    forwarding = cfg.get("forwarding", {})
    switches = cfg["switches"]

    for sw_name, mac_rules in forwarding.items():
        thrift_port = switches[sw_name]["thrift_port"]

        cmds = []
        cmds.append("table_clear MyIngress.mac_table")

        for mac, port in mac_rules.items():
            cmds.append(f"table_add MyIngress.mac_table MyIngress.forward {mac} => {port}")

        cmds.append("table_set_default MyIngress.mac_table MyIngress.drop")

        cmd_file = f"/tmp/{sw_name}_commands.txt"

        with open(cmd_file, "w") as f:
            f.write("\n".join(cmds) + "\n")

        os.system(f"simple_switch_CLI --thrift-port {thrift_port} < {cmd_file}")
        print(f"  {sw_name}: installed {len(mac_rules)} MAC forwarding rules")



def run():
    cfg = load_config()

    topo = ConfigTopo()
    net = Mininet(topo=topo, controller=None, autoSetMacs=False)

    net.start()

    disable_offloading(net)
    configure_static_arp(net, cfg)
#    configure_static_forwarding(cfg)
    if os.environ.get("STATIC_FORWARDING", "1") == "1":
        configure_static_forwarding(cfg)
    else:
        info("*** Skipping simple_switch_CLI static forwarding; expecting P4Runtime controller\n")

    print_summary(cfg)

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
