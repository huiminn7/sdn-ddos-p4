#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Switch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time


class BMv2Switch(Switch):
    """BMv2 simple_switch for P4"""

    def __init__(self, name, **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.sw_path = kwargs.get("sw_path", "/usr/local/bin/simple_switch_grpc")
        self.json_path = kwargs.get("json_path", "p4/ddos_detect.json")
        self.thrift_port = kwargs.get("thrift_port", 9090)
        self.device_id = kwargs.get("device_id", 0)

    def start(self, controllers):
        info(f"*** Starting BMv2 switch {self.name}\n")

        cmd = (
	    f"{self.sw_path} "
	    f"--device-id {self.device_id} "
	    f"--thrift-port {self.thrift_port} "
	    f"-i 1@{self.name}-eth1 "
	    f"-i 2@{self.name}-eth2 "
	    f"-i 3@{self.name}-eth3 "
	    f"-i 4@{self.name}-eth4 "
	    f"--log-console "
	    f"{self.json_path} "
	    f"-- "
	    f"--grpc-server-addr 0.0.0.0:50051 "
	    f"> /tmp/{self.name}.log 2>&1 &"
        )

        self.cmd(cmd)
        time.sleep(2)

    def stop(self):
        info(f"*** Stopping BMv2 switch {self.name}\n")
        self.cmd("pkill -9 -f simple_switch")
        Switch.stop(self)


class DDoSTopo(Topo):
    def build(self):
        s1 = self.addSwitch(
            "s1",
            cls=BMv2Switch,
            json_path="p4/ddos_detect.json",
            thrift_port=9090,
            device_id=0
        )

        attacker1 = self.addHost(
            "attacker1",
            ip="10.0.0.1/24",
            mac="00:00:00:00:00:01"
        )

        attacker2 = self.addHost(
            "attacker2",
            ip="10.0.0.2/24",
            mac="00:00:00:00:00:02"
        )

        normal = self.addHost(
            "normal",
            ip="10.0.0.3/24",
            mac="00:00:00:00:00:03"
        )

        victim = self.addHost(
            "victim",
            ip="10.0.0.100/24",
            mac="00:00:00:00:00:04"
        )

        self.addLink(attacker1, s1, port1=1, port2=1)
        self.addLink(attacker2, s1, port1=1, port2=2)
        self.addLink(normal, s1, port1=1, port2=3)
        self.addLink(victim, s1, port1=1, port2=4)


def configure_tables():
    info("*** Configuring BMv2 MAC table\n")

    cmds = """
table_clear mac_table
table_add mac_table forward 00:00:00:00:00:01 => 1
table_add mac_table forward 00:00:00:00:00:02 => 2
table_add mac_table forward 00:00:00:00:00:03 => 3
table_add mac_table forward 00:00:00:00:00:04 => 4
table_set_default mac_table forward 1
"""

    with open("/tmp/commands.txt", "w") as f:
        f.write(cmds)

    import os
    os.system("simple_switch_CLI --thrift-port 9090 < /tmp/commands.txt")


def disable_offloading(net):
    info("*** Disabling checksum/segmentation offloading on host interfaces\n")

    for host in net.hosts:
        intf = host.defaultIntf()

        cmd = f"ethtool -K {intf} tx off rx off tso off gso off gro off"
        result = host.cmd(cmd)

        print(f"  {host.name:10} {intf}: offloading disabled")

        # Optional: print warnings only if needed
        if result.strip():
            print(result.strip())

def run():
    topo = DDoSTopo()
    net = Mininet(topo=topo, controller=None, autoSetMacs=False)

    net.start()
    disable_offloading(net)
#    configure_tables()

    # Add static ARP entries so hosts do not need ARP broadcast
    hosts = {
    	"attacker1": ("10.0.0.1", "00:00:00:00:00:01"),
    	"attacker2": ("10.0.0.2", "00:00:00:00:00:02"),
    	"normal":    ("10.0.0.3", "00:00:00:00:00:03"),
    	"victim":    ("10.0.0.100", "00:00:00:00:00:04"),
    }

    for hname, (ip, mac) in hosts.items():
    	host = net.get(hname)
    	for other_name, (other_ip, other_mac) in hosts.items():
    	    if hname != other_name:
                host.cmd(f"arp -s {other_ip} {other_mac}")

    print("\n" + "=" * 55)
    print("DDoS Test Network Ready with BMv2 P4 Switch")
    print("=" * 55)
    print("Hosts:")
    print("  attacker1 : 10.0.0.1     MAC 00:00:00:00:00:01")
    print("  attacker2 : 10.0.0.2     MAC 00:00:00:00:00:02")
    print("  normal    : 10.0.0.3     MAC 00:00:00:00:00:03")
    print("  victim    : 10.0.0.100   MAC 00:00:00:00:00:04")
    print("")
    print("Test:")
    print("  pingall")
    print("  normal ping victim")
    print("  attacker1 ping victim")
    print("")
    print("Check BMv2 in another terminal:")
    print("  ps aux | grep simple_switch")
    print("  simple_switch_CLI --thrift-port 9090")
    print("=" * 55 + "\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()

