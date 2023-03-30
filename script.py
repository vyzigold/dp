#!/bin/python
import yaml
import os
from enum import Enum
import socket
from scapy.all import *
import time
import threading

DEBUG = False

class ConfigError(Exception):
    pass

class PortStatus(Enum):
    CLOSED = 0
    OPENED = 1
    FILTERED = 2
    REDIRECT = 3

def parse_port_ranges(ports):
    result = []
    for p in ports:
        if "-" in p:
            edges = p.split("-")
            result += list(range(int(edges[0]), int(edges[1]) + 1))
        else:
            result.append(int(p))
    return result

def parse_behavior(behavior, reroute_targets):
    MIN_PORT = 0
    MAX_PORT = 65535
    default = PortStatus[behavior["default"].upper()]

    closed = []
    opened = []
    filtered = []
    reroutes = {}

    if "closed" in behavior:
        closed = parse_port_ranges(behavior["closed"])
    if "opened" in behavior:
        opened = parse_port_ranges(behavior["opened"])
    if "filtered" in behavior:
        filtered = parse_port_ranges(behavior["filtered"])

    for target in reroute_targets:
        if target in behavior:
            reroutes.update({target: parse_port_ranges(behavior[target])})

    if DEBUG:
        print("Closed: " + str(closed))
        print("Opened: " + str(opened))
        print("Filtered: " + str(filtered))
        print("Reroutes: " + str(reroutes))
        print("Default: " + str(default))

    result = []
    for x in range(MIN_PORT, MAX_PORT):
        occurances = 0
        if x in closed:
            result.append(PortStatus.CLOSED)
            occurances += 1
        if x in opened:
            result.append(PortStatus.OPENED)
            occurances += 1
        if x in filtered:
            result.append(PortStatus.FILTERED)
            occurances += 1
        for target, ports in reroutes.items():
            if x in ports:
                result.append(target)
                occurances += 1
                break

        if occurances == 0:
            result.append(default)
        if occurances > 1:
            raise ConfigError("Multiple actions configured for port '" + str(x) + "'")

    return result


def load_conf(filename):
    with open(filename, "r") as file:
        global DEBUG
        conf = yaml.load(file, yaml.Loader)
        if "debug" in conf and conf["debug"] == True:
            DEBUG = True

        if "behavior" not in conf:
            conf["behavior"] = {}
        if "default" not in conf["behavior"]:
            cenf["behavior"]["default"] = "closed"

        if "interface" not in conf:
            raise ConfigError("A required 'interface' option is missing in configuration file")

        if "ip" not in conf:
            conf["ip"] = get_if_addr(conf["interface"])
        if "mac" not in conf:
            conf["mac"] = get_if_hwaddr(conf["interface"])
        for target in conf["reroute_targets"]:
            src_ip = get_if_addr(conf["reroute_targets"][target]["interface"])
#            src_ip = "10.1.0.2"
            src_mac = get_if_hwaddr(conf["reroute_targets"][target]["interface"])
            conf["reroute_targets"][target]["src_ip"] = src_ip
            conf["reroute_targets"][target]["src_mac"] = src_mac

        conf["ports"] = parse_behavior(conf["behavior"], conf["reroute_targets"])
        return conf

def print_usage():
    print("Run: python script.py path_to_config_file.yaml\n")
    print("Take a look into doc/example_config.yaml to see an example config file with all possible values documented and explained.")

def isReroute(port):
    return not (port == PortStatus.OPENED or
                port == PortStatus.CLOSED or
                port == PortStatus.FILTERED)

class Rerouter(threading.Thread):
    def __init__(self, interface, conf):
        self.interface = interface
        self.reroute_table = []
        self.conf = conf
        threading.Thread.__init__(self)

    def add(self, dest_ip, src_ip, new_src_ip, dest_port, src_port, dest_mac):
        if (dest_ip, src_ip, new_src_ip, dest_port, src_port, dest_mac) not in self.reroute_table:
            self.reroute_table.append((dest_ip, src_ip, new_src_ip, dest_port, src_port, dest_mac))
            if DEBUG:
                print("Adding: {}, {}, {}, {}, {}, {}".format(dest_ip, src_ip, new_src_ip, dest_port, src_port, dest_mac))

    def get_new_addresses(self, frame):
        for dest_ip, src_ip, new_src_ip, dest_port, src_port, dest_mac in self.reroute_table:
            if (frame["IP"].src == src_ip and
                frame["TCP"].dport == dest_port and
                frame["TCP"].sport == src_port):
                return dest_mac, dest_ip, new_src_ip
        return None

    def run(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.bind((self.interface, 0))
        print("Listening on: " + self.interface)
        prev = None
        while True:
            frame = Ether(s.recv(10000))
            if frame.haslayer(IP) and frame.haslayer(TCP) and frame["TCP"].chksum != prev:
                prev = frame["TCP"].chksum
                addresses = self.get_new_addresses(frame)
                if addresses is None:
                    continue
                dest_mac, dest_ip, new_src_ip = addresses
                del frame["TCP"].chksum
                sendp(Ether(dst=dest_mac, src=self.conf["mac"])/IP(dst=dest_ip, src=new_src_ip)/frame["TCP"], iface=self.conf["interface"])
                if DEBUG:
                    print("Rerouting packet: {}, {}, {}".format(dest_mac, dest_ip, new_src_ip))

def listen(conf):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((conf["interface"], 0))
    print("Listening on: " + conf["interface"] + " with IP: " + conf["ip"] + " MAC: " + conf["mac"])
    rerouters = {}
    while True:
        frame = Ether(s.recv(10000))
        if frame.haslayer(IP) and frame.haslayer(TCP):
            scanner_mac = frame["Ether"].src
            scanner_ip = frame["IP"].src
            scanner_port = frame["TCP"].sport
            my_port = frame["TCP"].dport
            seq = frame["TCP"].seq
            port_status = conf["ports"][my_port]
            dst_ip = frame["IP"].dst

            if scanner_ip == conf["ip"]:
                continue

            if isReroute(port_status):
                new_ip = conf["reroute_targets"][port_status]["ip"]
                new_mac = conf["reroute_targets"][port_status]["mac"]
                del frame["TCP"].chksum
                if conf["reroute_targets"][port_status]["interface"] == scapy.all.conf.loopback_name:
                    scapy.all.conf.L3socket = L3RawSocket
                    send(IP(dst="127.0.0.1", src="127.0.0.1")/frame["TCP"])
                else:
                    sendp(Ether(dst=new_mac, src=conf["reroute_targets"][port_status]["src_mac"])/IP(dst=new_ip, src=conf["reroute_targets"][port_status]["src_ip"])/frame["TCP"], iface=conf["reroute_targets"][port_status]["interface"])
                if DEBUG:
                    print("Rerouting packet: {}, {}".format(new_mac, new_ip))
                #new rerouter dict. interface names are keys
                if conf["reroute_targets"][port_status]["interface"] not in rerouters.keys():
                    rerouter = Rerouter(conf["reroute_targets"][port_status]["interface"], conf)
                    rerouters.update({conf["reroute_targets"][port_status]["interface"]: rerouter})
                    rerouter.start()

                rerouters[conf["reroute_targets"][port_status]["interface"]].add(scanner_ip, new_ip, dst_ip, scanner_port, my_port, scanner_mac)
                # add new_ip, tcp_dst_port, tcp_src_port, old_ip

            elif frame["TCP"].flags == 0x2: # SYN received
                if port_status == PortStatus.OPENED:
                    if DEBUG:
                        print("Sending SA to: " + scanner_ip + ":" + str(scanner_port))
                        print("From: " + conf["ip"] + ":" + str(my_port))
                    sendp(Ether(dst=scanner_mac, src=conf["mac"])/IP(dst=scanner_ip, src=conf["ip"])/TCP(sport=my_port, dport=scanner_port, flags="SA", seq=200, ack=seq+1), iface=conf["interface"])
                if port_status == PortStatus.CLOSED:
                    if DEBUG:
                        print("Sending RA to: " + scanner_ip + ":" + str(scanner_port))
                        print("From: " + conf["ip"] + ":" + str(my_port))
                    sendp(Ether(dst=scanner_mac, src=conf["mac"])/IP(dst=scanner_ip, src=conf["ip"])/TCP(sport=my_port, dport=scanner_port, flags="RA", seq=200, ack=seq+1), iface=conf["interface"])
#                    sendp(Ether(dst=scanner_mac, src=conf["mac"])/IP(dst=scanner_ip, src=conf["ip"])/TCP(sport=my_port, dport=scanner_port, flags="RA", seq=200, ack=seq+1), iface=conf["interface"])
                if port_status == PortStatus.FILTERED:
                    if DEBUG:
                        print("Sending nothing to: " + scanner_ip + ":" + str(scanner_port))
            elif frame["TCP"].flags == 0x10 or frame["TCP"].flags == 0x11: # ACK or ACK+FIN received
                if port_status != PortStatus.FILTERED:
                    if DEBUG:
                        print("Sending R to: " + scanner_ip + ":" + str(scanner_port))
                        print("From: " + conf["ip"] + ":" + str(my_port))
                    sendp(Ether(dst=scanner_mac, src=conf["mac"])/IP(dst=scanner_ip, src=conf["ip"])/TCP(sport=my_port, dport=scanner_port, flags="R", seq=200, ack=seq+1), iface=conf["interface"])

def main():
    conf = None
    if len(os.sys.argv) != 2:
        print("Wrong number of arguments\n")
        print_usage()
        return 1
    try:
        conf = load_conf(os.sys.argv[1])
    except ConfigError as e:
        print(e)
        print_usage()
        return 2

#    reroute_ports(conf)
    listen(conf)

def reroute_ports(conf):
    os.system("iptables -t nat -A PREROUTING -i " + conf["interface"] + " -p tcp -m tcp --dport 1:65535 -j REDIRECT --to-ports " + str(conf["port"]))

def backup_iptables():
    os.system("iptables-save > /tmp/iptables_backup")

def restore_iptables():
    os.system("iptables-restore < /tmp/iptables_backup")

if __name__ == "__main__":
#    backup_iptables()
    return_value = main()
#    restore_iptables()
    exit(return_value)
