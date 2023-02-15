#!/bin/python
import yaml
import os
from enum import Enum
import socket
from scapy.all import *
import time

DEBUG = False

class ConfigError(Exception):
    pass

class PortStatus(Enum):
    CLOSED = 0
    OPENED = 1
    FILTERED = 2

def parse_port_ranges(ports):
    result = []
    for p in ports:
        if "-" in p:
            edges = p.split("-")
            result += list(range(int(edges[0]), int(edges[1]) + 1))
        else:
            result.append(int(p))
    return result


def parse_behavior(behavior):
    MIN_PORT = 0
    MAX_PORT = 65535
    default = PortStatus[behavior["default"].upper()]

    closed = []
    opened = []
    filtered = []

    if "closed" in behavior:
        closed = parse_port_ranges(behavior["closed"])
    if "opened" in behavior:
        opened = parse_port_ranges(behavior["opened"])
    if "filtered" in behavior:
        filtered = parse_port_ranges(behavior["filtered"])

    if DEBUG:
        print("Closed: " + str(closed))
        print("Opened: " + str(opened))
        print("Filtered: " + str(filtered))
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

        conf["ports"] = parse_behavior(conf["behavior"])
        return conf

def print_usage():
    print("Run: python script.py path_to_config_file.yaml\n")
    print("Take a look into doc/example_config.yaml to see an example config file with all possible values documented and explained.")

def listen(conf):
    s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((conf["interface"], 0))
    if DEBUG:
        print("Listening on " + conf["interface"])
    while True:
        p = s.recv(2000)
        eth = Ether(p)
        if TCP in eth:
            print(time.time())
            os.sys.stdout.write("<%s>\n\n"%eth["IP"].show())

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

    reroute_ports(conf)
    listen(conf)

def reroute_ports(conf):
    os.system("iptables -t nat -A PREROUTING -i " + conf["interface"] + " -p tcp -m tcp --dport 1:65535 -j REDIRECT --to-ports " + str(conf["port"]))

def backup_iptables():
    os.system("iptables-save > /tmp/iptables_backup")

def restore_iptables():
    os.system("iptables-restore < /tmp/iptables_backup")

if __name__ == "__main__":
    backup_iptables()
    return_value = main()
    restore_iptables()
    exit(return_value)
