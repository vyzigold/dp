import yaml
from enum import Enum
from scapy.all import *

from src.global_vars import DEBUG, DONE
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
            src_mac = get_if_hwaddr(conf["reroute_targets"][target]["interface"])
            conf["reroute_targets"][target]["src_ip"] = src_ip
            conf["reroute_targets"][target]["src_mac"] = src_mac

        conf["ports"] = parse_behavior(conf["behavior"], conf["reroute_targets"])
        return conf

def print_usage():
    print("Run: python script.py path_to_config_file.yaml\n")
    print("Take a look into doc/example_config.yaml to see an example config file with all possible values documented and explained.")
