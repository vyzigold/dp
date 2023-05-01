#!/bin/python
import yaml
from struct import pack
import os
from enum import Enum
import socket
from scapy.all import *
import time
import threading
#import libpcap
from scapy.arch.linux import attach_filter
from warden_client import Client
import signal


DEBUG = False
DONE = False

def get_filter_host(ip):
    if "/" in ip:
        return "net " + ip
    else:
        return "host " + ip

class TimedTargets(threading.Thread):
    def __init__(self, conf):
        self.initial_filter = conf["filter"]
        if self.initial_filter == "":
            self.initial_filter = "tcp port 0" # shouldn't match anything
        self.filter = self.initial_filter
        self.targetList = []
        self.changed = True
        self.lock = threading.Lock()
        self.conf = conf
        threading.Thread.__init__(self)

    def get_filter(self):
        self.changed = False
        return self.filter
    
    def add(self, src, target):
        self.lock.acquire()
        self.targetList.append((time.time() + self.conf["reaction_duration"], src, target))
        self.lock.release()
        self.update()

    def update(self):
        self.lock.acquire()
        self.create_new_filter()
        self.regenerate_suricata()
        self.lock.release()

    def create_new_filter(self):
        self.filter = self.initial_filter
        for _, src, target in self.targetList:
            if src is not None and target is not None:
                filter_part = "(src {} and dst {})".format(get_filter_host(src), get_filter_host(target))
                self.filter = "(" + self.filter + ") or " + filter_part
                if DEBUG:
                    print("Adding filter: " + filter_part)
            elif src is not None:
                filter_part = "src {}".format(get_filter_host(src))
                self.filter = "(" + self.filter + ") or " + filter_part
                if DEBUG:
                    print("Adding filter: " + filter_part)
            elif target is not None:
                filter_part = "dst {}".format(get_filter_host(target))
                self.filter = "(" + self.filter + ") or " + filter_part
                if DEBUG:
                    print("Adding filter: " + filter_part)
        self.changed = True

    def regenerate_suricata(self):
        with open(self.conf["suricata_rules_filename"], "w") as file:
            for index, item in enumerate(self.targetList):
                _, src, target = item
                rule_string = "drop tcp "
                if src is None:
                    rule_string += "any "
                else:
                    rule_string += src + " "
                rule_string += "any -> "
                if target is None:
                    rule_string += "any "
                else:
                    rule_string += target + " "
                rule_string += "any (msg: \"active reaction rule\"; sid: {};)".format(10000+index)
                file.write(rule_string + "\n")
        os.system("kill -USR2 $(pidof suricata)")

    def run(self):
        while not DONE:
            poped = False
            while len(self.targetList) > 0 and self.targetList[0][0] < time.time():
                self.targetList.pop(0)
                poped = True
            if poped:
                self.update()
                if DEBUG:
                    print("Removed a target. New filter: {}".format(self.filter))
            time.sleep(1)
        os.remove(self.conf["suricata_rules_filename"])
        os.system("kill -USR2 $(pidof suricata)")


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
    def __init__(self, interface, interface_ip, conf):
        self.interface = interface
        self.interface_ip = interface_ip
        self.reroute_table = []
        self.conf = conf
        self.filter = "tcp port 0" # shouldn't match anything
        self.filter_changed = True
        self.lock = threading.Lock()
        threading.Thread.__init__(self)

    def add(self, dest_ip, src_ip, new_src_ip, dest_port, src_port, dest_mac):
        if (dest_ip, src_ip, new_src_ip, dest_port, src_port, dest_mac) not in self.reroute_table:
            self.reroute_table.append((dest_ip, src_ip, new_src_ip, dest_port, src_port, dest_mac))
            os.system("iptables -A INPUT -i {} -p tcp --dport {} --sport {} -j DROP".format(self.interface, dest_port, src_port))
            self.filter = "(" + self.filter + ")" + " or " + "(src host {} and src port {} and dst host {} and dst port {})".format(src_ip, src_port, self.interface_ip, dest_port)
            self.lock.acquire()
            self.filter_changed = True
            self.lock.release()
            if DEBUG:
                print("Adding: {}, {}, {}, {}, {}, {}".format(dest_ip, src_ip, new_src_ip, dest_port, src_port, dest_mac))
                print("New rerouter filter: " + self.filter)

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
        s.settimeout(1)
        print("Listening on: " + self.interface)
        prev = None
        while not DONE:
            if self.filter_changed:
                self.lock.acquire()
                attach_filter(s, self.filter, self.interface)
                if DEBUG:
                    print("Rerouter reattaching filter: {}".format(self.filter))
                self.filter_changed = False
                self.lock.release()
            try:
                frame = Ether(s.recv(10000))
            except:
                continue
            if frame.haslayer(IP) and frame.haslayer(TCP) and frame["TCP"].chksum != prev:
                prev = frame["TCP"].chksum
                addresses = self.get_new_addresses(frame)
                if addresses is None:
                    continue
                dest_mac, dest_ip, new_src_ip = addresses
                del frame["TCP"].chksum
                sendp(Ether(dst=dest_mac, src=self.conf["mac"])/IP(dst=dest_ip, src=new_src_ip)/frame["TCP"], iface=self.conf["interface"])
                if DEBUG:
                    print("Rerouting packet (backward reroute): {}, {}, {}".format(dest_mac, dest_ip, new_src_ip))



def listen(conf, reaction_targets):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((conf["interface"], 0))
    s.settimeout(1)
    attach_filter(s, reaction_targets.get_filter(), conf["interface"])
    print("Listening on: " + conf["interface"] + " with IP: " + conf["ip"] + " MAC: " + conf["mac"])
    rerouters = {}
    while not DONE:
        if reaction_targets.changed:
            attach_filter(s, reaction_targets.get_filter(), conf["interface"])
            if DEBUG:
                print("Reattaching filter")
                print(reaction_targets.get_filter())
        try:
            frame = Ether(s.recv(10000))
        except:
            continue
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
                    print("Rerouting packet (forward reroute): {}, {}".format(new_mac, new_ip))
                #new rerouter dict. interface names are keys
                if conf["reroute_targets"][port_status]["interface"] not in rerouters.keys():
                    rerouter = Rerouter(conf["reroute_targets"][port_status]["interface"], conf["reroute_targets"][port_status]["src_ip"], conf)
                    rerouters.update({conf["reroute_targets"][port_status]["interface"]: rerouter})
                    rerouter.start()

                rerouters[conf["reroute_targets"][port_status]["interface"]].add(scanner_ip, new_ip, dst_ip, scanner_port, my_port, scanner_mac)

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
                if port_status == PortStatus.FILTERED:
                    if DEBUG:
                        print("Sending nothing to: " + scanner_ip + ":" + str(scanner_port))
            elif frame["TCP"].flags == 0x10 or frame["TCP"].flags == 0x11: # ACK or ACK+FIN received
                if port_status != PortStatus.FILTERED:
                    if DEBUG:
                        print("Sending R to: " + scanner_ip + ":" + str(scanner_port))
                        print("From: " + conf["ip"] + ":" + str(my_port))
                    sendp(Ether(dst=scanner_mac, src=conf["mac"])/IP(dst=scanner_ip, src=conf["ip"])/TCP(sport=my_port, dport=scanner_port, flags="R", seq=200, ack=seq+1), iface=conf["interface"])

    # Cleanup rerouter threads - wait for them to end
    for rerouter in rerouters.values():
        rerouter.join()


def poll_warden(conf, reaction_targets):
    global REACTION_TARGETS
    if DEBUG:
        print("Running warden listener thread")

    wconf = conf["input"]["warden"]
    c = wconf["client_config"]

    wclient = Client(
            url = c["url"],
            keyfile = c["keyfile"],
            certfile = c["certfile"],
            cafile = c["cafile"],
            timeout = c["timeout"],
            errlog = {"level": c["errlog_level"]},
            filelog = {"level": c["filelog_level"]},
            idstore = c["idstore"],
            name = c["name"],
            )

    e_filter = wconf["event_filter"]

    cat = e_filter["categories"]
    nocat = e_filter["no_categories"]
    tag = e_filter["tag"]
    notag = e_filter["no_tag"]
    group = e_filter["group"]
    nogroup = e_filter["no_group"]

    while not DONE:
        events = wclient.getEvents(count=10, cat=cat, nocat=nocat, tag=tag, notag=notag, group=group, nogroup=nogroup)
        if DEBUG and len(events) > 0:
            print("Received " + str(len(events)) + " from warden")
        for e in events:
            sourceIps = []
            targetIps = []
            if "source" in wconf["match"]:
                sources = e.get("Source")
                for s in sources:
                    if s.get("IP4") != None:
                        for ip in s.get("IP4"):
                            sourceIps.append(ip)
            if "target" in wconf["match"]:
                targets = e.get("Target")
                for t in targets:
                    if t.get("IP4") != None:
                        for ip in t.get("IP4"):
                            targetIps.append(ip)

            if "source" in wconf["match"] and "target" in wconf["match"]:
                for s in sourceIps:
                    for t in targetIps:
                        reaction_targets.add(s, t)
            elif "source" in wconf["match"]:
                for s in sourceIps:
                    reaction_targets.add(s, None)
            elif "target" in wconf["match"]:
                for t in targetIps:
                    reaction_targets.add(None, t)
        time.sleep(wconf["polling_interval"])

def end_execution(sig, frame):
    global DONE
    DONE = True

def main():
    signal.signal(signal.SIGINT, end_execution)
    signal.signal(signal.SIGTERM, end_execution)
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

    threads = []

    reaction_targets = TimedTargets(conf)

    threads.append(reaction_targets)

    # port listening thread
    threads.append(Thread(target=listen, args=(conf, reaction_targets)))

    # warden polling thread
    if "warden" in conf["input"]:
        threads.append(Thread(target=poll_warden, args=(conf, reaction_targets)))

    for thread in threads:
        thread.start()

    # wait for threads to stop
    for thread in threads:
        thread.join()
    return 0


def backup_iptables():
    os.system("iptables-save > /tmp/iptables_backup")

def restore_iptables():
    os.system("iptables-restore < /tmp/iptables_backup")

if __name__ == "__main__":
    backup_iptables()
    return_value = main()
    restore_iptables()
    exit(return_value)
