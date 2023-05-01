import threading
import socket
from scapy.all import *
from scapy.arch.linux import attach_filter

from src.global_vars import DEBUG, DONE

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
