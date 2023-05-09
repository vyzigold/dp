"""Module, that takes care of rerouting.

The module takes care of rerouting, both forward reroutes
(from primary interfaces / from attacker to secondary interfaces
/ to victims) and backward reroutes (from secondary interfaces
to primary interface). Forward reroute is done by the
reroute_frame function, while backward rerouting is done by
the Rerouter class. Each instance of that class takes care
about a single secondary interface.



This file includes the following functions:
    isReroute - checks if the port is configured to be rerouted
    reroute_frame - performs a forward reroute

This file includes the following classes:
    Rerouter - Listens on interfaces, does backward reroutes


@author Jaromir Wysoglad (xwysog00)
"""

import threading
import socket
from scapy.all import sendp, Ether, IP, TCP, L3RawSocket, send
from scapy.all import conf as scapy_conf
import os

from src.global_vars import Globals
from src.configuration import PortStatus


def isReroute(port):
    """Checks the port configuration

    @type port: integer
    @param port: port number to check
    @rtype: boolean
    @returns: True if the port is configured to be rerouted
    """
    return not (port == PortStatus.OPENED or
                port == PortStatus.CLOSED or
                port == PortStatus.FILTERED)


def reroute_frame(conf, frame, reroute_target, rerouters):
    """Reroutes a frame

    Sends a frame from the appropriate interface with the correct
    addresses. It also creates new Rerouter instances when
    needed. In the end it adds new targets to running
    Rerouter instances.

    @type conf: dictionary
    @param conf: parsed project configuration
    @type frame: scapy Frame instance
    @param frame: the received frame to be rerouted
    @type reroute_target: dictionary
    @param reroute_target: part of conf with information about
                            where to reroute the frame
    @type rerouters: dictionary
    @param rerouters: Dict of all Rerouter instances
    """
    new_ip = reroute_target["ip"]
    new_mac = reroute_target["mac"]
    out_iface = reroute_target["interface"]

    del frame["TCP"].chksum

    if out_iface == scapy_conf.loopback_name:
        # We need to use L3 socket for localhost
        scapy_conf.L3socket = L3RawSocket
        send(IP(dst="127.0.0.1", src="127.0.0.1")/frame["TCP"])
    else:
        # Use L2 socket for everything else
        sendp(Ether(dst=new_mac, src=reroute_target["src_mac"]) /
              IP(dst=new_ip, src=reroute_target["src_ip"]) /
              frame["TCP"], iface=out_iface)
    if Globals.DEBUG:
        print("Rerouting packet (forward reroute): {}, {}"
              .format(new_mac, new_ip))

    if out_iface not in rerouters.keys():
        # Create a new instance of rerouter for
        # previously unused outgoing interface
        rerouter = Rerouter(out_iface,
                            reroute_target["src_ip"],
                            conf)
        rerouters.update({out_iface: rerouter})
        rerouter.start()


class Rerouter(threading.Thread):
    """Class for performing backward rerouting

    It listens on a secondary interface (an interface
    facing a configured reroute target). If it detects
    a packet, which should be rerouted back to the primary
    interface, it does the necessary steps to get the packet
    rerouted.

    The instances of this class run in their own thread.

    The class includes the following methods:
        add: add a new target for backward reroute
        get_new_addresses: returns new addresses for rerouted packets
        process_frame: reroutes a single frame
        run: runs the rerouting thread
    """
    def __init__(self, interface, interface_ip, conf):
        """
        @type interface: string
        @param interface: secondary interface on which to listen
        @type interface_ip: string
        @param interface_ip: IP address of the interface
        @type conf: dictionary
        @param conf: Main project configuration
        """
        self.interface = interface
        self.interface_ip = interface_ip
        self.reroute_table = []
        self.conf = conf
        threading.Thread.__init__(self)

    def add(self, dest_ip, src_ip, new_src_ip,
            dest_port, src_port, dest_mac):
        """Adds a new rerouting target to the rerouting table

        @type dest_ip: string
        @param dest_ip: new destination IP after reroute (attacker)
        @type src_ip: string
        @param src_ip: IP of the target from config before reroute
        @type new_src_ip: string
        @param new_src_ip: IP of the original victim
        @type dest_port: integer
        @param dest_port: dst port of arriving packets from target
        @type src_port: integer
        @param src_port: src port of arriving packets from target
        @type dest_mac: string
        @param dest_mac: next hop mac after backward reroute
        """
        if ((dest_ip, src_ip, new_src_ip,
             dest_port, src_port, dest_mac) not in
                self.reroute_table):
            self.reroute_table.append((dest_ip, src_ip,
                                       new_src_ip, dest_port,
                                       src_port, dest_mac))
            os.system("iptables -A INPUT -i {} -p tcp "
                      "--dport {} --sport {} -j DROP"
                      .format(self.interface, dest_port, src_port))
            if Globals.DEBUG:
                print("Adding: {}, {}, {}, {}, {}, {}"
                      .format(dest_ip, src_ip, new_src_ip,
                              dest_port, src_port, dest_mac))

    def get_new_addresses(self, frame):
        """Extracts the required new addresses for a reroute

        @type frame: scapy Frame
        @param frame: The frame to reroute
        @rtype: tuple or None
        @returns: (dest_mac, dest_ip, new_src_ip) if the
                packet should be rerouted. None otherwise
        """
        for addresses in self.reroute_table:
            dst_ip, src_ip, new_src_ip, dst_port, src_port, dst_mac = addresses
            if (frame["IP"].src == src_ip and
                    frame["TCP"].dport == dst_port and
                    frame["TCP"].sport == src_port):
                return dst_mac, dst_ip, new_src_ip
        return None

    def process_frame(self, frame):
        """Processes a single frame

        If the frame should be backward rerouted,
        it performes the reroute

        @type frame: scapy Frame
        @param frame: The received frame to be rerouted
        """
        addresses = self.get_new_addresses(frame)
        if addresses is None:
            return
        dest_mac, dest_ip, new_src_ip = addresses
        del frame["TCP"].chksum
        sendp(Ether(dst=dest_mac, src=self.conf["mac"]) /
              IP(dst=dest_ip, src=new_src_ip) /
              frame["TCP"],
              iface=self.conf["interface"])
        if Globals.DEBUG:
            print("Rerouting packet "
                  "(backward reroute): {}, {}, {}"
                  .format(dest_mac, dest_ip, new_src_ip))

    def run(self):
        """The run function of the thread

        It initializes the listening socket. After that
        it periodically listens on the socket and calls
        process_frame on each received frame.

        This function should run in a thread and will not stop
        while Globals.DONE != True
        """
        s = socket.socket(socket.AF_PACKET,
                          socket.SOCK_RAW,
                          socket.htons(3))
        s.bind((self.interface, 0))
        s.settimeout(1)
        print("Listening on: " + self.interface)
        prev = None
        while not Globals.DONE:
            try:
                frame = Ether(s.recv(10000))
            except Exception:
                continue
            if (frame.haslayer(IP) and
                    frame.haslayer(TCP) and
                    frame["TCP"].chksum != prev):

                prev = frame["TCP"].chksum
                self.process_frame(frame)
