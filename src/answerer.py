"""Module containing Answerer

Answerer listens on configured interface. If
it detects traffic coming from a target, to which the
project should react, it either directly reacts, if the
traffic is a port scan, or it sends the traffic
to rerouter if the traffic should be rerouted.

The port scan answers look like this:
If SYN packet is received, it answers based on config with:
Config value | answer
Opened         SYN + ACK
Closed         RST + ACK
Filtered       Nothing

If ACK or ACK + FIN is received and the port isn't configured
as filtered, the answer is RST.

This file includes the following functions:
    init_socket - initializes the listening socket
    reroute_frame - reroutes a frame
    react - sends an appropriate reaction to a packet
    listen - listens on a socket

@author Jaromir Wysoglad (xwysog00)
"""

from scapy.all import sendp, Ether, IP, TCP
from scapy.arch.linux import attach_filter
import socket

from src.rerouter import isReroute, reroute_frame
from src.configuration import PortStatus

from src.global_vars import Globals


def init_socket(conf, reaction_targets):
    """Initializes a socket

    This function is called once at the start of the
    listening thread. it initializes the listening socket.

    @type conf: dictionary
    @param conf: parsed project configuration
    @type reaction_targets: TimedTargets
    @param reaction_targets: TimedTargets instance containing
                            targets to which we should react

    @rtype: socket
    @returns: initialized socket
    """
    s = socket.socket(socket.AF_PACKET,
                      socket.SOCK_RAW,
                      socket.htons(3))
    s.bind((conf["interface"], 0))
    s.settimeout(1)
    attach_filter(s,
                  reaction_targets.get_filter(),
                  conf["interface"])

    print("Listening on: {} with IP: {} MAC: {}"
          .format(conf["interface"], conf["ip"], conf["mac"]))
    return s


def react(conf, frame, rerouters):
    """Function performing active reaction to a frame

    When given a frame, it tries to perform an active
    reaction based on the frame and configuration.

    @type conf: dictionary
    @param conf: parsed project configuration
    @type frame: scapy Frame instance
    @param frame: the received frame to be rerouted
    @type rerouters: dictionary
    @param rerouters: Dict of all Rerouter instances
    """
    scanner_mac = frame["Ether"].src
    scanner_ip = frame["IP"].src
    scanner_port = frame["TCP"].sport
    my_port = frame["TCP"].dport
    seq = frame["TCP"].seq
    port_action = conf["ports"][my_port]
    dst_ip = frame["IP"].dst

    if scanner_ip == conf["ip"]:
        return

    if isReroute(port_action):
        reroute_target = conf["reroute_targets"][port_action]
        new_ip = reroute_target["ip"]
        out_iface = reroute_target["interface"]

        reroute_frame(conf,
                      frame,
                      reroute_target,
                      rerouters)

        # Add new rerouting target to the rerouter
        rerouters[out_iface].add(scanner_ip,
                                 new_ip,
                                 dst_ip,
                                 scanner_port,
                                 my_port,
                                 scanner_mac)

    elif frame["TCP"].flags == 0x2:
        # SYN received
        if port_action == PortStatus.OPENED:
            if Globals.DEBUG:
                print("Sending SA to: {}:{}"
                      .format(scanner_ip, scanner_port))
                print("From: {}:{}"
                      .format(dst_ip, my_port))

            # Sending SA
            sendp(Ether(dst=scanner_mac, src=conf["mac"]) /
                  IP(dst=scanner_ip, src=dst_ip) /
                  TCP(sport=my_port, dport=scanner_port,
                      flags="SA", seq=200, ack=seq+1),
                  iface=conf["interface"])
        if port_action == PortStatus.CLOSED:
            if Globals.DEBUG:
                print("Sending RA to: {}:{}"
                      .format(scanner_ip, scanner_port))
                print("From: {}:{}"
                      .format(dst_ip, my_port))

            # Sending RA
            sendp(Ether(dst=scanner_mac, src=conf["mac"]) /
                  IP(dst=scanner_ip, src=dst_ip) /
                  TCP(sport=my_port, dport=scanner_port,
                      flags="RA", seq=200, ack=seq+1),
                  iface=conf["interface"])
        if port_action == PortStatus.FILTERED:
            if Globals.DEBUG:
                print("Sending nothing to: {}:{}"
                      .format(scanner_ip, scanner_port))
    elif (frame["TCP"].flags == 0x10 or
          frame["TCP"].flags == 0x11):
        # ACK or ACK+FIN received
        if port_action != PortStatus.FILTERED:
            if Globals.DEBUG:
                print("Sending R to: {}:{}"
                      .format(scanner_ip, scanner_port))
                print("From: {}:{}"
                      .format(dst_ip, my_port))

            # Sending R
            sendp(Ether(dst=scanner_mac, src=conf["mac"]) /
                  IP(dst=scanner_ip, src=dst_ip) /
                  TCP(sport=my_port, dport=scanner_port,
                      flags="R", seq=200, ack=seq+1),
                  iface=conf["interface"])


def listen(conf, reaction_targets):
    """Thread listening on a socket for incoming packets

    This function should be run in a thread. It will
    keep running until Globals.DONE != True. In each
    iteration it checks if the targets changed and if they
    did, it applies a new filter to the listening socket.
    After this it goes through all the received frames
    and calls react() on each of them. At the end
    it waits for all rerouters to finish.

    @type conf: dictionary
    @param conf: parsed project configuration
    @type reaction_targets: TimedTargets
    @param reaction_targets: TimedTargets instance containing
                            targets to which we should react
    """
    s = init_socket(conf, reaction_targets)
    rerouters = {}

    while not Globals.DONE:
        # react to targets getting changed since last iteration
        if reaction_targets.changed:
            attach_filter(s,
                          reaction_targets.get_filter(),
                          conf["interface"])
            if Globals.DEBUG:
                print("Reattaching filter")
                print(reaction_targets.get_filter())

        try:
            frame = Ether(s.recv(10000))
        except Exception:
            continue

        if frame.haslayer(IP) and frame.haslayer(TCP):
            react(conf, frame, rerouters)

    # Cleanup rerouter threads at the end - wait for them to end
    for rerouter in rerouters.values():
        rerouter.join()
