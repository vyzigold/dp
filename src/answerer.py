from scapy.all import *
from scapy.arch.linux import attach_filter
import socket

from src.rerouter import Rerouter, isReroute

from src.global_vars import DEBUG, DONE

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
