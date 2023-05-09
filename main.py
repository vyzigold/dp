#!/usr/bin/env python3
"""Active attack reaction script

This script allows for performing an active reaction
to a network attack. It is expected to be run on a device,
through which the attack is going through. It is also
expected, that the device is using suricata in Layer 2 IPS mode
to achieve that the trafic is going through the device.

The script can be used for 2 different types of attack.
1. It can be configured to answer a port scan instead of a
    victim, that is somewhere further inside the defended network.
    The answers can be configured, so that each port appears
    either as opened, closed or droped.
2. It can be configured to reroute trafic to a honeypot
    and thanks to this the defender can observe an ongoing
    attack as it's happening. The attacker doesn't notice
    the reroute.

This file includes the following functions:
    end_execution - callback called when receiving a signal
    main - the main function of the script
    backup_iptables - makes an iptables backup
    restore_iptables - restores iptables from a backup

@author Jaromir Wysoglad (xwysog00)
"""

import os
import signal

from threading import Thread
from scapy.all import conf as scapy_conf

from src.configuration import load_conf, print_usage, ConfigError
from src.target_management import TimedTargets
from src.answerer import listen
from src.warden_poller import poll_warden

from src.global_vars import Globals


def end_execution(sig, frame):
    """Callback for handling signals.

    Sets the global DONE variable to True

    @param sig: signal type
    @param frame: stack frame
    """

    Globals.DONE = True


def main():
    """Main function of the script

    Sets up signal handling, checks arguments, executes
    functions to load the configuration, starts all threads
    and afterwards waits for all threads to finish.
    """
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

    if Globals.DEBUG is False:
        scapy_conf.verb = 0
    threads = []

    reaction_targets = TimedTargets(conf)

    threads.append(reaction_targets)

    # port listening thread
    threads.append(Thread(target=listen, args=(conf, reaction_targets)))

    # warden polling thread
    if "warden" in conf["input"] and conf["input"]["warden"] is not None:
        threads.append(Thread(target=poll_warden,
                              args=(conf, reaction_targets)))

    for thread in threads:
        thread.start()

    # wait for threads to stop
    for thread in threads:
        thread.join()
    return 0


def backup_iptables():
    """Function to backup the iptables"""
    os.system("iptables-save > /tmp/iptables_backup")


def restore_iptables():
    """Function to restore the iptables from a backup"""
    os.system("iptables-restore < /tmp/iptables_backup")


if __name__ == "__main__":
    backup_iptables()
    return_value = main()
    restore_iptables()
    exit(return_value)
