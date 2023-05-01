#!/bin/python
import os
import threading
import signal

from threading import Thread

from src.configuration import load_conf, print_usage, ConfigError
from src.target_management import TimedTargets
from src.answerer import listen
from src.warden_poller import poll_warden

from src.global_vars import DEBUG, DONE

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
