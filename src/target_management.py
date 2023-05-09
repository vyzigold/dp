"""Module, that takes care of target management.

The contents of this module take care of managing reaction
targets. When a new target, to which the project should
react is detected, it's added to a list of targets in
the TimedTargets class. The target stays there for a configured
amount of time, after which it's deleted and the project won't
react to traffic comming from that target. The class also takes
care about regenerating bpf filter for the socked listened to
by the answerer and generating rules for suricata based on
the targets.


This file includes the following functions:
    get_filter_host - a helper function for determining if
                      an ip address is a single host or a subnet.

This file includes the following classes:
    TimedTargets - A class, that manages reaction targets


@author Jaromir Wysoglad (xwysog00)
"""

import threading
import time
import os
from src.global_vars import Globals


def get_filter_host(ip):
    """ Helper function for determining if an IP is a single
    host of a subnet.

    @type ip: string
    @param ip: string containing an ip address or a
                subnet address in format x.x.x.x/yy

    @rtype: string
    @returns: a part of bpf filter corresponding to that ip address
    """
    if "/" in ip:
        return "net " + ip
    else:
        return "host " + ip


class TimedTargets(threading.Thread):
    """Class for managing reaction targets

    It can manage targets, each target is active only for
    a certain amount of time. It can generate bpf filter and
    suricata rules based on the targets.

    The class includes the following methods:
        get_filter: used to get the current bpf filter
        add: add a new target
        update: update the current bpf filter and suricata rules
        create_new_filter: creates a bpf filter based on targets
        regenerate_suricata: regenerates suricata rules
        run: runs the thread to discard old targets
    """
    def __init__(self, conf):
        """
        @type conf: dictionary
        @param conf: configuration of the project
        """
        self.initial_filter = conf["filter"]
        if self.initial_filter == "":
            # shouldn't match anything
            self.initial_filter = "tcp port 0"
        self.filter = self.initial_filter
        self.targetList = []
        self.changed = True
        self.lock = threading.Lock()
        self.conf = conf
        threading.Thread.__init__(self)

    def get_filter(self):
        """Returns the current bpf filter

        @rtype: string
        @returns: current bpf filter
        """
        self.changed = False
        return self.filter

    def add(self, src, target):
        """Adds a new target

        @type src: string
        @param src: source ip address of the attacker
        @type target: string
        @param target: target ip address of the victim
        """
        self.lock.acquire()
        self.targetList.append((time.time() + self.conf["reaction_duration"],
                                src, target))
        self.lock.release()
        self.update()

    def update(self):
        """Updates the bpf filter and suricata rules

        Helper method for updating everything after the targets
        change. It takes care of proper locking and calls the
        create_new_filter and regenerate_suricata functions.
        """
        self.lock.acquire()
        self.create_new_filter()
        self.regenerate_suricata()
        self.lock.release()

    def create_new_filter(self):
        """Creates a new bpf filter
        """
        self.filter = self.initial_filter
        for _, src, target in self.targetList:
            filter_part = ""
            if src is not None and target is not None:
                filter_part = "(src {} and dst {})".format(
                        get_filter_host(src),
                        get_filter_host(target)
                        )
            elif src is not None:
                filter_part = "src {}".format(get_filter_host(src))
            elif target is not None:
                filter_part = "dst {}".format(
                        get_filter_host(target)
                        )

            if Globals.DEBUG:
                print("Adding filter: " + filter_part)
            self.filter = "({}) or {}".format(self.filter, filter_part)
        self.changed = True

    def regenerate_suricata(self):
        """Generates new set of suricata rules based on targets
        """
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
                rule_string += "any (msg: \"active reaction rule\";"
                rule_string += " sid: {};)".format(10000+index)
                file.write(rule_string + "\n")
        try:
            rv = os.system("kill -USR2 $(pidof suricata)")
            if rv != 0:
                raise Exception
        except Exception:
            print("Cannot communicate with suricata, is it running?")
            Globals.DONE = True

    def run(self):
        """Runs a thread to manage targets

        Each iteration it compares current time and the time
        when the oldest target should expire. When the target
        should expire, it deletes it from the target list and
        updates the filters and rules. At the end
        it sleeps a second before next iteration.
        """
        while not Globals.DONE:
            poped = False
            # targetList[0][0] is the expration time of
            # the oldest target
            while (len(self.targetList) > 0 and
                   self.targetList[0][0] < time.time()):
                self.targetList.pop(0)
                poped = True
            if poped:
                self.update()
                if Globals.DEBUG:
                    print("Removed a target. New filter: {}"
                          .format(self.filter))
            time.sleep(1)
        try:
            os.remove(self.conf["suricata_rules_filename"])
        except Exception:
            pass
        os.system("kill -USR2 $(pidof suricata)")
