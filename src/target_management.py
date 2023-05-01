import threading
import time
import os
from src.global_vars import DEBUG, DONE

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
