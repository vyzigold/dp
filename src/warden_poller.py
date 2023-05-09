"""This module takes care of polling warden for information

It'll try to periodically ask warden for new events, to which
it should react. Each iteration it will get new events, process
them and wait for `polling_interval` configured in the main
configuration file.

This file includes the following functions:
    process_event - processes a single event
    poll_warden - periodically asks warden for events

@author Jaromir Wysoglad (xwysog00)
"""

import time
from src.warden_client import Client
from src.global_vars import Globals


def process_event(e, match, reaction_targets):
    """The function processes a single event

    Based on the match config parameter it extracts source
    and target IP addresses from the event and adds them
    to the reaction_targets.

    @type e: warden event
    @param e: The event to process
    @type match: list
    @param match: list of strings from config file
    @type reaction_targets: TimedTargets instance
    @param reaction_targets: instance of TimedTargets to which
                            new targets should be added
    """
    sourceIps = []
    targetIps = []
    # Extract the IPs
    if "source" in match:
        sources = e.get("Source")
        for s in sources:
            if s.get("IP4") is not None:
                for ip in s.get("IP4"):
                    sourceIps.append(ip)
    if "target" in match:
        targets = e.get("Target")
        for t in targets:
            if t.get("IP4") is not None:
                for ip in t.get("IP4"):
                    targetIps.append(ip)

    # Add the extracted targets
    if "source" in match and "target" in match:
        for s in sourceIps:
            for t in targetIps:
                reaction_targets.add(s, t)
    elif "source" in match:
        for s in sourceIps:
            reaction_targets.add(s, None)
    elif "target" in match:
        for t in targetIps:
            reaction_targets.add(None, t)


def poll_warden(conf, reaction_targets):
    """Periodically gets new events from warden

    This function should periodically get events from warden
    and send them to the process_event() function. The time
    it waits between each iteration can be configured in the
    polling_interval in the main configuration file.

    The function is intended to run in a thread. It'll run
    for ever while Globals.DONE != True.

    @type conf: dictionary
    @param conf: The project configuration
    @type reaction_targets: TimedTargets instance
    @param reaction_targets: instance of TimedTargets to which
                            new targets should be added
    """
    if Globals.DEBUG:
        print("Running warden listener thread")

    # client creation and config extraction
    wconf = conf["input"]["warden"]
    c = wconf["client_config"]

    wclient = Client(
            url=c["url"],
            keyfile=c["keyfile"],
            certfile=c["certfile"],
            cafile=c["cafile"],
            timeout=c["timeout"],
            errlog={"level": c["errlog_level"]},
            filelog={"level": c["filelog_level"]},
            idstore=c["idstore"],
            name=c["name"],
            )

    e_filter = wconf["event_filter"]

    cat = e_filter["categories"]
    nocat = e_filter["no_categories"]
    tag = e_filter["tag"]
    notag = e_filter["no_tag"]
    group = e_filter["group"]
    nogroup = e_filter["no_group"]

    while not Globals.DONE:
        events = wclient.getEvents(count=10,
                                   cat=cat,
                                   nocat=nocat,
                                   tag=tag,
                                   notag=notag,
                                   group=group,
                                   nogroup=nogroup)
        if Globals.DEBUG and len(events) > 0:
            print("Received " + str(len(events)) + " from warden")
        for e in events:
            process_event(e, wconf["match"], reaction_targets)
        time.sleep(wconf["polling_interval"])
