import time
from src.warden_client import Client
from src.global_vars import DEBUG, DONE

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
