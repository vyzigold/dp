import json

class Client:
    def __init__(self, url, keyfile, certfile, cafile, timeout, errlog, filelog, idstore, name):
        self.lastId = ""
        pass
    
    def getEvents(self, count, cat, nocat, tag, notag, group, nogroup):
        with open("warden-file", "r") as file:
            data = file.read()
            events = json.loads(data)
            if self.lastId != events[-1].get("ID"):
                self.lastId = events[-1].get("ID")
                return events
            else:
                return []
