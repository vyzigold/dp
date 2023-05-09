"""Fake warden client

This module is there to simulate a proper warden client.
A normal warden client would talk to warden to get
data about incidents, for the purposes of testing,
this client just reads a file with incidents.

Delete this file and use a proper client when trying to run with
the real warden.

This file includes the following class:
    Client - tries to behave like the real warden client to the
             outside

@author Jaromir Wysoglad (xwysog00)
"""
import json


class Client:
    """
    A mocked warden client. Tries to behave the same way as
    the real client to the outside code. So far, this class
    implements only the __init__ and getEvents methods.
    """
    def __init__(self, url, keyfile, certfile, cafile,
                 timeout, errlog, filelog, idstore, name):
        """
        A constructor, that tries to have the same function
        signature as the real warden client constructor, but
        actually does nothing.
        """
        self.lastId = ""
        pass

    def getEvents(self, count, cat, nocat, tag, notag, group, nogroup):
        """
        A function, that tries to have the same function
        signature as the real getEvents from real warden client.
        This actually reads events from "warden-file" file and
        returns all new incidents found there, no matter
        what parameters were given to this function.
        """
        try:
            with open("warden-file", "r") as file:
                data = file.read()
                events = json.loads(data)
                if self.lastId != events[-1].get("ID"):
                    self.lastId = events[-1].get("ID")
                    return events
                else:
                    return []
        except Exception:
            return []
