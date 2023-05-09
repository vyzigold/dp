"""Module used for parsing configuration

This file includes the following functions:
    parse_port_ranges - Parses ports
    parse_behavior - parses the behavior part of config
    load_conf - loads configuration from file
    print_usage - prints usage message

This file includes the following classes:
    ConfigError: Exception for config errors
    PortStatus: Enum containing all possible port statuses

@author Jaromir Wysoglad (xwysog00)
"""

import yaml
from enum import Enum
from scapy.all import get_if_addr, get_if_hwaddr

from src.global_vars import Globals

CONFIG_STRUCTURE = {
        "interface": {
            "required": True,
            "default": None,
            "children": {}
            },
        "ip": {
            "required": False,
            "default": None,
            "children": {}
            },
        "debug": {
            "required": False,
            "default": False,
            "children": {}
            },
        "reaction_duration": {
            "required": False,
            "default": 60,
            "children": {}
            },
        "suricata_rules_filename": {
            "required": False,
            "default": "reaction.rules",
            "children": {}
            },
        "filter": {
            "required": False,
            "default": "",
            "children": {}
            },


        # The contents of reroute_targets are checked separately
        "reroute_targets": {
            "required": False,
            "default": None,
            "children": {}
            },

        "behavior": {
            "required": False,
            "default": {
                "filtered": [],
                "opened": [],
                "closed": []
                },
            "children": {
                "filtered": {
                    "required": False,
                    "default": [],
                    "children": {}
                    },
                "opened": {
                    "required": False,
                    "default": [],
                    "children": {}
                    },
                "closed": {
                    "required": False,
                    "default": [],
                    "children": {}
                    },
                "default": {
                    "required": False,
                    "default": "closed",
                    "children": {}
                    }
                }
            },


        "input": {
            "required": False,
            "default": None,
            "children": {
                "warden": {
                    "required": False,
                    "default": None,
                    "children": {
                        "client_config": {
                            "required": True,
                            "default": None,
                            "children": {
                                "url": {
                                    "required": True,
                                    "default": None,
                                    "children": {}
                                    },
                                "keyfile": {
                                    "required": True,
                                    "default": None,
                                    "children": {}
                                    },
                                "certfile": {
                                    "required": True,
                                    "default": None,
                                    "children": {}
                                    },
                                "cafile": {
                                    "required": True,
                                    "default": None,
                                    "children": {}
                                    },
                                "timeout": {
                                    "required": False,
                                    "default": 10,
                                    "children": {}
                                    },
                                "errlog_level": {
                                    "required": False,
                                    "default": "debug",
                                    "children": {}
                                    },
                                "filelog_level": {
                                    "required": False,
                                    "default": "debug",
                                    "children": {}
                                    },
                                "idstore": {
                                    "required": True,
                                    "default": None,
                                    "children": {}
                                    },
                                "name": {
                                    "required": True,
                                    "default": None,
                                    "children": {}
                                    }
                                }
                            },
                        "event_filter": {
                            "required": True,
                            "default": None,
                            "children": {
                                "categories": {
                                    "required": False,
                                    "default": [],
                                    "children": {}
                                    },
                                "no_categories": {
                                    "required": False,
                                    "default": [],
                                    "children": {}
                                    },
                                "tag": {
                                    "required": False,
                                    "default": [],
                                    "children": {}
                                    },
                                "no_tag": {
                                    "required": False,
                                    "default": [],
                                    "children": {}
                                    },
                                "group": {
                                    "required": False,
                                    "default": [],
                                    "children": {}
                                    },
                                "no_group": {
                                    "required": False,
                                    "default": [],
                                    "children": {}
                                    }
                                }
                            },
                        "polling_interval": {
                            "required": False,
                            "default": 1,
                            "children": {}
                            },
                        "match": {
                            "required": False,
                            "default": ["source"],
                            "children": {}
                            }
                        }
                    }
                }
            }
        }

REROUTE_TARGET_STRUCTURE = {
        "ip": {
            "required": True,
            "default": None,
            "children": {}
            },
        "mac": {
            "required": True,
            "default": None,
            "children": {}
            },
        "interface": {
            "required": True,
            "default": None,
            "children": {}
            }
        }


class ConfigError(Exception):
    """Used for configuration error exceptions
    """
    pass


class PortStatus(Enum):
    """Enum containing all possible port statuses
    """
    CLOSED = 0
    OPENED = 1
    FILTERED = 2
    REDIRECT = 3


def parse_port_ranges(ports):
    """Used to parse port notations

    @type ports: string
    @param ports: string containing either an integer
                    or a range like 10-20
    @rtype: list
    @returns: list of single ports
    """
    result = []
    for p in ports:
        if "-" in p:
            edges = p.split("-")
            result += list(range(int(edges[0]), int(edges[1]) + 1))
        else:
            result.append(int(p))
    return result


def parse_behavior(behavior, reroute_targets):
    """Used to parse the behavior part of configuration

    @type behavior: dictionary
    @param behavior: The behavior part of configuration
    @type reroute_targets: dictionary
    @param reroute_targets: The reroute_targets part of configuration

    @rtype: list
    @returns: list of length 65536. Each element is a
                PortStatus for that port (list index == port number)
    """
    MIN_PORT = 0
    MAX_PORT = 65535
    default = PortStatus[behavior["default"].upper()]

    closed = []
    opened = []
    filtered = []
    reroutes = {}

    if "closed" in behavior:
        closed = parse_port_ranges(behavior["closed"])
    if "opened" in behavior:
        opened = parse_port_ranges(behavior["opened"])
    if "filtered" in behavior:
        filtered = parse_port_ranges(behavior["filtered"])

    for target in reroute_targets:
        if target in behavior:
            reroutes.update({target: parse_port_ranges(behavior[target])})

    if Globals.DEBUG:
        print("Closed: " + str(closed))
        print("Opened: " + str(opened))
        print("Filtered: " + str(filtered))
        print("Reroutes: " + str(reroutes))
        print("Default: " + str(default))

    result = []
    for x in range(MIN_PORT, MAX_PORT):
        occurances = 0
        if x in closed:
            result.append(PortStatus.CLOSED)
            occurances += 1
        if x in opened:
            result.append(PortStatus.OPENED)
            occurances += 1
        if x in filtered:
            result.append(PortStatus.FILTERED)
            occurances += 1
        for target, ports in reroutes.items():
            if x in ports:
                result.append(target)
                occurances += 1
                break

        if occurances == 0:
            result.append(default)
        if occurances > 1:
            raise ConfigError("Multiple actions configured for"
                              " port '" + str(x) + "'")

    return result


def sanitize(conf, structure):
    for key in structure:
        if structure[key]["required"] and key not in conf:
            raise ConfigError("Mandatory key configuration "
                              "value: " + key + " missing")
        elif structure[key]["required"] is False and key not in conf:
            conf[key] = structure[key]["default"]
        if structure[key]["children"] != {} and conf[key] is not None:
            sanitize(conf[key], structure[key]["children"])


def load_conf(filename):
    """Loads a configuration from file

    @type filename: string
    @param filename: path to configuration file

    @rtype: dictionary
    @returns: parsed configuration
    """
    with open(filename, "r") as file:
        conf = yaml.load(file, yaml.Loader)

        sanitize(conf, CONFIG_STRUCTURE)
        for target in conf["reroute_targets"]:
            sanitize(conf["reroute_targets"][target], REROUTE_TARGET_STRUCTURE)
        if "ip" not in conf or conf["ip"] is None:
            conf["ip"] = get_if_addr(conf["interface"])
        if "mac" not in conf or conf["mac"] is None:
            conf["mac"] = get_if_hwaddr(conf["interface"])
        for key in conf["reroute_targets"]:
            target = conf["reroute_targets"][key]
            src_ip = get_if_addr(target["interface"])
            src_mac = get_if_hwaddr(target["interface"])
            target["src_ip"] = src_ip
            target["src_mac"] = src_mac

        conf["ports"] = parse_behavior(conf["behavior"],
                                       conf["reroute_targets"])
        return conf


def print_usage():
    """Prints program usage
    """
    print("Run: python main.py path_to_config_file.yaml\n")
    print("Take a look into doc/example_config.yaml to see an example "
          "config file with all possible values documented and explained.")
