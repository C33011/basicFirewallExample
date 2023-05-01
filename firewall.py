import packet
import re

class Firewall(object):

    #Initializes a firewall objects with a name, total list of rules, amount of packets blocked and allowed, as well as a verbose modifier
    def __init__(self, name):
        self.name = name
        self.rules = []
        self.totalPacketsBlocked = 0
        self.totalPacketsAllowed = 0
        self.verbose = False

    #addRule creates a new rule based on source and destination IPs and either blocks or allows noted port
    def addRule(self,src,dst,port,action):
        id = self.getLastRuleID()
        rule = {"id":id,"src":src,"dst":dst,"port":port,"action":action}
        self.rules.append(rule)

    #getLastRuleID method used to generate unique id for each new rule
    def getLastRuleID(self):
        if self.rules:
            id = self.rules[-1]["id"] + 1
        else:
            id = 0
        return id

    #inspectPacket method inspects packet and compares to the current firewall rule list
    def inspectPacket(self,netPacket):
        action = self.findRuleMatch(netPacket)
        if action == "Block":
            self.totalPacketsBlocked = self.totalPacketsBlocked + 1
            print("-",netPacket.src, "to", netPacket.dst,"using port",netPacket.port,"is blocked")    
        elif action == "Allow":
            if self.verbose == True:
                print("+",netPacket.src, "to", netPacket.dst,"using port",netPacket.port,"is allowed.")
            self.totalPacketsAllowed = self.totalPacketsAllowed + 1
        else:
            if self.verbose == True:
                print("+",netPacket.src, "to", netPacket.dst,"using port",netPacket.port,"is allowed due to no rule.")
            self.totalPacketsAllowed = self.totalPacketsAllowed + 1

    #findRuleMatch checks every packet for a match in parameters. If a match in a rule to packet is found, will return the subsequent action
    def findRuleMatch(self,netPacket):
        for rule in self.rules:
            if netPacket.src == rule["src"] and netPacket.dst == rule["dst"] and netPacket.port == rule["port"]:
                return rule["action"]
            #Uses regex to search for an IPv4 address described with wildcard operators 
            elif (re.search(r"([0-9]+(\.[0-9]+)+)", netPacket.src)) and (re.search(r"([0-9]+(\.[0-9]+)+)", netPacket.dst)) and netPacket.port == rule["port"]:
                return rule["action"]
            else:
                continue