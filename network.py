import firewall as fw
import packet as p

#Creates a firewall object
nWall = fw.Firewall("firewall")

#Demonstrates addRule method defined in firewall.py
nWall.addRule("206.14.8.100","202.13.6.223","3389","Block")

#Demonstrates addRule to account for several IPs using wildcard operators
nWall.addRule("*","*","25","Block")
nWall.addRule("*","*","3389","Block")

#Allows for processes to be seen
nWall.verbose = False

#Processes IPs from networkLog.txt to allow or block each one
networkLog = open("networkLog.txt","r")
for line in networkLog.readlines():
    x = line.split(" ")
    a = p.Packet(x[0],x[1],x[2])
    nWall.inspectPacket(a)

#Prints total packets allowed/blocked
print("Total Packets:",nWall.totalPacketsBlocked + nWall.totalPacketsAllowed)
print("Total Packets Blocked:",nWall.totalPacketsBlocked)
print("Total Packets Allowed:",nWall.totalPacketsAllowed)


