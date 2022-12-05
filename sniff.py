#!/usr/bin/python

import os
import time
from scapy.all import *
from scapy.layers.dot11 import *

Probe = {}
Beacon = {}

# Function that sniff packets async. and checks if the packet has a Dot11 layer
# If true, we want to know if it is a Probe Response or a Beacon frame and extract the data
def sniff(p):
    rssi = p[RadioTap].dBm_AntSignal

    # Check if the captured packet has a Dot11 layer 
    if p.haslayer(Dot11):

        # Check if the packet is a Probe Response
        if p.type == 0 and p.subtype == 5:
            frameType = "PROBE_RESP"
            if not p.info:
                return
            else:
                Probe[p.addr3] = (((p.info).decode('UTF-8')), ord(p[Dot11Elt:3].info), rssi, frameType)
        
        # Check if the packet is a Beacon frame
        if p.type == 0 and p.subtype == 8:
            frameType = "BEACON"
            if not p.info:
                Beacon[p.addr3] = ("Hidden SSID", ord(p[Dot11Elt:3].info), rssi, frameType)
            else:
                txt = "b'\x00"
                if ((p.info).decode('UTF-8')).find(txt) != 1:
                    Beacon[p.addr3] = ("Hidden SSID", ord(p[Dot11Elt:3].info), rssi, frameType)
                else:
                    Beacon[p.addr3] = ((p.info).decode('UTF-8'), ord(p[Dot11Elt:3].info), rssi, frameType)
                        
                

def main():
    name = "AP Scanner"
    print("Welcome to AP Scanner")
    time.sleep(1)
    interface = input("Which interface do you want to use: ")
    time.sleep(0.5)
    print("Interface is switching to monitor mode ...")
    time.sleep(0.5)

    # Put network interface into monitor mode
    os.system("ifconfig %s down" % interface)
    os.system("iwconfig %s mode monitor" % interface)
    os.system("ifconfig %s up" % interface)
    time.sleep(0.5)
    print("%s is in monitor mode" % interface)
    time.sleep(1)

    packet = RadioTap()/Dot11(type=0,subtype=4,addr1="FF:FF:FF:FF:FF:FF", addr2="00:c0:ca:b1:24:92",addr3="FF:FF:FF:FF:FF:FF")/Dot11Elt(ID="SSID", info="")
    sendp(packet, iface=interface, count=5)
    print("Sent 5 Probe Request with the following info: ", str(packet))

    # Create a sniffer function 
    t = AsyncSniffer(prn=sniff, iface=interface, count=0)
    t.start()
    input("Press ENTER to stop scanning and print results\n")
    time.sleep(1)

    # Return network interface back to normal mode
    print("Interface is switching to managed mode...")
    time.sleep(0.5)
    os.system("ifconfig %s down" % interface)
    os.system("iwconfig %s mode managed" % interface)
    os.system("ifconfig %s up" % interface)
    time.sleep(0.5)
    print("%s is in managed mode" % interface)
    print("")
    print(name.center(65, " "))

    #  Prints out the Beacon frame details
    print("=================================================================================")
    print("=  frameType  =           SSIDs           =  CH   =   RSSI  =     MAC Address   =")
    print("=================================================================================")
    for key in Beacon.keys():
        print("=", (Beacon[key][3]).center(10, ' '),"=", (str(Beacon[key][0])).center(25, ' '), "=", str(Beacon[key][1]).center(5, ' '), "=", Beacon[key][2], "dBm", "=", key,"=")
    print("=================================================================================\n")

    # Prints out the Probe Response frame details
    print("=================================================================================")
    print("=  frameType  =           SSIDs           =  CH   =   RSSI  =     MAC Address   =")
    print("=================================================================================")
    for key in Probe.keys():
        print("=", (Probe[key][3]).center(10, ' '),"=", (str(Probe[key][0])).center(25, ' '), "=", str(Probe[key][1]).center(5, ' '), "=", Probe[key][2], "dBm", "=", key,"=")
    print("=================================================================================\n")

    # Compares both tables to see if there is a common MAC address between the two 
    for Beaconkey in Beacon.keys():
        for Probekey in Probe.keys():
            if Beaconkey == Probekey:
                print("This SSID was orignally known as:", Beacon[Beaconkey][0], "  After Probe Request:", Probe[Probekey][0], "  MAC Address =", Probekey)

if __name__ == "__main__":
    main()