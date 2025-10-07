#! /usr/bin/env python3
#
#
#   Run below before this if youre not in monitor mode vvv    
#   sudo ip link set wlo1 down && sudo iw dev wlo1 set type monitor && sudo ip link set wlo1 up
#
#   v1.1 Mac sniffer by Aaron 26/8/25

#Code pulled from https://github.com/UTS-Team-404/wifi-scanner/blob/main/wifi-scanner-scapy.py and adapted to have database

from scapy.all import *
from time import sleep
import databaseTemplates
from datetime import datetime


#Put filtering values here (yet to be fully tested lmao)
#-------------------
filterSSID = False
targetSSID = False
filterMAC = ""
targetMAC = ""
#-------------------

apMAC = ""      #Access point MAC address
sourceMAC = ""  #Sender MAC address
destMAC = ""    #Reciever MAC address
rssi = ""       #Access point Signal strength
ap = ""         #Access point name/SSID

projectID = databaseTemplates.create_project(str(datetime.now()), "sniff_external")

#Print out feild details if they are there
def output():

    #if no wifi protocol layer detected, skip  
    if not pkt.haslayer(Dot11):
        print("No 802.11 layer detected at all :(")
        return
    #Print packet SSID and ap MAC Address
    print(ap, "(", apMAC, "):")

    #If other layers are missing print them
    if not pkt.haslayer(RadioTap):
        print("No RadioTap layer found")
    if not pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        print("no 802.11 beacon layer found")
    
    scMac = sourceMAC

    if not scMac:
        scMac = ""
    #Print MAC address traffic of packet
    print("\t\t\t\t\t\t", sourceMAC, " --> ", destMAC)
    
    #Could instead have values saved to SQL database here.    

    # N/a = not implemented yet
    databaseTemplates.insert_sniff_external(projectID, datetime.now(),scMac, destMAC,ap,"Public","PSK",rssi, 0, "N/a")

    return


#Main loop
while(True):
    # Sniff one packet from a wireless interface in monitor mode
    # If a specific interface is needed use -> pkt = sniff(iface = "interface", count=1)[0]
    pkt = sniff(iface = "wlan0", count=1)[0]

    #Check if it has a wifi beacon or probe response layer, then save SSID
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        ap = pkt[Dot11Elt].info.decode(errors="ignore")
        if ap == "":
            ap = "<BROARDCAST>"

   #Check if it has a RadioTap layer, then save RSSI
    if pkt.haslayer(RadioTap):
        rssi = pkt.dBm_AntSignal
        

    #Check if it has the wifi layer, then save source, dest and ap mac addresses
    if pkt.haslayer(Dot11):
        destMAC = pkt[Dot11].addr1
        sourceMAC = pkt[Dot11].addr2
        apMAC = pkt[Dot11].addr3


    #Scuffed IF filter (should be swapped to a switch case)
    #Check if there is an SSID filter        
    if filterSSID == True:
        #If so, Check if packet matches filter
        if ap == targetSSID:
            #If so, is there a MAC filter?
            if filterMAC == True:
                #If so, does packet match filter?
                if sourceMAC == targetMAC:
                    #If so, print packet
                    output()

            #If no MAC Filter, Print with just matching SSID
            else:
                output()

    #If just MAC Filter is chosen    
    elif (filterSSID == False) & (filterMAC == True):
        if sourceMAC == targetMAC:
            #If so, print packet
            output()
        
    #If neither filter, Print any packet
    else:
        output()

    

