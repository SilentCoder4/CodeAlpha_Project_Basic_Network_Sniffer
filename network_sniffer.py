# ==================================================
# I am going to use scapy packag to perform sniffing
# ==================================================

# ===================headers========================
import sys
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, TCP
from colorama import init, Fore

# =================color=declaration================

init()
r = Fore.RED        #RED
g = Fore.GREEN      #GREEN
bu = Fore.BLUE      #BLUE
y = Fore.YELLOW     #YELLOW
c = Fore.CYAN       #CYAN
rst = Fore.RESET    #RESET color

# ==================================================


def sniff_packets(iface):
    if iface:
        sniff(prn = prc_packets, iface = iface, store = False)      #adding a port 80 filter 'filter = 'port 80'
    else:
        sniff(prn = prc_packets, store = False)

def prc_packets(packet):

    # check if the packet has TCP layar
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"{bu}[+] {src_ip} is using port {src_port} to connect {dst_ip} at port {dst_port} {rst}")

    # check if the packet contains HTTP data
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()
        print(f"{g}[+] {src_ip} is making a HTTP request to {url} with method {method} {rst}")
        print(f"[+] HTTP Data:")
        print(f"{y} {packet[HTTPRequest].show()}")

    # check if the packet contains Raw data
        if packet.haslayer(Raw):
            print(f"{r} [+] Useful raw data: {packet.getlayer(Raw).load.decode()}{rst}")
            print('=' * 75)

# iface = sys.argv[1] network interface can be entered by arguments if 'iface' is commented.

# Replace 'VMware Network Adapter VMnet8' with the appropriate interface name for your environment
sniff_packets('VMware Network Adapter VMnet8')
#heare we can use any network interface I am doing on VM From windows. so, I use 'VMware Network Adapter VMnet8' name
