# ==================================================
# I am going to use scapy packag to perform sniffing
# ==================================================

# ===================headers========================
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
        sniff(prn = prc_packets, iface = iface, store = False)
    else:
        sniff(prn = prc_packets, store = False)

def prc_packets(packet):

    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        print(f"{bu}[+] {src_ip} is using port {src_port} to connect {dst_ip} at port {dst_port} {rst}")

sniff_packets('VMware Network Adapter VMnet8')  #heare we can use any network interface I am doing on VM From windows. so, I use 'VMware Network Adapter VMnet8' name
