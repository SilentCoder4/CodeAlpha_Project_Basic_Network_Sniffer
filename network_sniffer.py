# ==================================================

# ===================headers========================
import sys
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, TCP
from colorama import init, Fore
from datetime import datetime

# =================color=declaration================

init()
r = Fore.RED        #RED
g = Fore.GREEN      #GREEN
bu = Fore.BLUE      #BLUE
y = Fore.YELLOW     #YELLOW
c = Fore.CYAN       #CYAN
rst = Fore.RESET    #RESET color

# ==================================================
LOG_FILE = "sniffed_packets.txt"
def sniff_packets(iface):
    # sniffing packet
    try:
        print(f"{g}[*]Starting packet sniffing on {iface if iface else 'all interfaces'}...{rst}")
        with open(LOG_FILE, "w") as log_file:
            log_file.write(f"Packet Sniffing Log - {datetime.now()}\n")
            log_file.write("=" * 50 + "\n")
        sniff(prn = prc_packets, iface = iface, store = False)      #adding a port 80 filter 'filter = 'port 80'
    except PermissionError:
        print(f"{r}[!] Permission denied. Run as administrator/root.{rst}")
    except Exception as e:
        print(f"{r}[!] Error: {str(e)}{rst}")

def prc_packets(packet):
    # process captured packets
    try:
        log_message = ""
        # check if the packet has TCP layar
        if packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            log_message += f"[+] {src_ip} is using port {src_port} to connect {dst_ip} at port {dst_port}\n"
            print(f"{bu}[+] {src_ip} is using port {src_port} to connect {dst_ip} at port {dst_port} {rst}")

        # check if the packet contains HTTP data
        if packet.haslayer(HTTPRequest):
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            method = packet[HTTPRequest].Method.decode()
            log_message += f"[+] HTTP Request: {src_ip} -> {url} [{method}]\n"
            log_message += f"[+] HTTP Data:\n{packet[HTTPRequest].show(dump=True)}\n"
            print(f"{g}[+] {src_ip} is making a HTTP request to {url} with method {method} {rst}")
            print(f"[+] HTTP Data:")
            print(f"{y} {packet[HTTPRequest].show()}")

            # check if the packet contains Raw data
            if packet.haslayer(Raw):
                raw_data = packet.getlayer(Raw).load.decode(errors="ignore")
                log_message += f"[+] Raw Data: {raw_data}\n"
                print(f"{r} [+] Useful raw data: {packet.getlayer(Raw).load.decode()}{rst}")
                print('=' * 75)

            if log_message:
                with open(LOG_FILE, "a") as log_file:
                    log_file.write(log_message + "\n")

    except Exception as e:
        print(f"{r}[!] Error processing packet: {str(e)}{rst}")

def main(): #main function

    iface = sys.argv[1] if len(sys.argv) > 1 else None
    sniff_packets(iface)

if __name__ == "__main__":
    main()