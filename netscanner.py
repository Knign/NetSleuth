import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether, srp
import argparse
import sys

parser = argparse.ArgumentParser(description="Simple network scanner")

# Obtaining the host
parser.add_argument("ip", help="IP to scan")

args = parser.parse_args()
target_ip = str(args.ip)

def scan_network():
    try:
        # create ARP packet
        arp = ARP(pdst=target_ip)

        # create the Ether broadcast packet
        # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        # stack them
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=0)[0]

        # Listing the clients
        clients = []

        for sent, received in result:
            # for each response, append ip and mac address to `clients` list
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        # Printing clients
        print("Available devices in the network:")
        print("IP" + " "*18 + "MAC")
        print("-"*40)

        for client in clients:
            print("{:16}    {}".format(client['ip'], client['mac']))

    except KeyboardInterrupt:
        print("\nExiting Program")
        sys.exit()

if __name__ == '__main__':
    scan_network()