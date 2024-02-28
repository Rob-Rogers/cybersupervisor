
"""
Python version pf passive arp scanner

WORK IN PROGRESS - DO NOT USE IN PRODUCTION.

This script captures ARP packets on a specified network interface to monitor local network traffic. It maintains an ARP table that records each unique IP-MAC pair, along with metadata such as the first and last time each pair was observed, and the total number of observations. Optional features include DNS resolution for IP addresses to hostnames, organization lookup via OUI (Organizationally Unique Identifier) data, and periodic summaries of ARP traffic.

Features:
- Packet capture in promiscuous mode to monitor ARP traffic on a specified network interface.
- ARP table management with IP, MAC, timestamps, and count.
- Optional DNS resolution for observed IP addresses.
- Optional periodic summary output.
- Logging to a specified output file or standard output.
- Organization lookup for MAC addresses using OUI data.
"""
import argparse
import threading
import time
from datetime import datetime
from scapy.all import sniff, ARP, get_if_list
import socket
import json
import os

def check_root():
    if os.geteuid() != 0:
        exit("This script must be run as root. Try using 'sudo'.")

def safe_open_write(path):
    if os.path.exists(path):
        raise ValueError("File already exists")
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)

def validate_interface(interface):
    if interface not in get_if_list():
        raise ValueError(f"Interface {interface} does not exist.")

parser = argparse.ArgumentParser(description="ARP Monitor")
parser.add_argument("--no-dns", help="Disable DNS resolution", action="store_true")
parser.add_argument("--summary", help="Enable periodic summary output", action="store_true")
parser.add_argument("--unix-time", help="Use Unix time for timestamps", action="store_true")
parser.add_argument("-o", "--output-file", help="Output file for logging", type=str, default="")
parser.add_argument("--oui-file", help="Path to OUI file", type=str, default="/usr/share/ieee-data/oui.txt")
parser.add_argument("interface", help="Network interface to monitor")
args = parser.parse_args()

arp_table = {}
arp_table_lock = threading.Lock()
output_file = None if args.output_file == "" else safe_open_write(args.output_file)
oui_data = {}

def load_oui_data(oui_file):
    try:
        with open(oui_file, "r") as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    oui = parts[0].strip().replace('-', ':').lower()
                    company_name = parts[1].strip()
                    oui_data[oui] = company_name
    except FileNotFoundError:
        print(f"OUI file {oui_file} not found. Skipping OUI data load.")

def lookup_oui(mac_address):
    oui_prefix = ":".join(mac_address.split(":")[:3])
    return oui_data.get(oui_prefix, "Unknown")

def update_arp_table(pkt):
    if ARP in pkt and pkt[ARP].op == 2:
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        timestamp = str(int(time.time())) if args.unix_time else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        dns_name = "DNS disabled" if args.no_dns else socket.getfqdn(src_ip)
        organization = lookup_oui(src_mac)

        with arp_table_lock:
            if src_ip in arp_table:
                arp_table[src_ip]['last_seen'] = timestamp
                arp_table[src_ip]['count'] += 1
            else:
                arp_table[src_ip] = {
                    'ip': src_ip, 
                    'mac': src_mac, 
                    'first_seen': timestamp, 
                    'last_seen': timestamp, 
                    'count': 1, 
                    'dns_name': dns_name, 
                    'organization': organization
                }
            print_arp_entry(arp_table[src_ip], "Live ARP")

def print_arp_entry(entry, entry_type):
    log_entry = json.dumps({**entry, "type": entry_type})
    if output_file is not None:
        output_file.write(log_entry + "\n")
    else:
        print(log_entry)

def main():
    check_root()
    validate_interface(args.interface)
    if args.output_file != "":
        global output_file
        output_file = safe_open_write(args.output_file)
    load_oui_data(args.oui_file)
    sniff(iface=args.interface, prn=update_arp_table, filter="arp", store=0)

if __name__ == "__main__":
    main()
