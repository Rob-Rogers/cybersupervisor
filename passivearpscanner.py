
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
"""import argparse
import json
import threading
import time
from datetime import datetime
from scapy.all import ARP, sniff
from socket import gethostbyaddr

# Setup command-line argument parsing
parser = argparse.ArgumentParser(description="ARP Monitor Tool")
parser.add_argument("--interface", help="Specify the network interface", required=True)
parser.add_argument("--no-dns", help="Disable DNS resolution", action="store_true")
parser.add_argument("--summary", help="Enable periodic summary output", action="store_true")
parser.add_argument("--unix-time", help="Use Unix time for timestamps", action="store_true")
parser.add_argument("-o", "--output-file", help="Output file for logging")
args = parser.parse_args()

# Initialize ARP table as a dictionary
arp_table = {}

def handle_packet(packet):
    """Process packets, filtering for ARP."""
    if packet.haslayer(ARP):
        if packet[ARP].op == 2:  # ARP Reply
            process_arp(packet)

def process_arp(packet):
    """Process ARP packets and update the ARP table."""
    ip = packet[ARP].psrc
    mac = packet[ARP].hwsrc
    timestamp = str(int(time.time())) if args.unix_time else datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    dns_name = ""
    if not args.no_dns:
        try:
            dns_name = gethostbyaddr(ip)[0]
        except Exception:
            dns_name = "Resolution failed"

    if ip not in arp_table:
        arp_table[ip] = {
            'mac': mac,
            'first_seen': timestamp,
            'last_seen': timestamp,
            'count': 1,
            'dns_name': dns_name
        }
        print_arp_entry(ip, "live")
    else:
        arp_table[ip]['last_seen'] = timestamp
        arp_table[ip]['count'] += 1

def print_arp_entry(ip, entry_type):
    """Print ARP entry as JSON, adding entry type (live/summary) and explicitly include the IP address."""
    entry = arp_table[ip].copy()  # Make a copy to avoid modifying the original entry
    if entry_type == "live":
        # For live view, exclude 'last_seen' and 'count'
        entry.pop('last_seen', None)
        entry.pop('count', None)
    entry_with_type = dict(entry, type=entry_type, ip_address=ip)  # Add 'type' and 'ip_address' to entry
    json_output = json.dumps(entry_with_type)
    print(json_output)

    if args.output_file:
        with open(args.output_file, "a") as file:
            file.write(json_output + "\n")

def summary_printer():
    """Periodically prints the summary of the ARP table."""
    while args.summary:
        time.sleep(30)  # Interval for printing the summary
        print("\n--- ARP Table Summary ---")
        for ip in arp_table:
            print_arp_entry(ip, "summary")
        print("--- End of Summary ---\n")

if __name__ == "__main__":
    # Start the summary thread if enabled
    if args.summary:
        summary_thread = threading.Thread(target=summary_printer, daemon=True)
        summary_thread.start()

    print(f"Monitoring ARP packets on {args.interface}...")
    sniff(prn=handle_packet, filter="arp", iface=args.interface, store=0)
