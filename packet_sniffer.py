#!/usr/bin/env python3
"""
sniffer.py

Sniffs packets from the network using Scapy and logs them into a CSV file.
"""

import csv
import time
from scapy.all import sniff, IP, TCP, UDP, ARP

# Name of the CSV file where we will store packet data
LOG_FILE = "packets_log.csv"

def write_packet_to_csv(packet_info):
    """
    Writes a single packet’s information into a CSV file.
    packet_info is expected to be a dictionary with relevant fields.
    """
    with open(LOG_FILE, mode='a', newline='') as csv_file:
        fieldnames = ["timestamp", "src_ip", "dst_ip", "protocol", "length"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        
        if csv_file.tell() == 0:
            writer.writeheader()
        writer.writerow(packet_info)
        

def packet_callback(packet):
    """
    Callback function called by sniff() for each captured packet.
    Extracts relevant data and writes it to CSV.
    """
    packet_info = {}
    packet_info["timestamp"] = time.time()
 
    if IP in packet:
        ip_layer = packet[IP]
        packet_info["src_ip"] = ip_layer.src
        packet_info["dst_ip"] = ip_layer.dst
        
        if TCP in packet:
            packet_info["protocol"] = "TCP"
        elif UDP in packet:
            packet_info["protocol"] = "UDP"
        else:
            packet_info["protocol"] = "IP"
    elif ARP in packet:
        packet_info["src_ip"] = packet[ARP].psrc
        packet_info["dst_ip"] = packet[ARP].pdst
        packet_info["protocol"] = "ARP"
    else:
        packet_info["src_ip"] = "Unknown"
        packet_info["dst_ip"] = "Unknown"
        packet_info["protocol"] = "OTHER"
    
    packet_info["length"] = len(packet)
    write_packet_to_csv(packet_info)


def start_sniffing(interface=None):
    """
    Starts sniffing on the specified interface.
    If interface is None, Scapy tries to sniff on all available interfaces.
    """
    print(f"Starting packet capture on interface: {interface or 'ALL'}")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffing()
