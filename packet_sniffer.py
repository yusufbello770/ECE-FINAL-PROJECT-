#!/usr/bin/env python3
"""
sniffer.py

Sniffs packets from the network using Scapy and logs them into a CSV file.
"""

import csv
import time
import platform
from scapy.all import sniff, IP, TCP, UDP, ARP, conf, get_if_list
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP

# Name of the CSV file where we will store packet data
LOG_FILE = "packets_log.csv"

def write_packet_to_csv(packet_info):
    """
    Writes a single packet's information into a CSV file.
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


def validate_interface(interface):
    """
    Validates if the interface exists and returns the correct interface name.
    """
    available_interfaces = get_if_list()
    
    # If interface is None, use default interface
    if interface is None:
        # Get the default interface from conf.iface
        try:
            return conf.iface if hasattr(conf.iface, 'name') else conf.iface
        except:
            # Fallback to first available interface
            return available_interfaces[0] if available_interfaces else None
    
    # Check if interface exists in available interfaces
    if interface in available_interfaces:
        return interface
    
    # If interface not found, try to find a similar one
    for iface in available_interfaces:
        if interface.lower() in iface.lower():
            return iface
    
    # If still not found, return first available interface
    return available_interfaces[0] if available_interfaces else None


def start_sniffing(interface=None):
    """
    Starts sniffing on the specified interface.
    If interface is None, Scapy tries to sniff on all available interfaces.
    """
    # Validate and get the correct interface name
    valid_interface = validate_interface(interface)
    print(f"Starting packet capture on interface: {valid_interface}")
    
    try:
        # Configure Scapy for Windows
        if platform.system() == "Windows":
            conf.use_pcap = False
            conf.use_dnet = False
            # Set the interface
            conf.iface = valid_interface
        
        # Start sniffing with the validated interface
        sniff(iface=valid_interface, prn=packet_callback, store=False)
    except Exception as e:
        print(f"Error while sniffing: {str(e)}")
        # Try with default interface if specified interface fails
        if valid_interface != conf.iface:
            print(f"Falling back to default interface: {conf.iface}")
            try:
                sniff(iface=conf.iface, prn=packet_callback, store=False)
            except Exception as e:
                print(f"Error with default interface: {str(e)}")
                print("Please make sure you're running the application with administrator privileges.")


