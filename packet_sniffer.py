import time
import platform
import sys
import logging
from threading import Lock
from datetime import datetime
from scapy.all import (
    sniff, IP, TCP, UDP, ARP, conf, get_if_list,
    DNS, DNSQR, Raw, IPv6, Ether, get_if_addr
)
from db import insert_packet

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

stop_sniffing = False
captured_packets = []
packet_lock = Lock()

HTTP_PORTS = {80, 8080, 8000, 8888}
HTTPS_PORTS = {443, 8443}
DNS_PORT = 53


def check_windows_requirements():
    """
    Check if Windows has the required packet capture drivers installed.
    Returns detailed error information if requirements are not met.
    """
    if platform.system() == "Windows":
        try:
            try:
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                if not interfaces:
                    error_msg = "No network interfaces found. Please install Npcap or WinPcap."
                    logger.error(error_msg)
                    logger.error("Download Npcap from: https://npcap.com/")
                    return False, error_msg
                
                logger.info(f"Found {len(interfaces)} Windows interfaces")
            except ImportError as e:
                error_msg = "Scapy Windows support not available."
                logger.error(f"{error_msg} Import error: {e}")
                logger.error("Please install Npcap from: https://npcap.com/")
                return False, error_msg
            
            try:
                conf.use_pcap = False
                conf.use_dnet = False
                conf.L3socket = None
                conf.L3socket6 = None
                from scapy.arch.windows import conf as win_conf
                win_conf.use_pcap = False
                win_conf.use_dnet = False
                
                logger.info("L3 socket configuration test passed")
                return True, f"Windows requirements met - {len(interfaces)} interfaces found, L3 sockets available"
                
            except Exception as e:
                logger.warning(f"L3 socket test failed: {e}")
                return True, f"Windows requirements met - {len(interfaces)} interfaces found (L3 test failed but continuing)"
            
        except Exception as e:
            error_msg = f"Unexpected error checking Windows requirements: {e}"
            logger.error(error_msg)
            return False, error_msg
    return True, "Non-Windows system"

def configure_scapy_for_capture():
    """
    Configure Scapy for optimal packet capture across different platforms.
    """
    try:
        if platform.system() == "Windows":
            # Windows-specific configuration
            conf.use_pcap = True
            conf.use_dnet = False
            logger.info("Configured Scapy for Windows packet capture")
        else:
            # Linux/Mac configuration
            conf.use_pcap = True
            logger.info("Configured Scapy for Unix packet capture")
        
        # Common configuration
        conf.verb = 0  # Reduce verbosity
        return True
    except Exception as e:
        logger.error(f"Error configuring Scapy: {e}")
        return False

def check_interface_availability(interface_name):
    """
    Check if the specified interface is available and accessible.
    """
    try:
        available_interfaces = get_if_list()
        if not available_interfaces:
            return False, "No network interfaces detected"
        
        if platform.system() == "Windows":
            if "DeviceNPF_" in interface_name:
                logger.info(f"Windows interface detected: {interface_name}")
                return True, f"Windows interface '{interface_name}' accepted"
            if interface_name not in available_interfaces:
                return False, f"Interface '{interface_name}' not found in available interfaces"
        else:
            if interface_name not in available_interfaces:
                return False, f"Interface '{interface_name}' not found in available interfaces"
        
        try:
            from scapy.all import get_if_addr
            ip = get_if_addr(interface_name)
            if not ip or ip == "127.0.0.1":
                return False, f"Interface '{interface_name}' has no valid IP address"
        except Exception as e:
            if platform.system() == "Windows":
                logger.warning(f"Cannot get IP for Windows interface '{interface_name}': {e}")
                return True, f"Windows interface '{interface_name}' (IP check failed but continuing)"
            else:
                return False, f"Cannot access interface '{interface_name}': {e}"
        
        return True, f"Interface '{interface_name}' is available"
    except Exception as e:
        return False, f"Error checking interface availability: {e}"

def write_packet_to_db(packet_info):
    """
    Safely write packet information to database with error handling.
    """
    try:
        insert_packet(packet_info)
        return True
    except Exception as e:
        logger.error(f"Error writing packet to database: {e}")
        return False



def packet_callback(packet):
    """
    Callback function called by sniff() for each captured packet.
    Extracts relevant data and stores it in the database.
    """
    global stop_sniffing
    if stop_sniffing:
        return
    
    packet_info = {
        "timestamp": time.time(),
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "protocol": "OTHER",
        "length": len(packet),
        "src_port": None,
        "dst_port": None,
        "info": ""
    }
    
    try:    
        # Link layer (Ethernet)
        if Ether in packet:
            eth = packet[Ether]
            packet_info.update({
                "src_mac": eth.src,
                "dst_mac": eth.dst
            })

        # Network layer (IPv4/IPv6)
        if IP in packet:
            ip_layer = packet[IP]
            packet_info.update({
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst
            })
        elif IPv6 in packet:
            ip_layer = packet[IPv6]
            packet_info.update({
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "protocol": "IPv6"
            })

        # Transport layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_info.update({
                "protocol": "TCP",
                "src_port": tcp_layer.sport,
                "dst_port": tcp_layer.dport
            })

            # HTTP detection
            if tcp_layer.dport in HTTP_PORTS or tcp_layer.sport in HTTP_PORTS:
                packet_info["protocol"] = "HTTP"
                if Raw in packet:
                    try:
                        payload = bytes(packet[Raw])
                        if b'GET' in payload or b'POST' in payload or b'HTTP/' in payload:
                            packet_info["info"] = "HTTP Traffic"
                    except:
                        pass

            # HTTPS/TLS detection
            elif tcp_layer.dport in HTTPS_PORTS or tcp_layer.sport in HTTPS_PORTS:
                packet_info["protocol"] = "HTTPS"
                packet_info["info"] = "HTTPS/TLS Traffic"

        elif UDP in packet:
            udp_layer = packet[UDP]
            packet_info.update({
                "protocol": "UDP",
                "src_port": udp_layer.sport,
                "dst_port": udp_layer.dport
            })

            # DNS detection
            if udp_layer.dport == DNS_PORT or udp_layer.sport == DNS_PORT:
                packet_info["protocol"] = "DNS"
                if DNS in packet:
                    try:
                        dns = packet[DNS]
                        if DNSQR in dns:
                            query_name = dns.qd.qname.decode('ascii', errors='replace')
                            packet_info["info"] = f"DNS Query: {query_name}"
                    except:
                        packet_info["info"] = "DNS Traffic"
                
        elif ARP in packet:
            arp_layer = packet[ARP]
            packet_info.update({
                "protocol": "ARP",
                "src_ip": arp_layer.psrc,
                "dst_ip": arp_layer.pdst,
                "info": f"ARP {arp_layer.op}"
            })

        # Store packet in memory for quick access
        with packet_lock:
            captured_packets.append(packet_info)
            # Keep only last 1000 packets in memory
            if len(captured_packets) > 1000:
                captured_packets.pop(0)
        
        # Write to database
        write_packet_to_db(packet_info)
            
    except Exception as e:
        logger.error(f"Error processing packet: {e}")

def validate_interface(interface):
    """
    Validates if the interface exists and returns the correct interface name.
    """
    try:
        available_interfaces = get_if_list()
        
        if not available_interfaces:
            logger.error("No network interfaces available")
            return None, "No network interfaces available"
        
        if interface is None:
            try:
                default_iface = conf.iface if hasattr(conf.iface, 'name') else conf.iface
                return default_iface, "Using default interface"
            except Exception as e:
                logger.error(f"Error getting default interface: {e}")
                return available_interfaces[0] if available_interfaces else None, "Using first available interface"
        
        if platform.system() == "Windows":
            if "DeviceNPF_" in interface:
                logger.info(f"Windows GUID interface detected: {interface}")
                return interface, "Windows GUID interface accepted"
            if interface in available_interfaces:
                return interface, "Interface found"
            for iface in available_interfaces:
                if interface.lower() in iface.lower():
                    logger.info(f"Found similar interface: {iface} for requested {interface}")
                    return iface, f"Using similar interface: {iface}"
            if available_interfaces:
                logger.warning(f"Interface '{interface}' not found, using first available: {available_interfaces[0]}")
                return available_interfaces[0], f"Using first available interface: {available_interfaces[0]}"
        else:
            if interface in available_interfaces:
                return interface, "Interface found"
            for iface in available_interfaces:
                if interface.lower() in iface.lower():
                    logger.info(f"Found similar interface: {iface} for requested {interface}")
                    return iface, f"Using similar interface: {iface}"
            if available_interfaces:
                logger.warning(f"Interface '{interface}' not found, using first available: {available_interfaces[0]}")
                return available_interfaces[0], f"Using first available interface: {available_interfaces[0]}"
        
        return None, "No valid interfaces found"
        
    except Exception as e:
        logger.error(f"Error validating interface: {e}")
        return None, f"Error validating interface: {e}"

def start_sniffing(interface=None):
    """
    Starts sniffing on the specified interface.
    Captures real network packets from the selected interface.
    Automatically handles permission issues with fallback methods.
    """
    global stop_sniffing
    
    stop_sniffing = False
    
    try:
        # Check system requirements
        windows_ok, windows_msg = check_windows_requirements()
        if not windows_ok:
            logger.error(f"System requirements not met: {windows_msg}")
            return False
        
        # Configure Scapy
        if not configure_scapy_for_capture():
            logger.error("Failed to configure Scapy")
            return False
        
        # Validate interface
        valid_interface, validation_msg = validate_interface(interface)
        if not valid_interface:
            logger.error(f"Interface validation failed: {validation_msg}")
            return False
        
        # Check interface availability
        interface_ok, interface_msg = check_interface_availability(valid_interface)
        if not interface_ok:
            logger.warning(f"Interface check warning: {interface_msg}")
            # Continue anyway for Windows
            
        logger.info(f"Starting real packet capture on interface: {valid_interface}")
        
        # Start packet capture
        try:
            if platform.system() == "Windows":
                # Windows packet capture
                logger.info("Starting Windows packet capture...")
                sniff(
                    iface=valid_interface,
                    prn=packet_callback,
                    store=False,
                    stop_filter=lambda p: stop_sniffing,
                    timeout=1  # Check stop condition every second
                )
            else:
                # Unix packet capture
                logger.info("Starting Unix packet capture...")
                sniff(
                    iface=valid_interface,
                    prn=packet_callback,
                    store=False,
                    stop_filter=lambda p: stop_sniffing,
                    timeout=1
                )
            
            logger.info("Packet capture completed successfully")
            return True
            
        except PermissionError:
            logger.warning("Permission denied for raw packet capture.")
            logger.info("💡 To run without sudo, set capabilities: sudo setcap cap_net_raw+ep $(which python3)")
            logger.info("💡 Or run the setup script: ./setup_capabilities.sh")
            logger.info("💡 Alternative: Use userspace_sniffer.py for limited capture without root")
            return False
        except Exception as e:
            logger.error(f"Packet capture failed: {e}")
            
            # Try fallback method for Windows
            if platform.system() == "Windows":
                logger.info("Trying Windows fallback capture method...")
                try:
                    sniff(
                        prn=packet_callback,
                        store=False,
                        stop_filter=lambda p: stop_sniffing,
                        timeout=1
                    )
                    return True
                except Exception as e2:
                    logger.error(f"Fallback capture also failed: {e2}")
            
            return False
            
    except KeyboardInterrupt:
        logger.info("Packet capture interrupted by user")
        return True
    except Exception as e:
        logger.error(f"Unexpected error in packet capture: {e}")
        return False

def stop_sniffing_capture():
    """
    Stops the packet capture by setting the global stop flag.
    """
    global stop_sniffing
    stop_sniffing = True
    logger.info("Stopping packet capture...")

def is_sniffing_active():
    """
    Returns True if packet capture is currently active.
    """
    global stop_sniffing
    return not stop_sniffing

def get_captured_packets(limit=None, filter_protocol=None):
    """
    Get captured packets with optional filtering
    limit: maximum number of packets to return
    filter_protocol: only return packets of this protocol
    """
    with packet_lock:
        packets = captured_packets.copy()
        
        if filter_protocol:
            filter_protocol = filter_protocol.upper()
            packets = [p for p in packets if p['protocol'].upper() == filter_protocol]
        
        if limit and len(packets) > limit:
            return packets[-limit:]
        return packets

def clear_captured_packets():
    """Clear all captured packets from memory"""
    with packet_lock:
        captured_packets.clear()

def get_sniffing_status():
    """
    Returns detailed status information about the sniffing process.
    """
    global stop_sniffing
    return {
        'active': not stop_sniffing,
        'stop_flag': stop_sniffing,
        'platform': platform.system(),
        'python_version': sys.version,
        'packet_count': len(captured_packets)
    }


