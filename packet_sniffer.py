import time
import platform
import sys
import logging
from threading import Lock
from datetime import datetime
from scapy.all import (
    sniff, IP, TCP, UDP, ARP, conf, get_if_list,
    DNS, DNSQR, Raw, IPv6, Ether
)
from colorama import Fore, Style
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

def configure_windows_scapy():
    """
    Configure Scapy specifically for Windows packet capture.
    Force L3 socket usage to bypass layer 2 requirements.
    """
    if platform.system() == "Windows":
        try:
            conf.use_pcap = False
            conf.use_dnet = False
            conf.L3socket = None
            conf.L3socket6 = None
            
            # Disable any layer 2 sniffing attempts
            conf.use_bpf = False
            conf.use_winpcapy = False
            conf.verb = 0
            try:
                from scapy.arch.windows import conf as win_conf
                win_conf.use_pcap = False
                win_conf.use_dnet = False
                win_conf.L3socket = None
                win_conf.L3socket6 = None
            except ImportError:
                pass
            
            logger.info("Windows Scapy configuration applied - forcing L3 socket usage")
            return True
        except Exception as e:
            logger.error(f"Error configuring Windows Scapy: {e}")
            return False
    return True

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

def inspect_http(payload):
    """Analyze HTTP traffic"""
    try:
        if b'HTTP/' in payload:
            lines = payload.split(b'\r\n')
            status_line = lines[0].decode('ascii', errors='replace')
            return {'type': 'HTTP Response', 'status': status_line}
        
        for method in [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD']:
            if payload.startswith(method):
                first_line = payload.split(b'\r\n')[0].decode('ascii', errors='replace')
                return {'type': 'HTTP Request', 'method': first_line.split()[0], 'path': first_line.split()[1]}
    except Exception as e:
        logger.error(f"HTTP inspection error: {e}")
    return None

def inspect_dns(packet):
    """Analyze DNS traffic"""
    try:
        if DNS in packet:
            dns = packet[DNS]
            if DNSQR in dns:
                if dns.qr == 0:  # Query
                    return {
                        'type': 'DNS Query',
                        'query': dns.qd.qname.decode('ascii', errors='replace'),
                        'qtype': dns.qd.qtype
                    }
                else:  # Response
                    answers = []
                    if dns.an:
                        for answer in dns.an:
                            answers.append({
                                'type': answer.type,
                                'data': str(answer.rdata)
                            })
                    return {
                        'type': 'DNS Response',
                        'query': dns.qd.qname.decode('ascii', errors='replace'),
                        'answers': answers
                    }
    except Exception as e:
        logger.error(f"DNS inspection error: {e}")
    return None

def inspect_tls(packet):
    """Detect TLS/SSL handshakes"""
    try:
        if Raw in packet:
            payload = packet[Raw].load
            if b'\x16\x03' in payload[:10]:  # TLS handshake
                return {'type': 'TLS Handshake'}
            elif b'\x17\x03' in payload[:10]:  # TLS application data
                return {'type': 'TLS Application Data'}
    except Exception as e:
        logger.error(f"TLS inspection error: {e}")
    return None

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
        "dpi": {} 
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

            # HTTP inspection
            if tcp_layer.dport in HTTP_PORTS or tcp_layer.sport in HTTP_PORTS:
                if Raw in packet:
                    http_info = inspect_http(bytes(packet[Raw]))
                    if http_info:
                        packet_info["dpi"]["http"] = http_info

            # TLS inspection
            elif tcp_layer.dport in HTTPS_PORTS or tcp_layer.sport in HTTPS_PORTS:
                tls_info = inspect_tls(packet)
                if tls_info:
                    packet_info["dpi"]["tls"] = tls_info

        elif UDP in packet:
            udp_layer = packet[UDP]
            packet_info.update({
                "protocol": "UDP",
                "src_port": udp_layer.sport,
                "dst_port": udp_layer.dport
            })

            # DNS inspection
            if udp_layer.dport == DNS_PORT or udp_layer.sport == DNS_PORT:
                dns_info = inspect_dns(packet)
                if dns_info:
                    packet_info["dpi"]["dns"] = dns_info
                
        elif ARP in packet:
            packet_info.update({
                "protocol": "ARP",
                "src_ip": packet[ARP].psrc,
                "dst_ip": packet[ARP].pdst
            })

        with packet_lock:
            captured_packets.append(packet_info)
        
        if not write_packet_to_db(packet_info):
            logger.warning("Failed to write packet to database")
            
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
    If interface is None, Scapy tries to sniff on all available interfaces.
    """
    global stop_sniffing
    
    stop_sniffing = False
    
    try:
        windows_ok, windows_msg = check_windows_requirements()
        if not windows_ok:
            logger.error(f"Windows requirements check failed: {windows_msg}")
            return False
        
        if not configure_windows_scapy():
            logger.error("Failed to configure Scapy for Windows")
            return False
        
        valid_interface, validation_msg = validate_interface(interface)
        if not valid_interface:
            logger.error(f"Interface validation failed: {validation_msg}")
            return False
        
        interface_ok, interface_msg = check_interface_availability(valid_interface)
        if not interface_ok:
            logger.error(f"Interface availability check failed: {interface_msg}")
            return False
            
        logger.info(f"Starting packet capture on interface: {valid_interface}")
        
        if platform.system() == "Windows":
            conf.iface = valid_interface
            capture_methods = [
                lambda: sniff(prn=packet_callback, store=False, stop_filter=lambda p: stop_sniffing),
                lambda: sniff(iface=valid_interface, prn=packet_callback, store=False, stop_filter=lambda p: stop_sniffing),
                lambda: sniff(prn=packet_callback, store=False, filter="ip", stop_filter=lambda p: stop_sniffing),
                lambda: sniff(iface=valid_interface, prn=packet_callback, store=False, filter="ip", stop_filter=lambda p: stop_sniffing)
            ]
            
            for i, method in enumerate(capture_methods, 1):
                try:
                    logger.info(f"Attempting Windows L3 capture method {i}...")
                    method()
                    logger.info(f"Windows L3 capture method {i} successful")
                    return True
                except Exception as e:
                    logger.warning(f"Windows L3 capture method {i} failed: {e}")
                    if i == len(capture_methods):
                        raise e
                    continue
        else:
            logger.info("Using standard packet capture...")
            sniff(iface=valid_interface, prn=packet_callback, store=False, stop_filter=lambda p: stop_sniffing)
            
    except KeyboardInterrupt:
        logger.info("Packet capture interrupted by user")
        return True
    except Exception as e:
        logger.error(f"Error while sniffing: {e}")
        
        if platform.system() == "Windows":
            try:
                logger.info("Attempting final Windows L3 fallback...")
                
                configure_windows_scapy()
                
                logger.info("Using pure L3 socket capture (no layer 2)...")
                sniff(prn=packet_callback, store=False, stop_filter=lambda p: stop_sniffing)
                return True
            except Exception as e2:
                logger.error(f"Final Windows L3 fallback failed: {e2}")
                logger.error("TROUBLESHOOTING STEPS:")
                logger.error("1. Make sure you're running as Administrator")
                logger.error("2. Check Windows Firewall settings")
                logger.error("3. Verify Npcap service is running: sc query npcap")
                logger.error("4. Try restarting your computer")
                logger.error("5. Reinstall Npcap from https://npcap.com/")
                logger.error("6. Check if antivirus is blocking packet capture")
                return False
        else:
            logger.error("Please make sure you're running the application with administrator privileges.")
            logger.error("For Windows users: Install Npcap from https://npcap.com/")
            return False
    
    return True

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
    filter_protocol: only return packets of this protocol (e.g., 'HTTP', 'DNS', 'TLS')
    """
    with packet_lock:
        packets = captured_packets.copy()
        
        if filter_protocol:
            filter_protocol = filter_protocol.upper()
            packets = [p for p in packets if (
                (filter_protocol == 'HTTP' and 'http' in p['dpi']) or
                (filter_protocol == 'DNS' and 'dns' in p['dpi']) or
                (filter_protocol == 'TLS' and 'tls' in p['dpi']) or
                (filter_protocol == p['protocol'])
            )]
        
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
        'python_version': sys.version
    }


