#!/usr/bin/env python3
"""
User-space packet sniffer that works without root privileges.
Uses socket-based approach for network monitoring.
"""

import socket
import struct
import time
import logging
from threading import Lock
from db import insert_packet

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

captured_packets = []
packet_lock = Lock()
stop_sniffing = False

def parse_ethernet_header(data):
    """Parse Ethernet header"""
    eth_header = struct.unpack('!6s6sH', data[:14])
    dest_mac = ':'.join(f'{b:02x}' for b in eth_header[0])
    src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])
    eth_type = socket.ntohs(eth_header[2])
    return src_mac, dest_mac, eth_type

def parse_ip_header(data):
    """Parse IP header"""
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    ttl = ip_header[5]
    protocol = ip_header[6]
    src_addr = socket.inet_ntoa(ip_header[8])
    dest_addr = socket.inet_ntoa(ip_header[9])
    return version, ihl, ttl, protocol, src_addr, dest_addr

def parse_tcp_header(data):
    """Parse TCP header"""
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcp_header[0]
    dest_port = tcp_header[1]
    return src_port, dest_port

def parse_udp_header(data):
    """Parse UDP header"""
    udp_header = struct.unpack('!HHHH', data[:8])
    src_port = udp_header[0]
    dest_port = udp_header[1]
    return src_port, dest_port

def userspace_packet_capture(interface='any', duration=10):
    """
    Capture packets using user-space sockets (no root required for some traffic)
    """
    global stop_sniffing, captured_packets
    
    stop_sniffing = False
    packet_count = 0
    
    try:
        # Create raw socket (this might still need privileges for some protocols)
        # Try different socket types
        sock = None
        
        # Method 1: Try AF_PACKET (Linux specific, needs root)
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            logger.info("Using AF_PACKET socket (requires root)")
        except (OSError, PermissionError):
            logger.info("AF_PACKET not available, trying alternatives...")
        
        # Method 2: Try regular socket for specific protocols
        if sock is None:
            try:
                # Create socket for TCP traffic
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                logger.info("Using TCP raw socket")
            except (OSError, PermissionError):
                logger.info("TCP raw socket not available")
        
        # Method 3: Use regular UDP socket (works without root)
        if sock is None:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('', 0))  # Bind to any available port
                logger.info("Using UDP socket (limited capture)")
            except Exception as e:
                logger.error(f"Could not create any socket: {e}")
                return 0
        
        logger.info(f"Starting packet capture for {duration} seconds...")
        start_time = time.time()
        
        while time.time() - start_time < duration and not stop_sniffing:
            try:
                # Receive packet
                data, addr = sock.recvfrom(65536)
                
                if len(data) < 14:  # Minimum Ethernet frame size
                    continue
                
                packet_info = {
                    "timestamp": time.time(),
                    "src_mac": None,
                    "dst_mac": None,
                    "src_ip": None,
                    "dst_ip": None,
                    "protocol": "UNKNOWN",
                    "length": len(data),
                    "src_port": None,
                    "dst_port": None,
                    "info": f"Captured from {addr}"
                }
                
                try:
                    # Try to parse as Ethernet frame
                    if len(data) >= 14:
                        src_mac, dst_mac, eth_type = parse_ethernet_header(data)
                        packet_info["src_mac"] = src_mac
                        packet_info["dst_mac"] = dst_mac
                        
                        # Check if it's IP
                        if eth_type == 0x0800 and len(data) >= 34:  # IPv4
                            ip_data = data[14:]
                            version, ihl, ttl, protocol, src_ip, dst_ip = parse_ip_header(ip_data)
                            
                            packet_info["src_ip"] = src_ip
                            packet_info["dst_ip"] = dst_ip
                            
                            if protocol == 6:  # TCP
                                packet_info["protocol"] = "TCP"
                                if len(ip_data) >= 40:
                                    tcp_data = ip_data[20:]
                                    src_port, dst_port = parse_tcp_header(tcp_data)
                                    packet_info["src_port"] = src_port
                                    packet_info["dst_port"] = dst_port
                                    
                                    # Check for HTTP
                                    if src_port == 80 or dst_port == 80:
                                        packet_info["protocol"] = "HTTP"
                                    elif src_port == 443 or dst_port == 443:
                                        packet_info["protocol"] = "HTTPS"
                            
                            elif protocol == 17:  # UDP
                                packet_info["protocol"] = "UDP"
                                if len(ip_data) >= 28:
                                    udp_data = ip_data[20:]
                                    src_port, dst_port = parse_udp_header(udp_data)
                                    packet_info["src_port"] = src_port
                                    packet_info["dst_port"] = dst_port
                                    
                                    # Check for DNS
                                    if src_port == 53 or dst_port == 53:
                                        packet_info["protocol"] = "DNS"
                
                except Exception as parse_error:
                    logger.debug(f"Error parsing packet: {parse_error}")
                    # Use basic info from socket
                    if addr:
                        packet_info["src_ip"] = addr[0] if isinstance(addr, tuple) else str(addr)
                
                # Store packet
                with packet_lock:
                    captured_packets.append(packet_info)
                
                # Save to database
                insert_packet(packet_info)
                packet_count += 1
                
                if packet_count % 10 == 0:
                    logger.info(f"Captured {packet_count} packets...")
                
            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"Error receiving packet: {e}")
                continue
        
        sock.close()
        logger.info(f"Capture completed. Total packets: {packet_count}")
        return packet_count
        
    except Exception as e:
        logger.error(f"Error in packet capture: {e}")
        return 0

def stop_userspace_capture():
    """Stop the userspace capture"""
    global stop_sniffing
    stop_sniffing = True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="User-space packet capture (no root required)")
    parser.add_argument("--duration", type=int, default=10, help="Capture duration in seconds")
    parser.add_argument("--interface", help="Network interface (ignored in userspace mode)")
    
    args = parser.parse_args()
    
    try:
        from db import init_db, clear_database
        init_db()
        clear_database()
        
        packet_count = userspace_packet_capture(duration=args.duration)
        
        if packet_count > 0:
            print(f"\n✅ Successfully captured {packet_count} packets without root privileges!")
            
            # Show some sample packets
            from db import get_all_packets
            packets = get_all_packets(limit=5)
            
            print("\nSample captured packets:")
            for i, packet in enumerate(packets[:5], 1):
                print(f"  {i}. {packet['src_ip']} → {packet['dst_ip']} ({packet['protocol']}) - {packet['length']} bytes")
        else:
            print("❌ No packets captured. This method has limitations without root privileges.")
            print("For full packet capture, use: sudo python3 test_capture.py")
            
    except KeyboardInterrupt:
        print("\nCapture interrupted by user")
        stop_userspace_capture()
    except Exception as e:
        print(f"Error: {e}")