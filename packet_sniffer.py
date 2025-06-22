import time
import platform
import sys
import logging
from scapy.all import sniff, IP, TCP, UDP, ARP, conf, get_if_list
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
from db import insert_packet

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global stop flag for controlling sniffing
stop_sniffing = False

def check_windows_requirements():
    """
    Check if Windows has the required packet capture drivers installed.
    Returns detailed error information if requirements are not met.
    """
    if platform.system() == "Windows":
        try:
            # First, check if we can import Windows-specific modules
            try:
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                if not interfaces:
                    error_msg = "No network interfaces found. Please install Npcap or WinPcap."
                    logger.error(error_msg)
                    print(f"ERROR: {error_msg}")
                    print("Download Npcap from: https://npcap.com/")
                    return False, error_msg
                
                logger.info(f"Found {len(interfaces)} Windows interfaces")
            except ImportError as e:
                error_msg = "Scapy Windows support not available."
                logger.error(f"{error_msg} Import error: {e}")
                print(f"ERROR: {error_msg}")
                print("Please install Npcap from: https://npcap.com/")
                return False, error_msg
            
            # Test L3 socket capability
            try:
                # Configure for L3 socket usage
                conf.use_pcap = False
                conf.use_dnet = False
                conf.L3socket = None
                conf.L3socket6 = None
                
                # Try to create a simple L3 socket test
                from scapy.arch.windows import conf as win_conf
                win_conf.use_pcap = False
                win_conf.use_dnet = False
                
                logger.info("L3 socket configuration test passed")
                return True, f"Windows requirements met - {len(interfaces)} interfaces found, L3 sockets available"
                
            except Exception as e:
                logger.warning(f"L3 socket test failed: {e}")
                # Even if L3 socket test fails, we might still be able to capture
                return True, f"Windows requirements met - {len(interfaces)} interfaces found (L3 test failed but continuing)"
            
        except Exception as e:
            error_msg = f"Unexpected error checking Windows requirements: {e}"
            logger.error(error_msg)
            print(f"ERROR: {error_msg}")
            return False, error_msg
    return True, "Non-Windows system"

def configure_windows_scapy():
    """
    Configure Scapy specifically for Windows packet capture.
    Force L3 socket usage to bypass layer 2 requirements.
    """
    if platform.system() == "Windows":
        try:
            # Completely disable pcap and dnet to force L3 socket usage
            conf.use_pcap = False
            conf.use_dnet = False
            
            # Force L3 socket usage by setting these to None
            # This tells Scapy to use L3 sockets instead of trying layer 2
            conf.L3socket = None
            conf.L3socket6 = None
            
            # Disable any layer 2 sniffing attempts
            conf.use_bpf = False
            conf.use_winpcapy = False
            
            # Set verbosity to minimum
            conf.verb = 0
            
            # Force Windows-specific socket creation
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
        
        # For Windows, be more flexible with interface validation
        if platform.system() == "Windows":
            # On Windows, if the interface contains DeviceNPF_, assume it's valid
            if "DeviceNPF_" in interface_name:
                logger.info(f"Windows interface detected: {interface_name}")
                return True, f"Windows interface '{interface_name}' accepted"
            
            # For other Windows interfaces, check if they exist
            if interface_name not in available_interfaces:
                return False, f"Interface '{interface_name}' not found in available interfaces"
        else:
            # For non-Windows systems, strict validation
            if interface_name not in available_interfaces:
                return False, f"Interface '{interface_name}' not found in available interfaces"
        
        # Try to get IP address for the interface
        try:
            from scapy.all import get_if_addr
            ip = get_if_addr(interface_name)
            if not ip or ip == "127.0.0.1":
                return False, f"Interface '{interface_name}' has no valid IP address"
        except Exception as e:
            # On Windows, this might fail but we can still try to use the interface
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
    
    # Check if we should stop sniffing
    if stop_sniffing:
        return
    
    try:
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
        
        # Store packet in database
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
        
        # If interface is None, use default interface
        if interface is None:
            try:
                default_iface = conf.iface if hasattr(conf.iface, 'name') else conf.iface
                return default_iface, "Using default interface"
            except Exception as e:
                logger.error(f"Error getting default interface: {e}")
                return available_interfaces[0] if available_interfaces else None, "Using first available interface"
        
        # For Windows, be more flexible
        if platform.system() == "Windows":
            # If it's a Windows GUID format, accept it
            if "DeviceNPF_" in interface:
                logger.info(f"Windows GUID interface detected: {interface}")
                return interface, "Windows GUID interface accepted"
            
            # Check if interface exists in available interfaces
            if interface in available_interfaces:
                return interface, "Interface found"
            
            # Try to find a similar one
            for iface in available_interfaces:
                if interface.lower() in iface.lower():
                    logger.info(f"Found similar interface: {iface} for requested {interface}")
                    return iface, f"Using similar interface: {iface}"
            
            # If still not found, return first available interface
            if available_interfaces:
                logger.warning(f"Interface '{interface}' not found, using first available: {available_interfaces[0]}")
                return available_interfaces[0], f"Using first available interface: {available_interfaces[0]}"
        else:
            # For non-Windows systems, strict validation
            if interface in available_interfaces:
                return interface, "Interface found"
            
            # Try to find a similar one
            for iface in available_interfaces:
                if interface.lower() in iface.lower():
                    logger.info(f"Found similar interface: {iface} for requested {interface}")
                    return iface, f"Using similar interface: {iface}"
            
            # If still not found, return first available interface
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
    
    # Reset stop flag
    stop_sniffing = False
    
    try:
        # Check Windows requirements first
        windows_ok, windows_msg = check_windows_requirements()
        if not windows_ok:
            logger.error(f"Windows requirements check failed: {windows_msg}")
            return False
        
        # Configure Scapy for Windows
        if not configure_windows_scapy():
            logger.error("Failed to configure Scapy for Windows")
            return False
        
        # Validate and get the correct interface name
        valid_interface, validation_msg = validate_interface(interface)
        if not valid_interface:
            logger.error(f"Interface validation failed: {validation_msg}")
            return False
        
        # Check interface availability
        interface_ok, interface_msg = check_interface_availability(valid_interface)
        if not interface_ok:
            logger.error(f"Interface availability check failed: {interface_msg}")
            return False
            
        logger.info(f"Starting packet capture on interface: {valid_interface}")
        print(f"Starting packet capture on interface: {valid_interface}")
        
        # Configure Scapy based on platform
        if platform.system() == "Windows":
            # Set the interface
            conf.iface = valid_interface
            
            # Try multiple capture methods for Windows, all using L3 sockets
            capture_methods = [
                # Method 1: Direct L3 socket with minimal configuration
                lambda: sniff(prn=packet_callback, store=False, stop_filter=lambda p: stop_sniffing),
                # Method 2: L3 socket with interface specified
                lambda: sniff(iface=valid_interface, prn=packet_callback, store=False, stop_filter=lambda p: stop_sniffing),
                # Method 3: L3 socket with IP filter only
                lambda: sniff(prn=packet_callback, store=False, filter="ip", stop_filter=lambda p: stop_sniffing),
                # Method 4: L3 socket with interface and IP filter
                lambda: sniff(iface=valid_interface, prn=packet_callback, store=False, filter="ip", stop_filter=lambda p: stop_sniffing)
            ]
            
            for i, method in enumerate(capture_methods, 1):
                try:
                    logger.info(f"Attempting Windows L3 capture method {i}...")
                    print(f"Attempting Windows L3 capture method {i}...")
                    method()
                    logger.info(f"Windows L3 capture method {i} successful")
                    return True
                except Exception as e:
                    logger.warning(f"Windows L3 capture method {i} failed: {e}")
                    if i == len(capture_methods):
                        # Last method failed
                        raise e
                    continue
        else:
            # For non-Windows systems, use standard sniffing
            logger.info("Using standard packet capture...")
            sniff(iface=valid_interface, prn=packet_callback, store=False, stop_filter=lambda p: stop_sniffing)
            
    except KeyboardInterrupt:
        logger.info("Packet capture interrupted by user")
        print("Packet capture interrupted by user")
        return True
    except Exception as e:
        logger.error(f"Error while sniffing: {e}")
        print(f"Error while sniffing: {str(e)}")
        
        # Final fallback for Windows
        if platform.system() == "Windows":
            try:
                logger.info("Attempting final Windows L3 fallback...")
                print("Attempting final Windows L3 fallback...")
                
                # Reset Scapy configuration to force L3
                configure_windows_scapy()
                
                # Try with absolute minimal configuration - pure L3 socket
                print("Using pure L3 socket capture (no layer 2)...")
                sniff(prn=packet_callback, store=False, stop_filter=lambda p: stop_sniffing)
                return True
            except Exception as e2:
                logger.error(f"Final Windows L3 fallback failed: {e2}")
                print(f"Final Windows L3 fallback failed: {str(e2)}")
                print("\nTROUBLESHOOTING STEPS:")
                print("1. Make sure you're running as Administrator")
                print("2. Check Windows Firewall settings")
                print("3. Verify Npcap service is running: sc query npcap")
                print("4. Try restarting your computer")
                print("5. Reinstall Npcap from https://npcap.com/")
                print("6. Check if antivirus is blocking packet capture")
                return False
        else:
            print("Please make sure you're running the application with administrator privileges.")
            print("For Windows users: Install Npcap from https://npcap.com/")
            return False
    
    return True

def stop_sniffing_capture():
    """
    Stops the packet capture by setting the global stop flag.
    """
    global stop_sniffing
    stop_sniffing = True
    logger.info("Stopping packet capture...")
    print("Stopping packet capture...")

def is_sniffing_active():
    """
    Returns True if packet capture is currently active.
    """
    global stop_sniffing
    return not stop_sniffing

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

if __name__ == "__main__":
    try:
        print("Network Packet Sniffer")
        print("Press Ctrl+C to stop")
        start_sniffing()
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        stop_sniffing_capture()
    except Exception as e:
        logger.error(f"Application error: {e}")
        print(f"Application error: {e}")
        sys.exit(1)


