from flask import Flask, render_template, jsonify, request, flash, session
from scapy.all import get_if_list, get_if_addr, conf
from packet_sniffer import start_sniffing, stop_sniffing_capture, is_sniffing_active
from db import get_all_packets, get_packet_count, get_protocol_stats, get_top_ips, migrate_csv_to_db
from anomaly_detector import detect_anomalies
import threading
import platform
import os
import re
import json
import logging
from datetime import datetime
import dotenv

dotenv.load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
sniffing_thread = None
is_sniffing = False
current_interface = None
capture_start_time = None

def validate_interface_name(interface):
    """
    Validate interface name for security and correctness.
    """
    if not interface or not isinstance(interface, str):
        return False, "Invalid interface name"
    
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')']
    # Allow Windows GUID format: DeviceNPF_{GUID}
    if "DeviceNPF_" in interface:
        # This is a valid Windows interface format, skip dangerous char check
        pass
    elif any(char in interface for char in dangerous_chars):
        return False, "Interface name contains invalid characters"
    
    # Check length
    if len(interface) > 200:  # Increased for Windows GUIDs
        return False, "Interface name too long"
    
    return True, "Valid"

def get_network_interfaces():
    """Get list of available network interfaces using Scapy"""
    try:
        interfaces = []
        # Get all interfaces from Scapy
        ifaces = get_if_list()
        
        if not ifaces:
            logger.warning("No network interfaces found")
            return []
        
        for iface in ifaces:
            try:
                # Get IP address for the interface
                ip = get_if_addr(iface)
                if ip and ip != "127.0.0.1":  # Only add non-loopback interfaces with IP addresses
                    # Clean up interface name for Windows
                    clean_name = iface
                    if "DeviceNPF_" in iface:
                        # Extract the GUID part
                        guid_match = re.search(r'DeviceNPF_\{([^}]+)\}', iface)
                        if guid_match:
                            clean_name = f"Network Interface ({guid_match.group(1)[:8]}...)"
                        else:
                            clean_name = "Network Interface"
                    
                    interfaces.append({
                        'name': iface,  # Original name for Scapy
                        'display_name': clean_name,  # Clean name for display
                        'ip': ip
                    })
            except Exception as e:
                logger.warning(f"Error getting IP for interface {iface}: {e}")
                continue
        
        # If no interfaces found, add a default one
        if not interfaces:
            try:
                default_iface = conf.iface if hasattr(conf.iface, 'name') else str(conf.iface)
                default_ip = get_if_addr(default_iface)
                interfaces.append({
                    'name': default_iface,
                    'display_name': 'Default Interface',
                    'ip': default_ip
                })
            except Exception as e:
                logger.error(f"Error setting up default interface: {e}")
                # Last resort - add a generic interface
                interfaces.append({
                    'name': 'default',
                    'display_name': 'Default Interface',
                    'ip': 'Unknown'
                })
        
        return interfaces
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        return []

def check_system_requirements():
    """
    Check if the system meets requirements for packet capture.
    """
    issues = []
    
    # Check operating system
    if platform.system() == "Windows":
        # Check for Npcap/WinPcap on Windows
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            if not interfaces:
                issues.append("No packet capture drivers found. Please install Npcap from https://npcap.com/")
        except ImportError:
            issues.append("Windows packet capture support not available. Please install Npcap.")
    else:
        # Check for root/admin privileges on Unix systems
        if os.geteuid() != 0:
            issues.append("Root privileges required for packet capture on Unix systems.")
    
    # Check if database is accessible
    try:
        from db import init_db
        init_db()
    except Exception as e:
        issues.append(f"Database initialization failed: {str(e)}")
    
    return issues

@app.route('/')
def index():
    """Render the main page with interface selection"""
    try:
        # Check system requirements
        issues = check_system_requirements()
        
        interfaces = get_network_interfaces()
        
        if not interfaces:
            flash("No network interfaces found. Please check your network configuration.", "warning")
        
        return render_template('index.html', interfaces=interfaces, system_issues=issues)
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        flash("An error occurred while loading the page. Please try again.", "error")
        return render_template('index.html', interfaces=[], system_issues=[str(e)])

@app.route('/start_sniffing', methods=['POST'])
def start_sniffing_route():
    """Start packet sniffing on selected interface"""
    global sniffing_thread, is_sniffing, current_interface, capture_start_time
    
    try:
        if is_sniffing:
            return jsonify({'status': 'error', 'message': 'Packet capture is already active. Please stop the current session first.'})
        
        interface = request.form.get('interface')
        if not interface:
            return jsonify({'status': 'error', 'message': 'No interface selected. Please select a network interface.'})
        
        # Validate interface name
        is_valid, error_msg = validate_interface_name(interface)
        if not is_valid:
            return jsonify({'status': 'error', 'message': f'Invalid interface: {error_msg}'})
        
        # For Windows, be more flexible with interface validation
        if platform.system() == "Windows":
            # On Windows, we'll trust the interface name and let Scapy handle it
            logger.info(f"Windows system detected, using interface: {interface}")
        else:
            # Check if interface exists (only for non-Windows systems)
            available_interfaces = get_network_interfaces()
            interface_names = [iface['name'] for iface in available_interfaces]
            if interface not in interface_names:
                return jsonify({'status': 'error', 'message': f'Interface "{interface}" not found. Please select a valid interface.'})
        
        is_sniffing = True
        current_interface = interface
        capture_start_time = datetime.now()
        
        def sniffing_task():
            global is_sniffing
            try:
                logger.info(f"Starting packet capture on interface: {interface}")
                success = start_sniffing(interface)
                if not success:
                    is_sniffing = False
                    logger.error(f"Failed to start packet capture on {interface}")
            except Exception as e:
                logger.error(f"Error in sniffing task: {e}")
                is_sniffing = False
        
        sniffing_thread = threading.Thread(target=sniffing_task)
        sniffing_thread.daemon = True
        sniffing_thread.start()
        
        return jsonify({
            'status': 'success', 
            'message': f'Started packet capture on {interface}. You can now view the dashboard or captured packets.',
            'interface': interface
        })
        
    except Exception as e:
        logger.error(f"Error starting sniffing: {e}")
        is_sniffing = False
        current_interface = None
        capture_start_time = None
        return jsonify({'status': 'error', 'message': f'Failed to start packet capture: {str(e)}'})

@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing_route():
    """Stop packet sniffing"""
    global sniffing_thread, is_sniffing, current_interface, capture_start_time
    
    try:
        if not is_sniffing:
            return jsonify({'status': 'error', 'message': 'No active packet capture session to stop.'})
        
        # Stop the sniffing
        stop_sniffing_capture()
        
        # Wait for thread to finish (with timeout)
        if sniffing_thread and sniffing_thread.is_alive():
            sniffing_thread.join(timeout=5)
            if sniffing_thread.is_alive():
                logger.warning("Sniffing thread did not stop gracefully within timeout")
        
        interface_name = current_interface
        duration = None
        if capture_start_time:
            duration = datetime.now() - capture_start_time
        
        is_sniffing = False
        current_interface = None
        capture_start_time = None
        
        message = f'Stopped packet capture on {interface_name}.'
        if duration:
            message += f' Session duration: {duration.total_seconds():.1f} seconds.'
        
        return jsonify({'status': 'success', 'message': message})
        
    except Exception as e:
        logger.error(f"Error stopping sniffing: {e}")
        is_sniffing = False
        current_interface = None
        capture_start_time = None
        return jsonify({'status': 'error', 'message': f'Error stopping packet capture: {str(e)}'})

@app.route('/sniffing_status')
def sniffing_status():
    """Get current sniffing status"""
    global is_sniffing, current_interface, capture_start_time
    
    try:
        packet_count = get_packet_count()
        duration = None
        
        if is_sniffing and capture_start_time:
            duration = datetime.now() - capture_start_time
        
        return jsonify({
            'is_sniffing': is_sniffing,
            'interface': current_interface,
            'packet_count': packet_count,
            'duration': duration.total_seconds() if duration else None,
            'start_time': capture_start_time.isoformat() if capture_start_time else None
        })
    except Exception as e:
        logger.error(f"Error getting sniffing status: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/capture')
def capture():
    """Render the capture page with packet data from database"""
    try:
        # Migrate any existing CSV data to database
        if os.path.exists('packets_log.csv'):
            migrate_csv_to_db()
        
        # Get packets from database
        packets = get_all_packets()
        
        return render_template('capture.html', packets=packets)
    except Exception as e:
        logger.error(f"Error in capture route: {e}")
        flash("Error loading captured packets. Please try again.", "error")
        return render_template('capture.html', packets=[])

@app.route('/dashboard')
def dashboard():
    """Render the analysis dashboard"""
    try:
        return render_template('dashboard.html')
    except Exception as e:
        logger.error(f"Error in dashboard route: {e}")
        flash("Error loading dashboard. Please try again.", "error")
        return render_template('error.html', error=str(e))

@app.route('/stats')
def stats():
    """Get packet statistics from database"""
    try:
        packet_count = get_packet_count()
        protocol_stats = get_protocol_stats()
        top_src_ips, top_dst_ips = get_top_ips(5)
        
        return jsonify({
            'packet_count': packet_count,
            'protocol_stats': protocol_stats,
            'top_src_ips': [{'ip': ip, 'count': count} for ip, count in top_src_ips],
            'top_dst_ips': [{'ip': ip, 'count': count} for ip, count in top_dst_ips]
        })
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/anomalies')
def anomalies():
    """Get anomaly detection results"""
    try:
        threshold = request.args.get('threshold', 100, type=int)
        
        # Validate threshold
        if threshold < 1 or threshold > 10000:
            return jsonify({'error': 'Threshold must be between 1 and 10000'}), 400
        
        anomalies_list = detect_anomalies(threshold)
        
        return jsonify({
            'threshold': threshold,
            'anomalies': [{'ip': ip, 'count': count} for ip, count in anomalies_list],
            'anomaly_count': len(anomalies_list)
        })
    except ValueError:
        return jsonify({'error': 'Invalid threshold value'}), 400
    except Exception as e:
        logger.error(f"Error detecting anomalies: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/visualizations')
def visualizations():
    """Render the visualizations page"""
    try:
        return render_template('visualizations.html')
    except Exception as e:
        logger.error(f"Error in visualizations route: {e}")
        flash("Error loading visualizations. Please try again.", "error")
        return render_template('error.html', error=str(e))

@app.route('/api/protocol-data')
def protocol_data():
    """Get protocol data for visualizations"""
    try:
        protocol_stats = get_protocol_stats()
        return jsonify({
            'protocols': list(protocol_stats.keys()),
            'counts': list(protocol_stats.values())
        })
    except Exception as e:
        logger.error(f"Error getting protocol data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip-data')
def ip_data():
    """Get IP data for visualizations"""
    try:
        limit = request.args.get('limit', 5, type=int)
        
        # Validate limit
        if limit < 1 or limit > 50:
            return jsonify({'error': 'Limit must be between 1 and 50'}), 400
        
        top_src_ips, top_dst_ips = get_top_ips(limit)
        
        return jsonify({
            'source_ips': [{'ip': ip, 'count': count} for ip, count in top_src_ips],
            'destination_ips': [{'ip': ip, 'count': count} for ip, count in top_dst_ips]
        })
    except ValueError:
        return jsonify({'error': 'Invalid limit value'}), 400
    except Exception as e:
        logger.error(f"Error getting IP data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/debug/interfaces')
def debug_interfaces():
    """Debug route to show all available interfaces"""
    try:
        from scapy.all import get_if_list, get_if_addr
        
        all_interfaces = get_if_list()
        interface_details = []
        
        for iface in all_interfaces:
            try:
                ip = get_if_addr(iface)
                interface_details.append({
                    'name': iface,
                    'ip': ip,
                    'is_loopback': ip == "127.0.0.1" if ip else False
                })
            except Exception as e:
                interface_details.append({
                    'name': iface,
                    'ip': 'Error getting IP',
                    'error': str(e)
                })
        
        return jsonify({
            'platform': platform.system(),
            'total_interfaces': len(all_interfaces),
            'interfaces': interface_details,
            'scapy_conf_iface': str(conf.iface) if hasattr(conf.iface, 'name') else str(conf.iface)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug/system')
def debug_system():
    """Debug route to show system information"""
    try:
        import os
        import sys
        
        system_info = {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'python_version': sys.version,
            'architecture': platform.architecture(),
            'processor': platform.processor(),
            'current_user': os.getenv('USERNAME') or os.getenv('USER'),
            'is_admin': False,
            'scapy_version': None,
            'npcap_installed': False,
            'firewall_status': 'Unknown'
        }
        
        # Check if running as admin (Windows)
        if platform.system() == "Windows":
            try:
                import ctypes
                system_info['is_admin'] = ctypes.windll.shell32.IsUserAnAdmin()
            except:
                pass
            
            # Check Windows Firewall status
            try:
                import subprocess
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    if 'ON' in result.stdout:
                        system_info['firewall_status'] = 'Enabled'
                    elif 'OFF' in result.stdout:
                        system_info['firewall_status'] = 'Disabled'
                    else:
                        system_info['firewall_status'] = 'Mixed'
                else:
                    system_info['firewall_status'] = 'Could not determine'
            except Exception as e:
                system_info['firewall_error'] = str(e)
        
        # Check Scapy version
        try:
            import scapy
            system_info['scapy_version'] = scapy.__version__
        except:
            pass
        
        # Check for Npcap (Windows)
        if platform.system() == "Windows":
            try:
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                system_info['npcap_installed'] = len(interfaces) > 0
                system_info['windows_interfaces'] = interfaces
                
                # Additional Npcap checks
                try:
                    import subprocess
                    # Check if Npcap service is running
                    result = subprocess.run(['sc', 'query', 'npcap'], 
                                          capture_output=True, text=True, timeout=5)
                    if 'RUNNING' in result.stdout:
                        system_info['npcap_service'] = 'Running'
                    elif 'STOPPED' in result.stdout:
                        system_info['npcap_service'] = 'Stopped'
                    else:
                        system_info['npcap_service'] = 'Not found'
                except:
                    system_info['npcap_service'] = 'Could not check'
                    
            except Exception as e:
                system_info['npcap_error'] = str(e)
        
        return jsonify(system_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug')
def debug_page():
    """Render the debug page"""
    try:
        return render_template('debug.html')
    except Exception as e:
        logger.error(f"Error in debug route: {e}")
        return render_template('error.html', error=str(e))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return render_template('error.html', error="Internal server error"), 500

if __name__ == '__main__':
    try:
        # Migrate any existing CSV data on startup
        if os.path.exists('packets_log.csv'):
            print("Migrating existing CSV data to database...")
            migrate_csv_to_db()
        
        # Check system requirements on startup
        issues = check_system_requirements()
        if issues:
            print("System requirement issues found:")
            for issue in issues:
                print(f"  - {issue}")
        
        app.run(debug=True)
    except Exception as e:
        logger.error(f"Application startup error: {e}")
        print(f"Failed to start application: {e}") 