from flask import Flask, render_template, jsonify, request, flash
from scapy.all import get_if_list, get_if_addr, conf
from packet_sniffer import start_sniffing, stop_sniffing_capture, is_sniffing_active, get_captured_packets, validate_interface
from db import get_all_packets, get_packet_count, get_protocol_stats, get_top_ips, migrate_csv_to_db
from anomaly_detector import detect_anomalies
from ip_analyzer import get_ip_info, analyze_traffic_summary, assess_connection_risk
import threading
import platform
import os
import re
import logging
from datetime import datetime
import dotenv

dotenv.load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "your-secret-key-here")
sniffing_thread = None
is_sniffing = False
current_interface = None
capture_start_time = None

def get_network_interfaces():
    """Get list of available network interfaces using Scapy"""
    try:
        interfaces = []
        ifaces = get_if_list()
        
        if not ifaces:
            logger.warning("No network interfaces found")
            return []
        
        for iface in ifaces:
            try:
                ip = get_if_addr(iface)
                if ip and ip != "127.0.0.1":
                    clean_name = iface
                    if "DeviceNPF_" in iface:
                        guid_match = re.search(r'DeviceNPF_\{([^}]+)\}', iface)
                        if guid_match:
                            clean_name = f"Network Interface ({guid_match.group(1)[:8]}...)"
                        else:
                            clean_name = "Network Interface"
                    
                    interfaces.append({
                        'name': iface,
                        'display_name': clean_name,
                        'ip': ip
                    })
            except Exception as e:
                logger.warning(f"Error getting IP for interface {iface}: {e}")
                continue
        
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
    
    if platform.system() == "Windows":
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            if not interfaces:
                issues.append("No packet capture drivers found. Please install Npcap from https://npcap.com/")
        except ImportError:
            issues.append("Windows packet capture support not available. Please install Npcap.")
    else:
        if os.geteuid() != 0:
            issues.append("Root privileges required for packet capture on Unix systems.")
    
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
        
        valid_interface, validation_msg = validate_interface(interface)
        if not valid_interface:
            return jsonify({'status': 'error', 'message': f'Invalid interface: {validation_msg}'})
        
        if platform.system() == "Windows":
            logger.info(f"Windows system detected, using interface: {valid_interface}")
        else:
            available_interfaces = get_network_interfaces()
            interface_names = [iface['name'] for iface in available_interfaces]
            if valid_interface not in interface_names:
                return jsonify({'status': 'error', 'message': f'Interface "{valid_interface}" not found. Please select a valid interface.'})
        
        is_sniffing = True
        current_interface = valid_interface
        capture_start_time = datetime.now()
        
        def sniffing_task():
            global is_sniffing
            try:
                logger.info(f"Starting packet capture on interface: {valid_interface}")
                success = start_sniffing(valid_interface)
                if not success:
                    is_sniffing = False
                    logger.error(f"Failed to start packet capture on {valid_interface}")
            except Exception as e:
                logger.error(f"Error in sniffing task: {e}")
                is_sniffing = False
        
        sniffing_thread = threading.Thread(target=sniffing_task)
        sniffing_thread.daemon = True
        sniffing_thread.start()
        
        return jsonify({
            'status': 'success', 
            'message': f'Started packet capture on {valid_interface}. You can now view the dashboard or captured packets.',
            'interface': valid_interface
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
        
        stop_sniffing_capture()
        
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
        if os.path.exists('packets_log.csv'):
            migrate_csv_to_db()
        
        packets = get_all_packets()
        
        return render_template('capture.html', packets=packets)
    except Exception as e:
        logger.error(f"Error in capture route: {e}")
        flash("Error loading captured packets. Please try again.", "error")
        return render_template('capture.html', packets=[])

@app.route('/clear_database', methods=['POST'])
def clear_database_route():
    """Clear all captured packets from database"""
    try:
        from db import clear_database
        clear_database()
        flash("Database cleared successfully. All captured packets have been removed.", "success")
        return jsonify({'status': 'success', 'message': 'Database cleared successfully'})
    except Exception as e:
        logger.error(f"Error clearing database: {e}")
        return jsonify({'status': 'error', 'message': f'Error clearing database: {str(e)}'})

@app.route('/database_stats')
def database_stats():
    """Get database statistics"""
    try:
        packet_count = get_packet_count()
        protocol_stats = get_protocol_stats()
        
        # Get oldest and newest packet timestamps
        packets = get_all_packets(limit=1)
        newest_packet = packets[0]['timestamp'] if packets else None
        
        # Get oldest packet
        import sqlite3
        conn = sqlite3.connect('packets.db')
        c = conn.cursor()
        c.execute("SELECT MIN(timestamp) FROM packets")
        oldest_timestamp = c.fetchone()[0]
        conn.close()
        
        return jsonify({
            'total_packets': packet_count,
            'protocols': protocol_stats,
            'oldest_packet': oldest_timestamp,
            'newest_packet': newest_packet,
            'database_size_mb': os.path.getsize('packets.db') / (1024 * 1024) if os.path.exists('packets.db') else 0
        })
    except Exception as e:
        logger.error(f"Error getting database stats: {e}")
        return jsonify({'error': str(e)}), 500

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

@app.route('/network-analysis')
def network_analysis():
    """Render the network analysis page"""
    try:
        return render_template('network_analysis.html')
    except Exception as e:
        logger.error(f"Error in network analysis route: {e}")
        flash("Error loading network analysis. Please try again.", "error")
        return render_template('error.html', error=str(e))

@app.route('/api/network-analysis')
def api_network_analysis():
    """Get comprehensive network analysis data"""
    try:
        # Get top IPs for analysis
        top_src_ips, top_dst_ips = get_top_ips(20)
        
        # Combine and deduplicate IPs
        all_ips = {}
        for ip, count in top_src_ips:
            if ip:
                all_ips[ip] = all_ips.get(ip, 0) + count
        for ip, count in top_dst_ips:
            if ip:
                all_ips[ip] = all_ips.get(ip, 0) + count
        
        # Convert back to list of tuples
        combined_ips = list(all_ips.items())
        
        # Analyze traffic summary
        summary = analyze_traffic_summary(combined_ips)
        
        # Detailed IP analysis
        ip_analysis = []
        for ip, count in sorted(combined_ips, key=lambda x: x[1], reverse=True):
            if ip:
                info = get_ip_info(ip)
                risk_info = assess_connection_risk(info)
                
                ip_analysis.append({
                    'ip': ip,
                    'packet_count': count,
                    'type': info['type'],
                    'organization': info['organization'],
                    'description': info['description'],
                    'hostname': info.get('hostname'),
                    'is_private': info['is_private'],
                    'risk_level': risk_info['level'],
                    'risk_icon': risk_info['icon'],
                    'risk_message': risk_info['message'],
                    'risk_color': risk_info['color']
                })
        
        # Generate conclusion
        conclusion = generate_traffic_conclusion(summary, ip_analysis)
        
        return jsonify({
            'summary': summary,
            'risk_assessment': summary['risk_summary'],
            'service_analysis': summary['service_types'],
            'organization_analysis': summary['organizations'],
            'ip_analysis': ip_analysis,
            'conclusion': conclusion
        })
        
    except Exception as e:
        logger.error(f"Error in network analysis API: {e}")
        return jsonify({'error': str(e)}), 500

def generate_traffic_conclusion(summary, ip_analysis):
    """Generate traffic analysis conclusion"""
    conclusion = {
        'is_normal': True,
        'message': '',
        'recommendations': []
    }
    
    # Analyze patterns
    total_ips = summary['total_ips']
    external_ips = summary['external_ips']
    high_risk_count = summary['risk_summary'].get('high', 0)
    medium_risk_count = summary['risk_summary'].get('medium', 0)
    
    # Determine if traffic is normal
    if high_risk_count > 0:
        conclusion['is_normal'] = False
        conclusion['message'] = f"Detected {high_risk_count} high-risk IP addresses that require immediate attention."
        conclusion['recommendations'].append("Investigate high-risk IP addresses immediately")
        conclusion['recommendations'].append("Consider blocking suspicious traffic")
    elif medium_risk_count > 3:
        conclusion['is_normal'] = False
        conclusion['message'] = f"Multiple medium-risk connections detected ({medium_risk_count} IPs). Review recommended."
        conclusion['recommendations'].append("Review medium-risk IP addresses")
        conclusion['recommendations'].append("Monitor traffic patterns closely")
    elif external_ips > 15:
        conclusion['message'] = f"High number of external connections ({external_ips} IPs). This may be normal for active internet usage."
        conclusion['recommendations'].append("Monitor for unusual spikes in external connections")
    else:
        conclusion['message'] = f"Network traffic appears normal. {total_ips} unique IPs detected with typical service patterns."
        conclusion['recommendations'].append("Continue regular monitoring")
    
    # Add service-specific recommendations
    service_types = summary['service_types']
    if 'Unknown' in service_types and service_types['Unknown'] > 5:
        conclusion['recommendations'].append("Investigate unknown service connections")
    
    if 'Cloud Server' in service_types and service_types['Cloud Server'] > 50:
        conclusion['recommendations'].append("High cloud server activity detected - verify legitimate usage")
    
    return conclusion

@app.route('/visualizations')
def visualizations():
    """Render the visualizations page"""
    try:
        return render_template('visualizations.html')
    except Exception as e:
        logger.error(f"Error in visualizations route: {e}")
        flash("Error loading visualizations. Please try again.", "error")
        return render_template('error.html', error=str(e))

@app.route('/api/ip-data')
def ip_data():
    """Get IP data for visualizations"""
    try:
        limit = request.args.get('limit', 5, type=int)
        
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

@app.route('/api/ip-analysis')
def ip_analysis():
    """Get detailed IP analysis for visualizations"""
    try:
        limit = request.args.get('limit', 10, type=int)
        
        if limit < 1 or limit > 50:
            return jsonify({'error': 'Limit must be between 1 and 50'}), 400
        
        top_src_ips, top_dst_ips = get_top_ips(limit)
        
        # Analyze source IPs
        src_analysis = []
        for ip, count in top_src_ips:
            if ip:
                info = get_ip_info(ip)
                risk = assess_connection_risk(info)
                src_analysis.append({
                    'ip': ip,
                    'count': count,
                    'type': info['type'],
                    'organization': info['organization'],
                    'description': info['description'],
                    'hostname': info['hostname'],
                    'is_private': info['is_private'],
                    'risk': risk
                })
        
        # Analyze destination IPs
        dst_analysis = []
        for ip, count in top_dst_ips:
            if ip:
                info = get_ip_info(ip)
                risk = assess_connection_risk(info)
                dst_analysis.append({
                    'ip': ip,
                    'count': count,
                    'type': info['type'],
                    'organization': info['organization'],
                    'description': info['description'],
                    'hostname': info['hostname'],
                    'is_private': info['is_private'],
                    'risk': risk
                })
        
        # Get traffic summary
        all_ips = top_src_ips + top_dst_ips
        summary = analyze_traffic_summary(all_ips)
        
        return jsonify({
            'source_ips': src_analysis,
            'destination_ips': dst_analysis,
            'summary': summary
        })
        
    except ValueError:
        return jsonify({'error': 'Invalid limit value'}), 400
    except Exception as e:
        logger.error(f"Error getting IP analysis: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip-info/<ip>')
def get_single_ip_info(ip):
    """Get detailed information about a specific IP address"""
    try:
        info = get_ip_info(ip)
        risk = assess_connection_risk(info)
        
        return jsonify({
            'ip': ip,
            'info': info,
            'risk': risk
        })
        
    except Exception as e:
        logger.error(f"Error getting info for IP {ip}: {e}")
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
        
        if platform.system() == "Windows":
            try:
                import ctypes
                system_info['is_admin'] = ctypes.windll.shell32.IsUserAnAdmin()
            except (ImportError, AttributeError, OSError):
                pass
            
            try:
                import subprocess
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True, timeout=10)
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
        
        try:
            import scapy
            system_info['scapy_version'] = scapy.__version__
        except (ImportError, AttributeError):
            pass
        
        if platform.system() == "Windows":
            try:
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                system_info['npcap_installed'] = len(interfaces) > 0
                system_info['windows_interfaces'] = interfaces
                
                try:
                    import subprocess
                    result = subprocess.run(['sc', 'query', 'npcap'], 
                                          capture_output=True, text=True, timeout=5)
                    if 'RUNNING' in result.stdout:
                        system_info['npcap_service'] = 'Running'
                    elif 'STOPPED' in result.stdout:
                        system_info['npcap_service'] = 'Stopped'
                    else:
                        system_info['npcap_service'] = 'Not found'
                except (subprocess.SubprocessError, FileNotFoundError, TimeoutError):
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
        if os.path.exists('packets_log.csv'):
            logger.info("Migrating existing CSV data to database...")
            migrate_csv_to_db()
        
        issues = check_system_requirements()
        if issues:
            logger.warning("System requirement issues found:")
            for issue in issues:
                logger.warning(f"  - {issue}")
        
        app.run(debug=True)
    except Exception as e:
        logger.error(f"Application startup error: {e}")
        logger.error(f"Failed to start application: {e}") 