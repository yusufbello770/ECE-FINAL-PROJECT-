from flask import Flask, render_template, jsonify, request
from scapy.all import get_if_list, get_if_addr, conf
from packet_sniffer import start_sniffing
import threading
import pandas as pd
import os
import re

app = Flask(__name__)
sniffing_thread = None
is_sniffing = False

def get_network_interfaces():
    """Get list of available network interfaces using Scapy"""
    interfaces = []
    # Get all interfaces from Scapy
    ifaces = get_if_list()
    
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
                        clean_name = guid_match.group(1)
                
                interfaces.append({
                    'name': iface,  # Original name for Scapy
                    'display_name': clean_name,  # Clean name for display
                    'ip': ip
                })
        except:
            continue
    
    # If no interfaces found, add a default one
    if not interfaces:
        interfaces.append({
            'name': conf.iface.name,
            'display_name': 'Default Interface',
            'ip': get_if_addr(conf.iface.name)
        })
    
    return interfaces

@app.route('/')
def index():
    """Render the main page with interface selection"""
    interfaces = get_network_interfaces()
    return render_template('index.html', interfaces=interfaces)

@app.route('/start_sniffing', methods=['POST'])
def start_sniffing_route():
    """Start packet sniffing on selected interface"""
    global sniffing_thread, is_sniffing
    
    if is_sniffing:
        return jsonify({'status': 'error', 'message': 'Already sniffing'})
    
    interface = request.form.get('interface')
    if not interface:
        return jsonify({'status': 'error', 'message': 'No interface selected'})
    
    is_sniffing = True
    
    def sniffing_task():
        try:
            start_sniffing(interface)
        except Exception as e:
            print(f"Error in sniffing: {str(e)}")
            is_sniffing = False
    
    sniffing_thread = threading.Thread(target=sniffing_task)
    sniffing_thread.daemon = True
    sniffing_thread.start()
    
    return jsonify({'status': 'success', 'message': f'Started sniffing on {interface}'})

@app.route('/capture')
def capture():
    """Render the capture page with packet data"""
    if not os.path.exists('packets_log.csv'):
        return render_template('capture.html', packets=[])
    
    df = pd.read_csv('packets_log.csv')
    packets = df.to_dict('records')
    return render_template('capture.html', packets=packets)

if __name__ == '__main__':
    app.run(debug=True) 