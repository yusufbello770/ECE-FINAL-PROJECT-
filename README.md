# Network Packet Sniffer & Traffic Analyzer

A comprehensive network monitoring tool that captures and analyzes real network traffic in real-time. This project provides detailed insights into network behavior, protocol usage, and potential security anomalies.

## 🚀 Key Features

### 1. **Real-Time Packet Capture**
- Captures actual network packets from live network interfaces
- Supports multiple network protocols (TCP, UDP, HTTP, HTTPS, DNS, ARP)
- Real-time processing and storage of packet data
- Cross-platform support (Windows, Linux, macOS)

### 2. **Comprehensive Traffic Analysis**
- Protocol distribution analysis
- Source and destination IP tracking
- Port-based traffic classification
- Bandwidth utilization monitoring

### 3. **Interactive Web Dashboard**
- Real-time statistics and visualizations
- Protocol distribution charts
- Top IP addresses analysis
- Network activity monitoring

### 4. **Anomaly Detection**
- Configurable threshold-based detection
- Identifies suspicious traffic patterns
- Alerts for unusual network behavior
- Security monitoring capabilities

### 5. **Data Visualization**
- Interactive charts and graphs
- Protocol distribution pie charts
- Traffic flow visualizations
- Historical data analysis

## 🛠️ Technical Stack

- **Backend**: Python, Flask
- **Packet Capture**: Scapy
- **Database**: SQLite
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Charts**: Chart.js
- **Data Analysis**: Pandas, NumPy

## 📋 Prerequisites

### Windows Users
- **Npcap**: Download and install from [npcap.com](https://npcap.com/)
- **Administrator privileges**: Required for packet capture
- **Python 3.7+**

### Linux/macOS Users
- **Root/sudo privileges**: Required for packet capture
- **Python 3.7+**
- **libpcap**: Usually pre-installed

## 🚀 Installation & Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ECE-FINAL-PROJECT
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   # or
   .venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   # Create .env file
   echo "SECRET_KEY=your-secret-key-here" > .env
   ```

## 🎯 Usage

### Starting the Application
```bash
python app.py
```

### Testing Packet Capture
```bash
# Test real packet capture for 10 seconds
python test_capture.py --duration 10

# Test with specific interface
python test_capture.py --interface "your-interface-name" --duration 15
```

### Web Interface
1. Open browser to `http://localhost:5000`
2. Select a network interface
3. Start packet capture
4. View real-time dashboard and analysis

## 📊 Features Overview

### Real Network Data Capture
- **No dummy data**: Captures actual network packets from your network interface
- **Live traffic**: Monitors real network activity as it happens
- **Multiple protocols**: Supports HTTP, HTTPS, DNS, TCP, UDP, ARP, and more

### Dashboard Features
- **Real-time statistics**: Live packet counts and protocol distribution
- **Interactive charts**: Visual representation of network traffic
- **Top IPs**: Most active source and destination addresses
- **Anomaly alerts**: Configurable threshold-based detection

### Packet Analysis
- **Detailed packet information**: Source/destination IPs, ports, protocols
- **Protocol classification**: Automatic identification of traffic types
- **Traffic patterns**: Analysis of network behavior over time

## 🔧 Configuration

### Network Interface Selection
The application automatically detects available network interfaces. Select the appropriate interface for your network monitoring needs.

### Anomaly Detection Thresholds
Configure detection thresholds in the dashboard to identify suspicious traffic patterns.

## 🛡️ Security Considerations

- **Administrator privileges**: Required for low-level packet capture
- **Network permissions**: Ensure proper authorization for network monitoring
- **Data privacy**: Be aware of local privacy laws and regulations
- **Firewall settings**: May need to configure firewall exceptions

## 🐛 Troubleshooting

### Windows Issues
- Install Npcap from official website
- Run as Administrator
- Check Windows Firewall settings
- Verify Npcap service is running: `sc query npcap`

### Linux/macOS Issues
- Run with sudo privileges
- Check network interface permissions
- Verify libpcap installation

### No Packets Captured
- Ensure network activity is present
- Check interface selection
- Verify permissions
- Test with the included test script

## 📈 Performance Optimization

- **Database indexing**: Optimized for fast queries
- **Memory management**: Efficient packet storage and retrieval
- **Real-time processing**: Minimal latency in packet analysis

## 🤝 Contributing

This project was developed as part of an ECE final project. Contributions and improvements are welcome.

## 👥 Development Team

**Created by:**
- BELLO YUSUF ALANI
- UDEMGBA FERDINAND CHIDERA
- NWANKWO BLESSING PETER
- NNADI MITCHELL CHUKWUEBUKA
- EDEH JOHNPAUL CHUKWUEMKA
- IGUH CHIMEZIE ANTHONY

**Under the supervision of:**
- **Prof. K. A. Akpado**
- Engr. Chikwado Eze
- Odo Uchenna Hilary
- Ozumba Emeka Cyril

## 📄 License

This project is developed for educational purposes as part of an ECE final project.

---

**Note**: This tool captures real network traffic. Ensure you have proper authorization before monitoring network traffic and comply with local privacy laws and regulations.




