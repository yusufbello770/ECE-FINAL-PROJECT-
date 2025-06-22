import argparse
import logging
from db import get_top_ips, get_packet_count

def detect_anomalies(threshold: int):
    """
    Detects anomalies by checking if any source IP has sent more than 'threshold' packets.

    Parameters:
        threshold (int): Packet count threshold to flag anomalies.

    Returns:
        list: List of anomalies found
    """
    try:
        # Get top source IPs
        top_src_ips, _ = get_top_ips(limit=100)  # Get more IPs to check against threshold
        
        anomalies = []
        for ip, count in top_src_ips:
            if count > threshold:
                anomalies.append((ip, count))
        
        return anomalies
        
    except Exception as e:
        logging.error("Failed to detect anomalies: %s", e)
        return []

def print_anomalies(anomalies, threshold):
    """
    Print the detected anomalies.
    """
    if not anomalies:
        print("No anomalies detected.")
    else:
        print(f"Anomalies detected (threshold: {threshold} packets):")
        for ip, count in anomalies:
            print(f"  - IP {ip} has {count} packets")

def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(
        description="Anomaly detection for network packet logs."
    )
    parser.add_argument(
        "--threshold", type=int, default=100,
        help="Packet threshold for anomaly detection (default: 100)"
    )
    parser.add_argument(
        "--log_level", type=str, default="INFO",
        help="Logging level (DEBUG, INFO, WARNING, ERROR; default: INFO)"
    )
    args = parser.parse_args()
    
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
    logging.basicConfig(level=numeric_level,
                        format='%(asctime)s - %(levelname)s - %(message)s')

    # Check if database has data
    packet_count = get_packet_count()
    if packet_count == 0:
        logging.warning("No packets found in the database.")
        return

    # Run anomaly detection
    anomalies = detect_anomalies(args.threshold)
    print_anomalies(anomalies, args.threshold)

if __name__ == "__main__":
    main()
