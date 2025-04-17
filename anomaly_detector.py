import os
import argparse
import logging
import pandas as pd

def detect_anomalies(log_file: str, threshold: int):
    """
    Reads the CSV file and detects anomalies by checking if any source IP
    has sent more than 'threshold' packets.

    Parameters:
        log_file (str): Path to the CSV file containing packet logs.
        threshold (int): Packet count threshold to flag anomalies.

    Returns:
        None; prints the anomalies found.
    """
    try:
        # Use pandas to efficiently read the CSV file
        df = pd.read_csv(log_file)
    except Exception as e:
        logging.error("Failed to read CSV file '%s': %s", log_file, e)
        return

    # Check if the dataframe is empty
    if df.empty:
        logging.warning("The CSV file '%s' is empty. No data to analyze.", log_file)
        return

    required_columns = {"timestamp", "src_ip", "dst_ip", "protocol", "length"}
    if not required_columns.issubset(df.columns):
        logging.error("CSV file '%s' is missing required columns. Expected columns: %s", 
                      log_file, required_columns)
        return
    
    ip_counts = df.groupby("src_ip").size()
    anomalies = ip_counts[ip_counts > threshold]

    if anomalies.empty:
        print("No anomalies detected.")
    else:
        print("Anomalies detected:")
        for ip, count in anomalies.items():
            print(f"  - IP {ip} has {count} packets (threshold: {threshold})")

def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(
        description="Anomaly detection for network packet logs."
    )
    parser.add_argument(
        "--log_file", type=str, default="packets_log.csv",
        help="Path to the packet log CSV file (default: packets_log.csv)"
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

    if not os.path.exists(args.log_file):
        logging.error("CSV file '%s' does not exist.", args.log_file)
        return

    # Run anomaly detection
    detect_anomalies(args.log_file, args.threshold)

if __name__ == "__main__":
    main()
