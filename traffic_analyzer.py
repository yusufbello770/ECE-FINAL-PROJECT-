import csv
from collections import Counter

LOG_FILE = "packets_log.csv"

def analyze_packets(log_file=LOG_FILE):
    """
    Reads packet data from a CSV file and prints out:
    1. Total number of packets
    2. Average packet size
    3. Top 5 source IP addresses
    4. Top 5 destination IP addresses
    5. Protocol distribution
    """
    total_packets = 0
    total_size = 0
    src_counter = Counter()
    dst_counter = Counter()
    protocol_counter = Counter()
    
    with open(log_file, mode='r') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            total_packets += 1
            total_size += int(row["length"])
            
            src_counter[row["src_ip"]] += 1
            dst_counter[row["dst_ip"]] += 1
            protocol_counter[row["protocol"]] += 1
    
    if total_packets == 0:
        print("No packets found in the log file.")
        return
    
    avg_size = total_size / total_packets   
    print(f"Total Packets: {total_packets}")
    print(f"Average Packet Size: {avg_size:.2f} bytes")
    
  
    print("\nTop 5 Source IPs:")
    for ip, count in src_counter.most_common(5):
        print(f"  {ip}: {count} packets")
    
    print("\nTop 5 Destination IPs:")
    for ip, count in dst_counter.most_common(5):
        print(f"  {ip}: {count} packets")
    
    print("\nProtocol Distribution:")
    for proto, count in protocol_counter.most_common():
        print(f"  {proto}: {count} packets")

if __name__ == "__main__":
    analyze_packets()
