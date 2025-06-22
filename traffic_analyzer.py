from db import get_packet_count, get_protocol_stats, get_top_ips

def analyze_packets():
    """
    Reads packet data from the database and prints out:
    1. Total number of packets
    2. Average packet size
    3. Top 5 source IP addresses
    4. Top 5 destination IP addresses
    5. Protocol distribution
    """
    # Get packet count
    total_packets = get_packet_count()
    
    if total_packets == 0:
        print("No packets found in the database.")
        return
    
    # Get protocol statistics
    protocol_stats = get_protocol_stats()
    
    # Get top IP addresses
    top_src_ips, top_dst_ips = get_top_ips(5)
    
    print(f"Total Packets: {total_packets}")
    
    # Calculate average packet size (we'll need to add this to db.py)
    # For now, we'll skip this calculation
    # print(f"Average Packet Size: {avg_size:.2f} bytes")
    
    print("\nTop 5 Source IPs:")
    for ip, count in top_src_ips:
        print(f"  {ip}: {count} packets")
    
    print("\nTop 5 Destination IPs:")
    for ip, count in top_dst_ips:
        print(f"  {ip}: {count} packets")
    
    print("\nProtocol Distribution:")
    for proto, count in protocol_stats.items():
        print(f"  {proto}: {count} packets")

if __name__ == "__main__":
    analyze_packets()
