import logging
from db import get_packet_count, get_protocol_stats, get_top_ips

# Set up logging
logger = logging.getLogger(__name__)

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
        logger.warning("No packets found in the database.")
        return
    
    # Get protocol statistics
    protocol_stats = get_protocol_stats()
    
    # Get top IP addresses
    top_src_ips, top_dst_ips = get_top_ips(5)
    
    logger.info(f"Total Packets: {total_packets}")
    logger.info("Top 5 Source IPs:")
    for ip, count in top_src_ips:
        logger.info(f"  {ip}: {count} packets")
    
    logger.info("Top 5 Destination IPs:")
    for ip, count in top_dst_ips:
        logger.info(f"  {ip}: {count} packets")
    
    logger.info("Protocol Distribution:")
    for proto, count in protocol_stats.items():
        logger.info(f"  {proto}: {count} packets")

if __name__ == "__main__":
    analyze_packets()
