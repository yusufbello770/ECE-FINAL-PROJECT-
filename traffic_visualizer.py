import matplotlib.pyplot as plt
from db import get_protocol_stats, get_top_ips

def visualize_protocol_distribution():
    """
    Reads the database and plots a bar chart showing how many packets
    are seen per protocol.
    """
    # Get protocol statistics from database
    protocol_stats = get_protocol_stats()
    
    if not protocol_stats:
        print("No data found in the database.")
        return

    # Prepare data for plotting
    protocols = list(protocol_stats.keys())
    counts = list(protocol_stats.values())
    
    # Create bar chart
    plt.figure(figsize=(10, 6))
    bars = plt.bar(protocols, counts, color='skyblue', edgecolor='navy', alpha=0.7)
    
    # Add value labels on bars
    for bar, count in zip(bars, counts):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01*max(counts),
                str(count), ha='center', va='bottom', fontweight='bold')
    
    plt.title("Protocol Distribution", fontsize=16, fontweight='bold')
    plt.xlabel("Protocol", fontsize=12)
    plt.ylabel("Number of Packets", fontsize=12)
    plt.grid(axis='y', alpha=0.3)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def visualize_top_ips(limit=5):
    """
    Visualize top source and destination IP addresses.
    """
    top_src_ips, top_dst_ips = get_top_ips(limit)
    
    if not top_src_ips and not top_dst_ips:
        print("No data found in the database.")
        return
    
    # Create subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    
    # Top source IPs
    if top_src_ips:
        src_ips = [ip for ip, _ in top_src_ips]
        src_counts = [count for _, count in top_src_ips]
        
        bars1 = ax1.bar(range(len(src_ips)), src_counts, color='lightcoral', alpha=0.7)
        ax1.set_title("Top Source IP Addresses", fontweight='bold')
        ax1.set_xlabel("IP Address")
        ax1.set_ylabel("Packet Count")
        ax1.set_xticks(range(len(src_ips)))
        ax1.set_xticklabels(src_ips, rotation=45, ha='right')
        
        # Add value labels
        for bar, count in zip(bars1, src_counts):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01*max(src_counts),
                    str(count), ha='center', va='bottom', fontweight='bold')
    
    # Top destination IPs
    if top_dst_ips:
        dst_ips = [ip for ip, _ in top_dst_ips]
        dst_counts = [count for _, count in top_dst_ips]
        
        bars2 = ax2.bar(range(len(dst_ips)), dst_counts, color='lightgreen', alpha=0.7)
        ax2.set_title("Top Destination IP Addresses", fontweight='bold')
        ax2.set_xlabel("IP Address")
        ax2.set_ylabel("Packet Count")
        ax2.set_xticks(range(len(dst_ips)))
        ax2.set_xticklabels(dst_ips, rotation=45, ha='right')
        
        # Add value labels
        for bar, count in zip(bars2, dst_counts):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01*max(dst_counts),
                    str(count), ha='center', va='bottom', fontweight='bold')
    
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    print("Visualizing protocol distribution...")
    visualize_protocol_distribution()
    
    print("\nVisualizing top IP addresses...")
    visualize_top_ips()

