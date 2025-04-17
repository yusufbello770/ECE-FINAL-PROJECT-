import csv
from collections import Counter
import matplotlib.pyplot as plt

LOG_FILE = "packets_log.csv"

def visualize_protocol_distribution(log_file=LOG_FILE):
    """
    Reads the CSV log file and plots a bar chart showing how many packets
    are seen per protocol.
    """
    protocol_counts = Counter()
    
    # Read CSV file
    with open(log_file, mode='r') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            protocol = row["protocol"]
            protocol_counts[protocol] += 1

    # Prepare data for plotting
    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())
    
    # Create bar chart
    plt.figure(figsize=(8, 6))
    plt.bar(protocols, counts, color='blue')
    plt.title("Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Number of Packets")
    plt.grid(axis='y')
    plt.show()

if __name__ == "__main__":
    visualize_protocol_distribution()
