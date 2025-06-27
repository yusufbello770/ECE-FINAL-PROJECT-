import sqlite3
import time
import os
import logging
from datetime import datetime

# Set up logging
logger = logging.getLogger(__name__)

# Database file name
DB_FILE = "packets.db"

def init_db():
    """
    Initialize the database with the correct schema.
    Creates the database file if it doesn't exist.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Create the packets table with proper schema matching CSV format
    c.execute("""CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                length INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )""")
    
    # Create indexes for better performance
    c.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_dst_ip ON packets(dst_ip)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_protocol ON packets(protocol)")
    
    conn.commit()
    conn.close()
    logger.info(f"Database initialized: {DB_FILE}")

def insert_packet(packet_data):
    """
    Insert a single packet into the database.
    
    Args:
        packet_data (dict): Dictionary containing packet information
            - timestamp: float
            - src_ip: str
            - dst_ip: str
            - protocol: str
            - length: int
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        c.execute("""INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length)
                     VALUES (?, ?, ?, ?, ?)""",
                  (packet_data['timestamp'], 
                   packet_data['src_ip'], 
                   packet_data['dst_ip'], 
                   packet_data['protocol'], 
                   packet_data['length']))
        conn.commit()
    except Exception as e:
        logger.error(f"Error inserting packet: {e}")
    finally:
        conn.close()

def get_all_packets(limit=None):
    """
    Get all packets from the database.
    
    Args:
        limit (int, optional): Maximum number of packets to return
    
    Returns:
        list: List of dictionaries containing packet data
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        if limit:
            c.execute("SELECT timestamp, src_ip, dst_ip, protocol, length FROM packets ORDER BY timestamp DESC LIMIT ?", (limit,))
        else:
            c.execute("SELECT timestamp, src_ip, dst_ip, protocol, length FROM packets ORDER BY timestamp DESC")
        
        rows = c.fetchall()
        packets = []
        for row in rows:
            packets.append({
                'timestamp': row[0],
                'src_ip': row[1],
                'dst_ip': row[2],
                'protocol': row[3],
                'length': row[4]
            })
        return packets
    except Exception as e:
        logger.error(f"Error getting packets: {e}")
        return []
    finally:
        conn.close()

def get_packet_count():
    """
    Get the total number of packets in the database.
    
    Returns:
        int: Total packet count
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        c.execute("SELECT COUNT(*) FROM packets")
        count = c.fetchone()[0]
        return count
    except Exception as e:
        logger.error(f"Error getting packet count: {e}")
        return 0
    finally:
        conn.close()

def get_protocol_stats():
    """
    Get protocol distribution statistics.
    
    Returns:
        dict: Dictionary with protocol counts
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        c.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol")
        rows = c.fetchall()
        stats = {}
        for row in rows:
            stats[row[0]] = row[1]
        return stats
    except Exception as e:
        logger.error(f"Error getting protocol stats: {e}")
        return {}
    finally:
        conn.close()

def get_top_ips(limit=5):
    """
    Get top source and destination IP addresses.
    
    Args:
        limit (int): Number of top IPs to return
    
    Returns:
        tuple: (top_src_ips, top_dst_ips)
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        # Get top source IPs
        c.execute("SELECT src_ip, COUNT(*) FROM packets GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT ?", (limit,))
        top_src = c.fetchall()
        
        # Get top destination IPs
        c.execute("SELECT dst_ip, COUNT(*) FROM packets GROUP BY dst_ip ORDER BY COUNT(*) DESC LIMIT ?", (limit,))
        top_dst = c.fetchall()
        
        return top_src, top_dst
    except Exception as e:
        logger.error(f"Error getting top IPs: {e}")
        return [], []
    finally:
        conn.close()

def clear_database():
    """
    Clear all data from the database.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        c.execute("DELETE FROM packets")
        conn.commit()
        logger.info("Database cleared successfully")
    except Exception as e:
        logger.error(f"Error clearing database: {e}")
    finally:
        conn.close()

def migrate_csv_to_db(csv_file="packets_log.csv"):
    """
    Migrate data from CSV file to database if CSV exists.
    
    Args:
        csv_file (str): Path to CSV file
    """
    if not os.path.exists(csv_file):
        return
    
    import csv
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        with open(csv_file, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                c.execute("""INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length)
                             VALUES (?, ?, ?, ?, ?)""",
                          (float(row['timestamp']), 
                           row['src_ip'], 
                           row['dst_ip'], 
                           row['protocol'], 
                           int(row['length'])))
        conn.commit()
        logger.info(f"Migrated data from {csv_file} to database")
    except Exception as e:
        logger.error(f"Error migrating CSV to database: {e}")
    finally:
        conn.close()

# Initialize database when module is imported
if __name__ == "__main__":
    init_db()
else:
    init_db()
