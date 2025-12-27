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
    Creates the database file if it doesn't exist and handles migrations.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Check if table exists and get its schema
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='packets'")
    table_exists = c.fetchone() is not None
    
    if not table_exists:
        # Create new table with full schema
        c.execute("""CREATE TABLE packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_mac TEXT,
                    dst_mac TEXT,
                    protocol TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    length INTEGER,
                    info TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )""")
        logger.info("Created new packets table with full schema")
    else:
        # Check if we need to add new columns
        c.execute("PRAGMA table_info(packets)")
        columns = [column[1] for column in c.fetchall()]
        
        # Add missing columns
        if 'src_mac' not in columns:
            c.execute("ALTER TABLE packets ADD COLUMN src_mac TEXT")
            logger.info("Added src_mac column")
        if 'dst_mac' not in columns:
            c.execute("ALTER TABLE packets ADD COLUMN dst_mac TEXT")
            logger.info("Added dst_mac column")
        if 'src_port' not in columns:
            c.execute("ALTER TABLE packets ADD COLUMN src_port INTEGER")
            logger.info("Added src_port column")
        if 'dst_port' not in columns:
            c.execute("ALTER TABLE packets ADD COLUMN dst_port INTEGER")
            logger.info("Added dst_port column")
        if 'info' not in columns:
            c.execute("ALTER TABLE packets ADD COLUMN info TEXT")
            logger.info("Added info column")
    
    # Create indexes for better performance
    try:
        c.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON packets(src_ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_dst_ip ON packets(dst_ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_protocol ON packets(protocol)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_src_port ON packets(src_port)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_dst_port ON packets(dst_port)")
    except Exception as e:
        logger.warning(f"Could not create some indexes: {e}")
    
    conn.commit()
    conn.close()
    logger.info(f"Database initialized: {DB_FILE}")

def insert_packet(packet_data):
    """
    Insert a single packet into the database.
    
    Args:
        packet_data (dict): Dictionary containing packet information
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        c.execute("""INSERT INTO packets (timestamp, src_ip, dst_ip, src_mac, dst_mac, 
                     protocol, src_port, dst_port, length, info)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                  (packet_data.get('timestamp'), 
                   packet_data.get('src_ip'), 
                   packet_data.get('dst_ip'),
                   packet_data.get('src_mac'),
                   packet_data.get('dst_mac'),
                   packet_data.get('protocol'), 
                   packet_data.get('src_port'),
                   packet_data.get('dst_port'),
                   packet_data.get('length'),
                   packet_data.get('info', '')))
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
            c.execute("""SELECT timestamp, src_ip, dst_ip, src_mac, dst_mac, protocol, 
                        src_port, dst_port, length, info FROM packets 
                        ORDER BY timestamp DESC LIMIT ?""", (limit,))
        else:
            c.execute("""SELECT timestamp, src_ip, dst_ip, src_mac, dst_mac, protocol, 
                        src_port, dst_port, length, info FROM packets 
                        ORDER BY timestamp DESC""")
        
        rows = c.fetchall()
        packets = []
        for row in rows:
            packets.append({
                'timestamp': row[0],
                'src_ip': row[1],
                'dst_ip': row[2],
                'src_mac': row[3],
                'dst_mac': row[4],
                'protocol': row[5],
                'src_port': row[6],
                'dst_port': row[7],
                'length': row[8],
                'info': row[9]
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
