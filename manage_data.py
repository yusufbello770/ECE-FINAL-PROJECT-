#!/usr/bin/env python3
"""
Data management script for the packet sniffer.
Provides options to clear, backup, and manage captured packet data.
"""

import os
import shutil
import sqlite3
import argparse
import logging
from datetime import datetime
from db import get_packet_count, clear_database, init_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def backup_database(backup_dir="backups"):
    """Create a backup of the current database"""
    if not os.path.exists("packets.db"):
        logger.error("No database file found to backup")
        return False
    
    # Create backup directory if it doesn't exist
    os.makedirs(backup_dir, exist_ok=True)
    
    # Create backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"packets_backup_{timestamp}.db"
    backup_path = os.path.join(backup_dir, backup_filename)
    
    try:
        shutil.copy2("packets.db", backup_path)
        packet_count = get_packet_count()
        logger.info(f"✅ Database backed up successfully!")
        logger.info(f"   Backup file: {backup_path}")
        logger.info(f"   Packets backed up: {packet_count}")
        return backup_path
    except Exception as e:
        logger.error(f"❌ Backup failed: {e}")
        return False

def restore_database(backup_file):
    """Restore database from backup"""
    if not os.path.exists(backup_file):
        logger.error(f"Backup file not found: {backup_file}")
        return False
    
    try:
        # Backup current database first
        if os.path.exists("packets.db"):
            current_backup = backup_database("temp_backups")
            if current_backup:
                logger.info(f"Current database backed up to: {current_backup}")
        
        # Restore from backup
        shutil.copy2(backup_file, "packets.db")
        packet_count = get_packet_count()
        logger.info(f"✅ Database restored successfully!")
        logger.info(f"   Restored from: {backup_file}")
        logger.info(f"   Packets restored: {packet_count}")
        return True
    except Exception as e:
        logger.error(f"❌ Restore failed: {e}")
        return False

def show_database_info():
    """Show information about the current database"""
    if not os.path.exists("packets.db"):
        logger.info("No database file found")
        return
    
    try:
        # Get basic stats
        packet_count = get_packet_count()
        file_size = os.path.getsize("packets.db") / (1024 * 1024)  # MB
        
        # Get date range
        conn = sqlite3.connect("packets.db")
        c = conn.cursor()
        c.execute("SELECT MIN(timestamp), MAX(timestamp) FROM packets")
        min_time, max_time = c.fetchone()
        
        # Get protocol stats
        c.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol ORDER BY COUNT(*) DESC")
        protocols = c.fetchall()
        
        conn.close()
        
        logger.info("📊 DATABASE INFORMATION")
        logger.info("=" * 30)
        logger.info(f"Total packets: {packet_count}")
        logger.info(f"Database size: {file_size:.2f} MB")
        
        if min_time and max_time:
            min_date = datetime.fromtimestamp(min_time).strftime("%Y-%m-%d %H:%M:%S")
            max_date = datetime.fromtimestamp(max_time).strftime("%Y-%m-%d %H:%M:%S")
            logger.info(f"Date range: {min_date} to {max_date}")
        
        if protocols:
            logger.info("Protocol distribution:")
            for protocol, count in protocols:
                percentage = (count / packet_count) * 100
                logger.info(f"  {protocol}: {count} packets ({percentage:.1f}%)")
        
    except Exception as e:
        logger.error(f"Error getting database info: {e}")

def clear_old_data(days=7):
    """Clear data older than specified days"""
    try:
        cutoff_time = datetime.now().timestamp() - (days * 24 * 60 * 60)
        
        conn = sqlite3.connect("packets.db")
        c = conn.cursor()
        
        # Count packets to be deleted
        c.execute("SELECT COUNT(*) FROM packets WHERE timestamp < ?", (cutoff_time,))
        old_count = c.fetchone()[0]
        
        if old_count == 0:
            logger.info(f"No packets older than {days} days found")
            conn.close()
            return
        
        # Delete old packets
        c.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff_time,))
        conn.commit()
        conn.close()
        
        logger.info(f"✅ Deleted {old_count} packets older than {days} days")
        
    except Exception as e:
        logger.error(f"Error clearing old data: {e}")

def export_data(format="csv", filename=None):
    """Export packet data to different formats"""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"packets_export_{timestamp}.{format}"
    
    try:
        conn = sqlite3.connect("packets.db")
        
        if format.lower() == "csv":
            import csv
            c = conn.cursor()
            c.execute("SELECT * FROM packets ORDER BY timestamp DESC")
            
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                # Write header
                writer.writerow(['id', 'timestamp', 'src_ip', 'dst_ip', 'src_mac', 'dst_mac', 
                               'protocol', 'src_port', 'dst_port', 'length', 'info', 'created_at'])
                # Write data
                writer.writerows(c.fetchall())
            
            packet_count = get_packet_count()
            logger.info(f"✅ Exported {packet_count} packets to {filename}")
            
        else:
            logger.error(f"Unsupported export format: {format}")
            return False
        
        conn.close()
        return filename
        
    except Exception as e:
        logger.error(f"Error exporting data: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Manage packet sniffer database")
    parser.add_argument("action", choices=["info", "clear", "backup", "restore", "export", "clean"], 
                       help="Action to perform")
    parser.add_argument("--file", help="File path for backup/restore operations")
    parser.add_argument("--days", type=int, default=7, help="Days for clean operation (default: 7)")
    parser.add_argument("--format", default="csv", help="Export format (default: csv)")
    
    args = parser.parse_args()
    
    # Initialize database if it doesn't exist
    init_db()
    
    if args.action == "info":
        show_database_info()
        
    elif args.action == "clear":
        packet_count = get_packet_count()
        if packet_count == 0:
            logger.info("Database is already empty")
        else:
            confirm = input(f"Are you sure you want to delete all {packet_count} packets? (y/N): ")
            if confirm.lower() == 'y':
                clear_database()
                logger.info("✅ Database cleared successfully")
            else:
                logger.info("Operation cancelled")
                
    elif args.action == "backup":
        backup_path = backup_database()
        if backup_path:
            logger.info(f"Backup completed: {backup_path}")
            
    elif args.action == "restore":
        if not args.file:
            logger.error("Please specify backup file with --file")
        else:
            restore_database(args.file)
            
    elif args.action == "export":
        export_file = export_data(args.format, args.file)
        if export_file:
            logger.info(f"Export completed: {export_file}")
            
    elif args.action == "clean":
        clear_old_data(args.days)

if __name__ == "__main__":
    main()