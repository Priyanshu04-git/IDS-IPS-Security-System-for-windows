"""
IDS/IPS Data Management Tool
Allows manual management of persistent data storage
"""

import sqlite3
import argparse
import sys
import os
from datetime import datetime, timedelta

class DataManager:
    def __init__(self, db_path):
        self.db_path = db_path
        if not os.path.exists(db_path):
            print(f"❌ Database not found: {db_path}")
            sys.exit(1)
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def view_threats(self, limit=10):
        """View recent threats"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT threat_id, timestamp, source_ip, threat_type, severity, blocked
        FROM threats 
        ORDER BY timestamp DESC 
        LIMIT ?
        ''', (limit,))
        
        print(f"\n📊 Recent {limit} Threats:")
        print("-" * 80)
        print(f"{'ID':<12} {'Time':<20} {'Source IP':<15} {'Type':<15} {'Severity':<8} {'Blocked'}")
        print("-" * 80)
        
        for row in cursor.fetchall():
            threat_id, timestamp, source_ip, threat_type, severity, blocked = row
            blocked_str = "✅ Yes" if blocked else "❌ No"
            time_str = timestamp[:19] if timestamp else "Unknown"
            print(f"{threat_id:<12} {time_str:<20} {source_ip:<15} {threat_type:<15} {severity:<8} {blocked_str}")
        
        conn.close()
    
    def count_data(self):
        """Show data counts"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        tables = ['threats', 'alerts', 'system_stats', 'blocked_ips', 'threat_intelligence']
        
        print("\n📈 Data Statistics:")
        print("-" * 30)
        
        for table in tables:
            try:
                cursor.execute(f'SELECT COUNT(*) FROM {table}')
                count = cursor.fetchone()[0]
                print(f"{table.capitalize():<20}: {count:>6}")
            except Exception as e:
                print(f"{table.capitalize():<20}: Error - {e}")
        
        conn.close()
    
    def delete_old_data(self, days=30):
        """Delete data older than specified days"""
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        tables_with_timestamp = ['threats', 'alerts', 'system_stats', 'blocked_ips', 'threat_intelligence']
        
        print(f"\n🗑️  Deleting data older than {days} days (before {cutoff_date[:10]})...")
        
        total_deleted = 0
        for table in tables_with_timestamp:
            try:
                cursor.execute(f'SELECT COUNT(*) FROM {table} WHERE timestamp < ?', (cutoff_date,))
                count_before = cursor.fetchone()[0]
                
                cursor.execute(f'DELETE FROM {table} WHERE timestamp < ?', (cutoff_date,))
                deleted = cursor.rowcount
                total_deleted += deleted
                
                if deleted > 0:
                    print(f"  {table}: {deleted} records deleted")
            except Exception as e:
                print(f"  {table}: Error - {e}")
        
        conn.commit()
        conn.close()
        
        print(f"✅ Total records deleted: {total_deleted}")
    
    def clear_all_data(self):
        """Clear all data (keep structure)"""
        confirmation = input("⚠️  This will delete ALL data. Type 'DELETE ALL' to confirm: ")
        
        if confirmation != "DELETE ALL":
            print("❌ Operation cancelled")
            return
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        tables = ['threats', 'alerts', 'system_stats', 'blocked_ips', 'threat_intelligence', 
                 'network_sessions', 'reports', 'geographic_data']
        
        print("\n🗑️  Clearing all data...")
        
        for table in tables:
            try:
                cursor.execute(f'DELETE FROM {table}')
                deleted = cursor.rowcount
                print(f"  {table}: {deleted} records deleted")
            except Exception as e:
                print(f"  {table}: Error - {e}")
        
        conn.commit()
        conn.close()
        
        print("✅ All data cleared successfully")
    
    def backup_data(self, backup_file):
        """Create a backup of the database"""
        try:
            import shutil
            shutil.copy2(self.db_path, backup_file)
            print(f"✅ Database backed up to: {backup_file}")
        except Exception as e:
            print(f"❌ Backup failed: {e}")
    
    def show_dashboard_preview(self):
        """Show a preview of dashboard data"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        print("\n🎯 Dashboard Data Preview:")
        print("=" * 50)
        
        # Threat type breakdown
        cursor.execute('''
        SELECT threat_type, COUNT(*) as count 
        FROM threats 
        GROUP BY threat_type 
        ORDER BY count DESC 
        LIMIT 5
        ''')
        
        print("\n📊 Top Threat Types:")
        for row in cursor.fetchall():
            threat_type, count = row
            print(f"  {threat_type:<15}: {count:>4} threats")
        
        # Top attacking IPs
        cursor.execute('''
        SELECT source_ip, COUNT(*) as count 
        FROM threats 
        GROUP BY source_ip 
        ORDER BY count DESC 
        LIMIT 5
        ''')
        
        print("\n🚨 Top Attacking IPs:")
        for row in cursor.fetchall():
            ip, count = row
            print(f"  {ip:<15}: {count:>4} attacks")
        
        # Recent activity
        cursor.execute('''
        SELECT DATE(timestamp) as date, COUNT(*) as threats
        FROM threats 
        WHERE timestamp > datetime('now', '-7 days')
        GROUP BY DATE(timestamp)
        ORDER BY date DESC
        ''')
        
        print("\n📅 Recent Activity (Last 7 days):")
        for row in cursor.fetchall():
            date, threats = row
            print(f"  {date}: {threats:>4} threats")
        
        conn.close()

def main():
    parser = argparse.ArgumentParser(description='IDS/IPS Data Management Tool')
    parser.add_argument('--db', default='/home/priyanshu/Desktop/ids_ips_final_delivery/ids_ips_final_delivery/logs/ids_events.db',
                       help='Database path')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # View command
    view_parser = subparsers.add_parser('view', help='View recent threats')
    view_parser.add_argument('--limit', type=int, default=10, help='Number of threats to show')
    
    # Stats command
    subparsers.add_parser('stats', help='Show data statistics')
    
    # Clean command
    clean_parser = subparsers.add_parser('clean', help='Delete old data')
    clean_parser.add_argument('--days', type=int, default=30, help='Delete data older than N days')
    
    # Clear command
    subparsers.add_parser('clear', help='Clear all data')
    
    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Backup database')
    backup_parser.add_argument('file', help='Backup file path')
    
    # Dashboard command
    subparsers.add_parser('dashboard', help='Show dashboard data preview')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    manager = DataManager(args.db)
    
    if args.command == 'view':
        manager.view_threats(args.limit)
    elif args.command == 'stats':
        manager.count_data()
    elif args.command == 'clean':
        manager.delete_old_data(args.days)
    elif args.command == 'clear':
        manager.clear_all_data()
    elif args.command == 'backup':
        manager.backup_data(args.file)
    elif args.command == 'dashboard':
        manager.show_dashboard_preview()

if __name__ == "__main__":
    main()
