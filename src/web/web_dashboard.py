"""
IDS/IPS Web Dashboard Server - FALLBACK VERSION
Simple Flask-based web interface with basic sample data
Use this as fallback when real-time version is not available
"""

from flask import Flask, render_template, jsonify, request
import json
import os
import sys
from datetime import datetime, timedelta
import random
import threading
import time

app = Flask(__name__)

# Simple system stats
system_stats = {
    'status': 'running',
    'uptime': 0,
    'packets_analyzed': 0,
    'threats_detected': 0,
    'blocked_ips': 0,
    'start_time': datetime.now()
}

# Sample data for fallback mode
recent_threats = []
blocked_ips = []
system_logs = []

def generate_sample_data():
    """Generate simple sample data for fallback mode"""
    global recent_threats, blocked_ips, system_logs
    
    # Sample threat types
    threat_types = ["Port Scan", "SQL Injection", "DDoS Attack", "Malware", "Brute Force"]
    sample_ips = ["192.168.1.100", "10.0.0.50", "172.16.1.20", "203.0.113.10"]
    severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    # Generate sample threats
    for i in range(5):
        threat = {
            'id': f"SAMPLE_{i}",
            'timestamp': (datetime.now() - timedelta(minutes=i*10)).isoformat(),
            'source_ip': random.choice(sample_ips),
            'threat_type': random.choice(threat_types),
            'severity': random.choice(severities),
            'status': 'Logged',
            'country': 'Unknown'
        }
        recent_threats.append(threat)
    
    # Generate sample blocked IPs
    for i in range(3):
        blocked_ip = {
            'ip': sample_ips[i],
            'reason': random.choice(threat_types),
            'blocked_at': (datetime.now() - timedelta(hours=i)).isoformat(),
            'country': 'Unknown'
        }
        blocked_ips.append(blocked_ip)
    
    # Generate sample logs
    log_messages = [
        "Fallback dashboard started",
        "Sample data loaded",
        "Dashboard ready for viewing"
    ]
    
    for i, msg in enumerate(log_messages):
        log_entry = {
            'timestamp': (datetime.now() - timedelta(minutes=i*2)).isoformat(),
            'level': 'INFO',
            'message': msg
        }
        system_logs.append(log_entry)

def update_sample_stats():
    """Update sample statistics"""
    global system_stats
    
    while True:
        system_stats['uptime'] = int((datetime.now() - system_stats['start_time']).total_seconds())
        system_stats['packets_analyzed'] += random.randint(10, 50)
        
        # Occasionally add threats
        if random.random() < 0.2:
            system_stats['threats_detected'] += 1
            
        time.sleep(10)  # Update every 10 seconds

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get current system statistics"""
    return jsonify(system_stats)

@app.route('/api/threats')
def get_threats():
    """Get recent threats"""
    return jsonify(recent_threats)

@app.route('/api/blocked_ips')
def get_blocked_ips():
    """Get blocked IP addresses"""
    return jsonify(blocked_ips)

@app.route('/api/logs')
def get_logs():
    """Get system logs"""
    return jsonify(system_logs)

@app.route('/api/threat_stats')
def get_threat_stats():
    """Get threat statistics for charts"""
    threat_counts = {}
    for threat in recent_threats:
        threat_type = threat['threat_type']
        threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
    
    severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
    for threat in recent_threats:
        severity_counts[threat['severity']] += 1
    
    return jsonify({
        'threat_types': threat_counts,
        'severity_distribution': severity_counts
    })

@app.route('/api/network_activity')
def get_network_activity():
    """Get network activity data for charts"""
    hours = []
    packets = []
    threats = []
    
    for i in range(24):
        hour_time = datetime.now() - timedelta(hours=23-i)
        hours.append(hour_time.strftime('%H:%M'))
        packets.append(random.randint(100, 500))
        threats.append(random.randint(0, 5))
    
    return jsonify({
        'hours': hours,
        'packets': packets,
        'threats': threats
    })

if __name__ == '__main__':
    print("🌐 Starting IDS/IPS FALLBACK Web Dashboard...")
    print("⚠️ This is a fallback version with sample data")
    print("📊 For real-time data, use web_dashboard_real.py")
    
    # Generate initial sample data
    generate_sample_data()
    
    # Start background thread to update sample stats
    stats_thread = threading.Thread(target=update_sample_stats, daemon=True)
    stats_thread.start()
    
    print("📊 Dashboard available at: http://localhost:5000")
    print("🔍 Fallback monitoring interface active")
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=False)
