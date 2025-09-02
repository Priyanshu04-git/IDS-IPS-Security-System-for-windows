"""
IDS/IPS Web Dashboard Server - SIMPLE REAL-TIME VERSION
Flask-based web interface for monitoring and managing the IDS/IPS system
Simple version without external dependencies that might cause loading issues
"""

from flask import Flask, jsonify
import json
import os
import sys
from datetime import datetime, timedelta
import threading
import time

app = Flask(__name__)

# Global variables to store system data
system_stats = {
    'status': 'running',
    'uptime': 0,
    'packets_analyzed': 0,
    'threats_detected': 0,
    'blocked_ips': 0,
    'start_time': datetime.now(),
    'packets_per_second': 0,
    'threat_rate': 0
}

recent_threats = []
blocked_ips = []
system_logs = []

def update_stats():
    """Update system statistics"""
    global system_stats, recent_threats, blocked_ips, system_logs
    
    while True:
        try:
            # Update uptime
            system_stats['uptime'] = int((datetime.now() - system_stats['start_time']).total_seconds())
            
            # Simulate some realistic stats
            system_stats['packets_analyzed'] += 5
            
            # Calculate packets per second
            if system_stats['uptime'] > 0:
                system_stats['packets_per_second'] = round(system_stats['packets_analyzed'] / system_stats['uptime'], 2)
            
            # Add occasional log entries
            if system_stats['uptime'] % 30 == 0 and system_stats['uptime'] > 0:  # Every 30 seconds
                system_logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'level': 'INFO',
                    'message': f"System Status: {system_stats['packets_analyzed']} packets analyzed, {system_stats['threats_detected']} threats detected"
                })
                
                # Keep logs manageable
                system_logs = system_logs[-50:]
            
        except Exception as e:
            print(f"Error in stats update: {e}")
        
        time.sleep(1)  # Update every second

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>IDS/IPS Security Dashboard - Real-time</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                color: #fff;
                min-height: 100vh;
                padding: 20px;
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            
            .header {
                text-align: center;
                margin-bottom: 30px;
            }
            
            .header h1 {
                font-size: 2.5rem;
                margin-bottom: 10px;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            }
            
            .status-bar {
                background: rgba(255,255,255,0.1);
                padding: 15px;
                border-radius: 10px;
                margin-bottom: 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
            }
            
            .status-item {
                text-align: center;
                margin: 5px;
            }
            
            .status-value {
                font-size: 1.5rem;
                font-weight: bold;
                color: #4CAF50;
            }
            
            .cards-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            
            .card {
                background: rgba(255,255,255,0.1);
                padding: 20px;
                border-radius: 15px;
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.2);
            }
            
            .card h3 {
                margin-bottom: 15px;
                color: #4CAF50;
                font-size: 1.2rem;
            }
            
            .metric {
                display: flex;
                justify-content: space-between;
                margin: 10px 0;
                padding: 5px 0;
                border-bottom: 1px solid rgba(255,255,255,0.1);
            }
            
            .metric:last-child {
                border-bottom: none;
            }
            
            .log-entry {
                background: rgba(255,255,255,0.05);
                padding: 8px 12px;
                margin: 5px 0;
                border-radius: 5px;
                font-size: 0.9rem;
                border-left: 3px solid #4CAF50;
            }
            
            .log-entry.warning {
                border-left-color: #FF9800;
            }
            
            .log-entry.error {
                border-left-color: #F44336;
            }
            
            .refresh-button {
                background: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 1rem;
                margin: 10px;
            }
            
            .refresh-button:hover {
                background: #45a049;
            }
            
            .live-indicator {
                display: inline-block;
                width: 8px;
                height: 8px;
                background: #4CAF50;
                border-radius: 50%;
                margin-right: 5px;
                animation: pulse 2s infinite;
            }
            
            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.5; }
                100% { opacity: 1; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ IDS/IPS Security Dashboard</h1>
                <p><span class="live-indicator"></span>Real-time Network Security Monitoring</p>
            </div>
            
            <div class="status-bar">
                <div class="status-item">
                    <div class="status-value" id="threats-count">0</div>
                    <div>Threats Detected</div>
                </div>
                <div class="status-item">
                    <div class="status-value" id="packets-count">0</div>
                    <div>Packets Analyzed</div>
                </div>
                <div class="status-item">
                    <div class="status-value" id="blocked-count">0</div>
                    <div>Blocked IPs</div>
                </div>
                <div class="status-item">
                    <div class="status-value" id="uptime">0s</div>
                    <div>Uptime</div>
                </div>
            </div>
            
            <div class="cards-grid">
                <div class="card">
                    <h3>📊 System Statistics</h3>
                    <div class="metric">
                        <span>Status:</span>
                        <span id="system-status">Running</span>
                    </div>
                    <div class="metric">
                        <span>Packets/sec:</span>
                        <span id="packets-per-sec">0</span>
                    </div>
                    <div class="metric">
                        <span>Threat Rate:</span>
                        <span id="threat-rate">0%</span>
                    </div>
                    <button class="refresh-button" onclick="refreshData()">🔄 Refresh Data</button>
                </div>
                
                <div class="card">
                    <h3>🚨 Recent Threats</h3>
                    <div id="threats-list">
                        <div class="log-entry">No threats detected</div>
                    </div>
                </div>
                
                <div class="card">
                    <h3>🚫 Blocked IPs</h3>
                    <div id="blocked-ips-list">
                        <div class="log-entry">No IPs blocked</div>
                    </div>
                </div>
                
                <div class="card">
                    <h3>📝 System Logs</h3>
                    <div id="logs-list">
                        <div class="log-entry">System initialized</div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            let autoRefresh = true;
            
            function formatUptime(seconds) {
                const hours = Math.floor(seconds / 3600);
                const minutes = Math.floor((seconds % 3600) / 60);
                const secs = seconds % 60;
                return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m ${secs}s`;
            }
            
            function refreshData() {
                // Fetch system stats
                fetch('/api/stats')
                    .then(response => response.json())
                    .then(data => {
                        document.getElementById('threats-count').textContent = data.threats_detected || 0;
                        document.getElementById('packets-count').textContent = data.packets_analyzed || 0;
                        document.getElementById('blocked-count').textContent = data.blocked_ips || 0;
                        document.getElementById('uptime').textContent = formatUptime(data.uptime || 0);
                        document.getElementById('system-status').textContent = data.status || 'Unknown';
                        document.getElementById('packets-per-sec').textContent = (data.packets_per_second || 0).toFixed(1);
                        document.getElementById('threat-rate').textContent = (data.threat_rate || 0).toFixed(2) + '%';
                    })
                    .catch(error => console.error('Error fetching stats:', error));
                
                // Fetch threats
                fetch('/api/threats')
                    .then(response => response.json())
                    .then(data => {
                        const threatsList = document.getElementById('threats-list');
                        if (data.length === 0) {
                            threatsList.innerHTML = '<div class="log-entry">No threats detected</div>';
                        } else {
                            threatsList.innerHTML = data.slice(-5).map(threat => 
                                `<div class="log-entry warning">${threat.timestamp || 'Unknown'}: ${threat.threat_type || 'Unknown threat'} from ${threat.source_ip || 'Unknown IP'}</div>`
                            ).join('');
                        }
                    })
                    .catch(error => console.error('Error fetching threats:', error));
                
                // Fetch blocked IPs
                fetch('/api/blocked_ips')
                    .then(response => response.json())
                    .then(data => {
                        const blockedList = document.getElementById('blocked-ips-list');
                        if (data.length === 0) {
                            blockedList.innerHTML = '<div class="log-entry">No IPs blocked</div>';
                        } else {
                            blockedList.innerHTML = data.slice(-5).map(ip => 
                                `<div class="log-entry error">${ip.ip || 'Unknown IP'}: ${ip.reason || 'Security violation'}</div>`
                            ).join('');
                        }
                    })
                    .catch(error => console.error('Error fetching blocked IPs:', error));
                
                // Fetch logs
                fetch('/api/logs')
                    .then(response => response.json())
                    .then(data => {
                        const logsList = document.getElementById('logs-list');
                        if (data.length === 0) {
                            logsList.innerHTML = '<div class="log-entry">No logs available</div>';
                        } else {
                            logsList.innerHTML = data.slice(-5).reverse().map(log => {
                                const level = log.level || 'INFO';
                                const cssClass = level.toLowerCase() === 'error' ? 'error' : 
                                                level.toLowerCase() === 'warning' ? 'warning' : '';
                                return `<div class="log-entry ${cssClass}">[${new Date(log.timestamp).toLocaleTimeString()}] ${level}: ${log.message}</div>`;
                            }).join('');
                        }
                    })
                    .catch(error => console.error('Error fetching logs:', error));
            }
            
            // Initial load
            refreshData();
            
            // Auto-refresh every 5 seconds
            if (autoRefresh) {
                setInterval(refreshData, 5000);
            }
        </script>
    </body>
    </html>
    '''

@app.route('/api/stats')
def get_stats():
    """Get current system statistics"""
    return jsonify(system_stats)

@app.route('/api/threats')
def get_threats():
    """Get recent threat detections"""
    return jsonify(recent_threats[-20:])

@app.route('/api/blocked_ips')
def get_blocked_ips():
    """Get list of blocked IP addresses"""
    return jsonify(blocked_ips[-20:])

@app.route('/api/logs')
def get_logs():
    """Get recent system logs"""
    return jsonify(system_logs[-30:])

if __name__ == '__main__':
    print("🛡️ Starting Simple Real-Time IDS/IPS Web Dashboard...")
    print("=" * 60)
    print("🔧 Initializing simple monitoring system...")
    
    # Add initial log
    system_logs.append({
        'timestamp': datetime.now().isoformat(),
        'level': 'INFO',
        'message': 'Simple IDS/IPS dashboard started successfully'
    })
    
    # Start background thread for updating stats
    stats_thread = threading.Thread(target=update_stats, daemon=True)
    stats_thread.start()
    print("✅ Stats update thread started")
    
    print("=" * 60)
    print("🌐 Web Dashboard available at: http://localhost:5000")
    print("📊 Simple dashboard with basic functionality")
    print("💻 Open http://localhost:5000 in your browser")
    print("=" * 60)
    
    # Run Flask app
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        print(f"❌ Error starting web server: {e}")
        input("Press Enter to exit...")
