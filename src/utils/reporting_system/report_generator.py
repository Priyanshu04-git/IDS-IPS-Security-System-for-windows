"""
Report Generation System for IDS/IPS
Generates comprehensive security reports in multiple formats
"""

import sqlite3
import json
import csv
import io
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.linecharts import HorizontalLineChart
import pandas as pd
import numpy as np

@dataclass
class ReportConfig:
    report_type: str
    start_date: str
    end_date: str
    format: str  # 'pdf', 'html', 'csv', 'json'
    include_charts: bool = True
    include_details: bool = True
    severity_filter: Optional[List[str]] = None
    component_filter: Optional[List[str]] = None

class ReportGenerator:
    """Comprehensive report generation for IDS/IPS system"""
    
    def __init__(self, db_path: str, output_dir: str = "/tmp/reports"):
        self.db_path = db_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup matplotlib style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        # Report styles
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        )
    
    def generate_report(self, config: ReportConfig) -> str:
        """Generate a comprehensive security report"""
        try:
            # Collect data based on report type
            data = self._collect_report_data(config)
            
            # Generate report based on format
            if config.format.lower() == 'pdf':
                return self._generate_pdf_report(data, config)
            elif config.format.lower() == 'html':
                return self._generate_html_report(data, config)
            elif config.format.lower() == 'csv':
                return self._generate_csv_report(data, config)
            elif config.format.lower() == 'json':
                return self._generate_json_report(data, config)
            else:
                raise ValueError(f"Unsupported format: {config.format}")
                
        except Exception as e:
            raise Exception(f"Failed to generate report: {e}")
    
    def _collect_report_data(self, config: ReportConfig) -> Dict[str, Any]:
        """Collect data for report generation"""
        conn = sqlite3.connect(self.db_path)
        
        data = {
            'config': config,
            'generated_at': datetime.now().isoformat(),
            'summary': {},
            'logs': [],
            'alerts': [],
            'statistics': {},
            'charts_data': {}
        }
        
        try:
            # Summary statistics
            data['summary'] = self._get_summary_stats(conn, config)
            
            # Detailed logs if requested
            if config.include_details:
                data['logs'] = self._get_filtered_logs(conn, config)
                data['alerts'] = self._get_filtered_alerts(conn, config)
            
            # Statistical analysis
            data['statistics'] = self._get_detailed_statistics(conn, config)
            
            # Chart data
            if config.include_charts:
                data['charts_data'] = self._get_chart_data(conn, config)
                
        finally:
            conn.close()
        
        return data
    
    def _get_summary_stats(self, conn: sqlite3.Connection, config: ReportConfig) -> Dict[str, Any]:
        """Get summary statistics for the report period"""
        cursor = conn.cursor()
        
        # Time range filter
        time_filter = "timestamp BETWEEN ? AND ?"
        time_params = [config.start_date, config.end_date]
        
        summary = {}
        
        # Total logs by level
        cursor.execute(f'''
            SELECT level, COUNT(*) FROM logs 
            WHERE {time_filter}
            GROUP BY level
        ''', time_params)
        summary['logs_by_level'] = dict(cursor.fetchall())
        
        # Total alerts by severity
        cursor.execute(f'''
            SELECT severity, COUNT(*) FROM alerts 
            WHERE {time_filter}
            GROUP BY severity
        ''', time_params)
        summary['alerts_by_severity'] = dict(cursor.fetchall())
        
        # Threat types
        cursor.execute(f'''
            SELECT threat_type, COUNT(*) FROM alerts 
            WHERE {time_filter} AND threat_type IS NOT NULL
            GROUP BY threat_type
            ORDER BY COUNT(*) DESC
        ''', time_params)
        summary['threat_types'] = dict(cursor.fetchall())
        
        # Top source IPs
        cursor.execute(f'''
            SELECT source_ip, COUNT(*) as count FROM alerts 
            WHERE {time_filter} AND source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
        ''', time_params)
        summary['top_source_ips'] = dict(cursor.fetchall())
        
        # Top destination IPs
        cursor.execute(f'''
            SELECT destination_ip, COUNT(*) as count FROM alerts 
            WHERE {time_filter} AND destination_ip IS NOT NULL
            GROUP BY destination_ip
            ORDER BY count DESC
            LIMIT 10
        ''', time_params)
        summary['top_destination_ips'] = dict(cursor.fetchall())
        
        # Daily activity
        cursor.execute(f'''
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM alerts 
            WHERE {time_filter}
            GROUP BY DATE(timestamp)
            ORDER BY date
        ''', time_params)
        summary['daily_activity'] = dict(cursor.fetchall())
        
        # System components activity
        cursor.execute(f'''
            SELECT component, COUNT(*) FROM logs 
            WHERE {time_filter}
            GROUP BY component
            ORDER BY COUNT(*) DESC
        ''', time_params)
        summary['component_activity'] = dict(cursor.fetchall())
        
        return summary
    
    def _get_filtered_logs(self, conn: sqlite3.Connection, config: ReportConfig) -> List[Dict]:
        """Get filtered log entries"""
        cursor = conn.cursor()
        
        query = '''
            SELECT timestamp, level, component, message, source_ip, 
                   destination_ip, threat_type, action_taken, metadata
            FROM logs 
            WHERE timestamp BETWEEN ? AND ?
        '''
        params = [config.start_date, config.end_date]
        
        if config.severity_filter:
            query += " AND level IN ({})".format(','.join(['?'] * len(config.severity_filter)))
            params.extend(config.severity_filter)
        
        if config.component_filter:
            query += " AND component IN ({})".format(','.join(['?'] * len(config.component_filter)))
            params.extend(config.component_filter)
        
        query += " ORDER BY timestamp DESC LIMIT 1000"
        
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def _get_filtered_alerts(self, conn: sqlite3.Connection, config: ReportConfig) -> List[Dict]:
        """Get filtered alert entries"""
        cursor = conn.cursor()
        
        query = '''
            SELECT id, timestamp, severity, title, description, source_ip,
                   destination_ip, threat_type, rule_id, action_taken, status, metadata
            FROM alerts 
            WHERE timestamp BETWEEN ? AND ?
        '''
        params = [config.start_date, config.end_date]
        
        if config.severity_filter:
            query += " AND severity IN ({})".format(','.join(['?'] * len(config.severity_filter)))
            params.extend(config.severity_filter)
        
        query += " ORDER BY timestamp DESC"
        
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def _get_detailed_statistics(self, conn: sqlite3.Connection, config: ReportConfig) -> Dict[str, Any]:
        """Get detailed statistical analysis"""
        cursor = conn.cursor()
        
        stats = {}
        
        # Time-based analysis
        cursor.execute('''
            SELECT 
                strftime('%H', timestamp) as hour,
                COUNT(*) as count
            FROM alerts 
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY strftime('%H', timestamp)
            ORDER BY hour
        ''', [config.start_date, config.end_date])
        stats['hourly_distribution'] = dict(cursor.fetchall())
        
        # Response time analysis (if available in metadata)
        cursor.execute('''
            SELECT AVG(CAST(json_extract(metadata, '$.response_time') AS REAL)) as avg_response_time,
                   MIN(CAST(json_extract(metadata, '$.response_time') AS REAL)) as min_response_time,
                   MAX(CAST(json_extract(metadata, '$.response_time') AS REAL)) as max_response_time
            FROM logs 
            WHERE timestamp BETWEEN ? AND ? 
            AND json_extract(metadata, '$.response_time') IS NOT NULL
        ''', [config.start_date, config.end_date])
        response_stats = cursor.fetchone()
        if response_stats and response_stats[0]:
            stats['response_time'] = {
                'average': response_stats[0],
                'minimum': response_stats[1],
                'maximum': response_stats[2]
            }
        
        # False positive analysis
        cursor.execute('''
            SELECT COUNT(*) FROM alerts 
            WHERE timestamp BETWEEN ? AND ? 
            AND (status = 'false_positive' OR json_extract(metadata, '$.false_positive') = 'true')
        ''', [config.start_date, config.end_date])
        stats['false_positives'] = cursor.fetchone()[0]
        
        # Resolution time analysis
        cursor.execute('''
            SELECT AVG(julianday(updated_at) - julianday(timestamp)) * 24 * 60 as avg_resolution_minutes
            FROM alerts 
            WHERE timestamp BETWEEN ? AND ? 
            AND status = 'resolved'
            AND updated_at IS NOT NULL
        ''', [config.start_date, config.end_date])
        resolution_time = cursor.fetchone()[0]
        if resolution_time:
            stats['avg_resolution_time_minutes'] = resolution_time
        
        return stats
    
    def _get_chart_data(self, conn: sqlite3.Connection, config: ReportConfig) -> Dict[str, Any]:
        """Prepare data for chart generation"""
        cursor = conn.cursor()
        
        charts = {}
        
        # Daily threat activity
        cursor.execute('''
            SELECT DATE(timestamp) as date, 
                   COUNT(*) as total_alerts,
                   SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                   SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                   SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                   SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low
            FROM alerts 
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY DATE(timestamp)
            ORDER BY date
        ''', [config.start_date, config.end_date])
        
        daily_data = cursor.fetchall()
        if daily_data:
            charts['daily_activity'] = {
                'dates': [row[0] for row in daily_data],
                'total': [row[1] for row in daily_data],
                'critical': [row[2] for row in daily_data],
                'high': [row[3] for row in daily_data],
                'medium': [row[4] for row in daily_data],
                'low': [row[5] for row in daily_data]
            }
        
        # Threat type distribution
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count
            FROM alerts 
            WHERE timestamp BETWEEN ? AND ? AND threat_type IS NOT NULL
            GROUP BY threat_type
            ORDER BY count DESC
        ''', [config.start_date, config.end_date])
        
        threat_data = cursor.fetchall()
        if threat_data:
            charts['threat_distribution'] = {
                'labels': [row[0] for row in threat_data],
                'values': [row[1] for row in threat_data]
            }
        
        return charts
    
    def _generate_pdf_report(self, data: Dict[str, Any], config: ReportConfig) -> str:
        """Generate PDF report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ids_ips_report_{config.report_type}_{timestamp}.pdf"
        filepath = self.output_dir / filename
        
        doc = SimpleDocTemplate(str(filepath), pagesize=A4)
        story = []
        
        # Title
        title = f"IDS/IPS Security Report - {config.report_type.title()}"
        story.append(Paragraph(title, self.title_style))
        story.append(Spacer(1, 20))
        
        # Report metadata
        metadata_data = [
            ['Report Type', config.report_type.title()],
            ['Period', f"{config.start_date} to {config.end_date}"],
            ['Generated', data['generated_at']],
            ['Format', config.format.upper()]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(metadata_table)
        story.append(Spacer(1, 30))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.heading_style))
        
        summary = data['summary']
        total_alerts = sum(summary.get('alerts_by_severity', {}).values())
        total_logs = sum(summary.get('logs_by_level', {}).values())
        
        summary_text = f"""
        During the reporting period from {config.start_date} to {config.end_date}, 
        the IDS/IPS system processed {total_logs:,} log entries and generated {total_alerts:,} security alerts.
        """
        
        if summary.get('threat_types'):
            top_threat = max(summary['threat_types'].items(), key=lambda x: x[1])
            summary_text += f" The most common threat type was {top_threat[0]} with {top_threat[1]} incidents."
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Statistics Tables
        if summary.get('alerts_by_severity'):
            story.append(Paragraph("Alerts by Severity", self.heading_style))
            
            severity_data = [['Severity', 'Count', 'Percentage']]
            for severity, count in summary['alerts_by_severity'].items():
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                severity_data.append([severity, str(count), f"{percentage:.1f}%"])
            
            severity_table = Table(severity_data, colWidths=[2*inch, 1*inch, 1*inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(severity_table)
            story.append(Spacer(1, 20))
        
        # Top Threats
        if summary.get('threat_types'):
            story.append(Paragraph("Top Threat Types", self.heading_style))
            
            threat_data = [['Threat Type', 'Count']]
            for threat_type, count in list(summary['threat_types'].items())[:10]:
                threat_data.append([threat_type, str(count)])
            
            threat_table = Table(threat_data, colWidths=[3*inch, 1*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(threat_table)
            story.append(Spacer(1, 20))
        
        # Generate charts if requested
        if config.include_charts and data.get('charts_data'):
            chart_files = self._generate_charts(data['charts_data'], config)
            
            for chart_file in chart_files:
                if chart_file.exists():
                    story.append(Paragraph(f"Chart: {chart_file.stem.replace('_', ' ').title()}", self.heading_style))
                    img = Image(str(chart_file), width=6*inch, height=4*inch)
                    story.append(img)
                    story.append(Spacer(1, 20))
        
        # Detailed alerts if requested
        if config.include_details and data.get('alerts'):
            story.append(Paragraph("Recent Alerts", self.heading_style))
            
            alert_data = [['Timestamp', 'Severity', 'Title', 'Source IP']]
            for alert in data['alerts'][:20]:  # Limit to 20 most recent
                alert_data.append([
                    alert['timestamp'][:19],  # Remove microseconds
                    alert['severity'],
                    alert['title'][:50] + ('...' if len(alert['title']) > 50 else ''),
                    alert['source_ip'] or 'N/A'
                ])
            
            alert_table = Table(alert_data, colWidths=[2*inch, 1*inch, 2.5*inch, 1.5*inch])
            alert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(alert_table)
        
        # Build PDF
        doc.build(story)
        
        return str(filepath)
    
    def _generate_charts(self, charts_data: Dict[str, Any], config: ReportConfig) -> List[Path]:
        """Generate chart images for reports"""
        chart_files = []
        
        # Daily activity chart
        if 'daily_activity' in charts_data:
            fig, ax = plt.subplots(figsize=(12, 6))
            
            data = charts_data['daily_activity']
            dates = pd.to_datetime(data['dates'])
            
            ax.plot(dates, data['total'], label='Total Alerts', linewidth=2, marker='o')
            ax.plot(dates, data['critical'], label='Critical', linewidth=2, marker='s')
            ax.plot(dates, data['high'], label='High', linewidth=2, marker='^')
            
            ax.set_title('Daily Alert Activity', fontsize=16, fontweight='bold')
            ax.set_xlabel('Date', fontsize=12)
            ax.set_ylabel('Number of Alerts', fontsize=12)
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            # Format x-axis
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            ax.xaxis.set_major_locator(mdates.DayLocator(interval=1))
            plt.xticks(rotation=45)
            
            plt.tight_layout()
            
            chart_file = self.output_dir / f"daily_activity_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(chart_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            chart_files.append(chart_file)
        
        # Threat distribution pie chart
        if 'threat_distribution' in charts_data:
            fig, ax = plt.subplots(figsize=(10, 8))
            
            data = charts_data['threat_distribution']
            labels = data['labels'][:8]  # Top 8 threats
            values = data['values'][:8]
            
            # Add "Others" category if there are more threats
            if len(data['labels']) > 8:
                others_count = sum(data['values'][8:])
                labels.append('Others')
                values.append(others_count)
            
            colors_list = plt.cm.Set3(np.linspace(0, 1, len(labels)))
            
            wedges, texts, autotexts = ax.pie(values, labels=labels, autopct='%1.1f%%', 
                                            colors=colors_list, startangle=90)
            
            ax.set_title('Threat Type Distribution', fontsize=16, fontweight='bold')
            
            # Improve text readability
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
            
            plt.tight_layout()
            
            chart_file = self.output_dir / f"threat_distribution_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(chart_file, dpi=300, bbox_inches='tight')
            plt.close()
            
            chart_files.append(chart_file)
        
        return chart_files
    
    def _generate_html_report(self, data: Dict[str, Any], config: ReportConfig) -> str:
        """Generate HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ids_ips_report_{config.report_type}_{timestamp}.html"
        filepath = self.output_dir / filename
        
        html_content = self._build_html_content(data, config)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(filepath)
    
    def _build_html_content(self, data: Dict[str, Any], config: ReportConfig) -> str:
        """Build HTML content for the report"""
        summary = data['summary']
        total_alerts = sum(summary.get('alerts_by_severity', {}).values())
        total_logs = sum(summary.get('logs_by_level', {}).values())
        
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>IDS/IPS Security Report - {config.report_type.title()}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background: #ecf0f1; padding: 20px; margin: 20px 0; border-radius: 5px; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
                .stat-card {{ background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .stat-number {{ font-size: 2em; font-weight: bold; color: #3498db; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #34495e; color: white; }}
                .severity-critical {{ color: #e74c3c; font-weight: bold; }}
                .severity-high {{ color: #f39c12; font-weight: bold; }}
                .severity-medium {{ color: #f1c40f; font-weight: bold; }}
                .severity-low {{ color: #27ae60; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>IDS/IPS Security Report</h1>
                <p>Report Type: {config.report_type.title()}</p>
                <p>Period: {config.start_date} to {config.end_date}</p>
                <p>Generated: {data['generated_at']}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>During the reporting period, the IDS/IPS system processed <strong>{total_logs:,}</strong> log entries 
                and generated <strong>{total_alerts:,}</strong> security alerts.</p>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Total Alerts</h3>
                    <div class="stat-number">{total_alerts:,}</div>
                </div>
                <div class="stat-card">
                    <h3>Total Logs</h3>
                    <div class="stat-number">{total_logs:,}</div>
                </div>
        """
        
        # Add severity breakdown
        if summary.get('alerts_by_severity'):
            for severity, count in summary['alerts_by_severity'].items():
                html += f"""
                <div class="stat-card">
                    <h3>{severity.title()} Alerts</h3>
                    <div class="stat-number severity-{severity.lower()}">{count:,}</div>
                </div>
                """
        
        html += "</div>"
        
        # Alerts by severity table
        if summary.get('alerts_by_severity'):
            html += """
            <h2>Alerts by Severity</h2>
            <table>
                <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
            """
            
            for severity, count in summary['alerts_by_severity'].items():
                percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
                html += f"""
                <tr>
                    <td class="severity-{severity.lower()}">{severity}</td>
                    <td>{count:,}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
                """
            
            html += "</table>"
        
        # Top threat types
        if summary.get('threat_types'):
            html += """
            <h2>Top Threat Types</h2>
            <table>
                <tr><th>Threat Type</th><th>Count</th></tr>
            """
            
            for threat_type, count in list(summary['threat_types'].items())[:10]:
                html += f"<tr><td>{threat_type}</td><td>{count:,}</td></tr>"
            
            html += "</table>"
        
        # Recent alerts if included
        if config.include_details and data.get('alerts'):
            html += """
            <h2>Recent Alerts</h2>
            <table>
                <tr><th>Timestamp</th><th>Severity</th><th>Title</th><th>Source IP</th></tr>
            """
            
            for alert in data['alerts'][:50]:  # Limit to 50 most recent
                html += f"""
                <tr>
                    <td>{alert['timestamp'][:19]}</td>
                    <td class="severity-{alert['severity'].lower()}">{alert['severity']}</td>
                    <td>{alert['title']}</td>
                    <td>{alert['source_ip'] or 'N/A'}</td>
                </tr>
                """
            
            html += "</table>"
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def _generate_csv_report(self, data: Dict[str, Any], config: ReportConfig) -> str:
        """Generate CSV report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ids_ips_report_{config.report_type}_{timestamp}.csv"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write metadata
            writer.writerow(['IDS/IPS Security Report'])
            writer.writerow(['Report Type', config.report_type.title()])
            writer.writerow(['Period', f"{config.start_date} to {config.end_date}"])
            writer.writerow(['Generated', data['generated_at']])
            writer.writerow([])  # Empty row
            
            # Write alerts if available
            if data.get('alerts'):
                writer.writerow(['ALERTS'])
                writer.writerow(['ID', 'Timestamp', 'Severity', 'Title', 'Description', 
                               'Source IP', 'Destination IP', 'Threat Type', 'Rule ID', 
                               'Action Taken', 'Status'])
                
                for alert in data['alerts']:
                    writer.writerow([
                        alert['id'],
                        alert['timestamp'],
                        alert['severity'],
                        alert['title'],
                        alert['description'],
                        alert['source_ip'] or '',
                        alert['destination_ip'] or '',
                        alert['threat_type'] or '',
                        alert['rule_id'] or '',
                        alert['action_taken'] or '',
                        alert['status']
                    ])
                
                writer.writerow([])  # Empty row
            
            # Write logs if available
            if data.get('logs'):
                writer.writerow(['LOGS'])
                writer.writerow(['Timestamp', 'Level', 'Component', 'Message', 
                               'Source IP', 'Destination IP', 'Threat Type', 'Action Taken'])
                
                for log in data['logs']:
                    writer.writerow([
                        log['timestamp'],
                        log['level'],
                        log['component'],
                        log['message'],
                        log['source_ip'] or '',
                        log['destination_ip'] or '',
                        log['threat_type'] or '',
                        log['action_taken'] or ''
                    ])
        
        return str(filepath)
    
    def _generate_json_report(self, data: Dict[str, Any], config: ReportConfig) -> str:
        """Generate JSON report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ids_ips_report_{config.report_type}_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as jsonfile:
            json.dump(data, jsonfile, indent=2, default=str)
        
        return str(filepath)
    
    def generate_scheduled_reports(self, schedule_config: Dict[str, Any]):
        """Generate reports based on schedule configuration"""
        # This would be called by a scheduler (cron, celery, etc.)
        for report_config in schedule_config.get('reports', []):
            try:
                # Calculate date range based on schedule
                end_date = datetime.now()
                
                if report_config['frequency'] == 'daily':
                    start_date = end_date - timedelta(days=1)
                elif report_config['frequency'] == 'weekly':
                    start_date = end_date - timedelta(weeks=1)
                elif report_config['frequency'] == 'monthly':
                    start_date = end_date - timedelta(days=30)
                else:
                    continue
                
                config = ReportConfig(
                    report_type=report_config['type'],
                    start_date=start_date.isoformat(),
                    end_date=end_date.isoformat(),
                    format=report_config['format'],
                    include_charts=report_config.get('include_charts', True),
                    include_details=report_config.get('include_details', True)
                )
                
                report_path = self.generate_report(config)
                print(f"Generated scheduled report: {report_path}")
                
            except Exception as e:
                print(f"Failed to generate scheduled report: {e}")

# Example usage
if __name__ == "__main__":
    # Initialize report generator
    generator = ReportGenerator("/var/log/ids_ips/ids_logs.db")
    
    # Generate a comprehensive security report
    config = ReportConfig(
        report_type="security_overview",
        start_date=(datetime.now() - timedelta(days=7)).isoformat(),
        end_date=datetime.now().isoformat(),
        format="pdf",
        include_charts=True,
        include_details=True
    )
    
    try:
        report_path = generator.generate_report(config)
        print(f"Report generated: {report_path}")
    except Exception as e:
        print(f"Failed to generate report: {e}")

