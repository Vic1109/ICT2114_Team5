import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import pandas as pd
from datetime import datetime

class SOCChartGenerator:
    """Generate charts for SOC threat analysis reports"""
    
    def __init__(self, charts_dir: str = None):
        self.charts_dir = Path(charts_dir) if charts_dir else Path("charts")
        self.charts_dir.mkdir(exist_ok=True)
        
        # Set up matplotlib for clean charts
        plt.style.use('default')
        plt.rcParams.update({
            'figure.figsize': (10, 8),
            'font.size': 10,
            'axes.titlesize': 14,
            'axes.labelsize': 12,
            'xtick.labelsize': 10,
            'ytick.labelsize': 10,
            'legend.fontsize': 10,
            'figure.dpi': 100,
            'savefig.dpi': 150,
            'savefig.bbox': 'tight',
            'figure.facecolor': 'white'
        })
    
    def generate_ip_analysis_charts(self, alerts: List[Dict], 
                                  chart_prefix: str = "ip_analysis") -> List[str]:
        """Generate comprehensive IP analysis charts and return image paths"""
        chart_paths = []
        
        try:
            # Extract IP data
            ip_data = self._extract_ip_data(alerts)
            
            if not ip_data['external_sources'] and not ip_data['geolocation']:
                print("⚠️ No external IP data found for charting")
                return chart_paths
            
            # 1. External Source IPs Pie Chart
            if ip_data['external_sources']:
                path = self._create_external_sources_pie(ip_data['external_sources'], chart_prefix)
                if path:
                    chart_paths.append(path)
            
            # 2. Geographic Distribution Pie Chart
            if ip_data['geolocation']:
                path = self._create_geolocation_pie(ip_data['geolocation'], chart_prefix)
                if path:
                    chart_paths.append(path)
            
            # 3. Threat Direction Distribution
            if ip_data['threat_directions']:
                path = self._create_threat_direction_pie(ip_data['threat_directions'], chart_prefix)
                if path:
                    chart_paths.append(path)
            
            # 4. Protocol Distribution (bonus chart)
            if ip_data['protocols']:
                path = self._create_protocol_pie(ip_data['protocols'], chart_prefix)
                if path:
                    chart_paths.append(path)
            
            print(f"✅ Generated {len(chart_paths)} IP analysis charts")
            return chart_paths
            
        except Exception as e:
            print(f"❌ Chart generation error: {e}")
            return chart_paths
    
    def _extract_ip_data(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Extract and categorize IP data from alerts"""
        ip_data = {
            'external_sources': Counter(),
            'internal_sources': Counter(),
            'geolocation': Counter(),
            'threat_directions': Counter(),
            'protocols': Counter(),
            'severity_by_country': {},
            'infrastructure_ips': set()
        }
        
        for alert in alerts:
            # Skip infrastructure alerts
            threat_class = alert.get('threat_classification', {})
            if threat_class.get('is_infrastructure_alert'):
                continue
            
            # Source IP analysis
            src_ip = alert.get('src_ip')
            src_context = alert.get('src_ip_context', 'unknown')
            
            if src_ip and src_context == 'external':
                ip_data['external_sources'][src_ip] += 1
            elif src_ip and src_context in ('internal', 'owned'):
                ip_data['internal_sources'][src_ip] += 1
            
            # Geolocation analysis
            geo = alert.get('geolocation', {})
            severity = alert.get('rule_level', 0)
            
            if geo.get('src', {}).get('country'):
                country = geo['src']['country']
                ip_data['geolocation'][country] += 1
                
                # Track severity by country
                if country not in ip_data['severity_by_country']:
                    ip_data['severity_by_country'][country] = {'total': 0, 'high_severity': 0}
                ip_data['severity_by_country'][country]['total'] += 1
                if severity >= 8:
                    ip_data['severity_by_country'][country]['high_severity'] += 1
            
            # Threat direction analysis
            direction = threat_class.get('threat_direction', 'unknown')
            if direction != 'unknown':
                ip_data['threat_directions'][direction] += 1
            
            # Protocol analysis
            protocol = alert.get('proto')
            if protocol:
                ip_data['protocols'][protocol.upper()] += 1
        
        return ip_data
    
    def _create_external_sources_pie(self, external_sources: Counter, 
                                   prefix: str) -> Optional[str]:
        """Create pie chart for top external source IPs"""
        if not external_sources:
            return None
        
        try:
            # Get top 10 sources
            top_sources = external_sources.most_common(10)
            others_count = sum(external_sources.values()) - sum(count for _, count in top_sources)
            
            # Prepare data
            labels = []
            sizes = []
            colors = []
            
            # Color palette for pie chart
            base_colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', 
                          '#DDA0DD', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E9']
            
            for i, (ip, count) in enumerate(top_sources):
                labels.append(f"{ip}\n({count} alerts)")
                sizes.append(count)
                colors.append(base_colors[i % len(base_colors)])
            
            if others_count > 0:
                labels.append(f"Others\n({others_count} alerts)")
                sizes.append(others_count)
                colors.append('#CCCCCC')
            
            # Create figure
            fig, ax = plt.subplots(figsize=(12, 8))
            
            # Create pie chart
            wedges, texts, autotexts = ax.pie(
                sizes, 
                labels=labels, 
                colors=colors,
                autopct='%1.1f%%',
                startangle=90,
                textprops={'fontsize': 9}
            )
            
            # Enhance appearance
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_weight('bold')
            
            ax.set_title('Top External Source IP Addresses\n(Threat Sources)', 
                        fontsize=16, fontweight='bold', pad=20)
            
            # Add summary text
            total_external = sum(external_sources.values())
            unique_ips = len(external_sources)
            
            plt.figtext(0.02, 0.02, 
                       f"Total External Alerts: {total_external} | Unique External IPs: {unique_ips}",
                       fontsize=10, style='italic')
            
            # Save chart
            chart_path = self.charts_dir / f"{prefix}_external_sources.png"
            plt.savefig(chart_path, bbox_inches='tight', facecolor='white')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            print(f"❌ Error creating external sources pie chart: {e}")
            plt.close()
            return None
    
    def _create_geolocation_pie(self, geolocation: Counter, 
                              prefix: str) -> Optional[str]:
        """Create pie chart for geographic distribution"""
        if not geolocation:
            return None
        
        try:
            # Get top countries
            top_countries = geolocation.most_common(8)
            others_count = sum(geolocation.values()) - sum(count for _, count in top_countries)
            
            # Prepare data
            labels = []
            sizes = []
            colors = []
            
            # Color palette for countries
            country_colors = ['#E74C3C', '#3498DB', '#2ECC71', '#F39C12', 
                            '#9B59B6', '#1ABC9C', '#34495E', '#E67E22']
            
            for i, (country, count) in enumerate(top_countries):
                labels.append(f"{country}\n({count} alerts)")
                sizes.append(count)
                colors.append(country_colors[i % len(country_colors)])
            
            if others_count > 0:
                labels.append(f"Others\n({others_count} alerts)")
                sizes.append(others_count)
                colors.append('#95A5A6')
            
            # Create figure
            fig, ax = plt.subplots(figsize=(12, 8))
            
            # Create pie chart
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct='%1.1f%%',
                startangle=90,
                textprops={'fontsize': 10}
            )
            
            # Enhance appearance
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_weight('bold')
            
            ax.set_title('Geographic Distribution of Threat Sources\n(Country-based)', 
                        fontsize=16, fontweight='bold', pad=20)
            
            # Add summary
            total_geo = sum(geolocation.values())
            unique_countries = len(geolocation)
            
            plt.figtext(0.02, 0.02, 
                       f"Total Geolocated Alerts: {total_geo} | Countries: {unique_countries}",
                       fontsize=10, style='italic')
            
            # Save chart
            chart_path = self.charts_dir / f"{prefix}_geolocation.png"
            plt.savefig(chart_path, bbox_inches='tight', facecolor='white')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            print(f"❌ Error creating geolocation pie chart: {e}")
            plt.close()
            return None
    
    def _create_threat_direction_pie(self, threat_directions: Counter,
                                   prefix: str) -> Optional[str]:
        """Create pie chart for threat directions"""
        if not threat_directions:
            return None
        
        try:
            # Direction labels and colors
            direction_map = {
                'inbound': ('Inbound Threats\n(External → Internal)', '#E74C3C'),
                'outbound': ('Outbound Threats\n(Internal → External)', '#F39C12'),
                'lateral': ('Lateral Movement\n(Internal → Internal)', '#9B59B6'),
                'external': ('External Traffic\n(External → External)', '#3498DB')
            }
            
            labels = []
            sizes = []
            colors = []
            
            for direction, count in threat_directions.items():
                if direction in direction_map:
                    label, color = direction_map[direction]
                    labels.append(f"{label}\n({count} alerts)")
                    sizes.append(count)
                    colors.append(color)
            
            if not sizes:
                return None
            
            # Create figure
            fig, ax = plt.subplots(figsize=(10, 8))
            
            # Create pie chart
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct='%1.1f%%',
                startangle=90,
                textprops={'fontsize': 10}
            )
            
            # Enhance appearance
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_weight('bold')
            
            ax.set_title('Threat Direction Analysis\n(Network Traffic Patterns)', 
                        fontsize=16, fontweight='bold', pad=20)
            
            # Add summary
            total_directional = sum(threat_directions.values())
            plt.figtext(0.02, 0.02, 
                       f"Total Directional Threats: {total_directional}",
                       fontsize=10, style='italic')
            
            # Save chart
            chart_path = self.charts_dir / f"{prefix}_threat_directions.png"
            plt.savefig(chart_path, bbox_inches='tight', facecolor='white')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            print(f"❌ Error creating threat direction pie chart: {e}")
            plt.close()
            return None
    
    def _create_protocol_pie(self, protocols: Counter, prefix: str) -> Optional[str]:
        """Create pie chart for protocol distribution"""
        if not protocols:
            return None
        
        try:
            # Get top protocols
            top_protocols = protocols.most_common(6)
            others_count = sum(protocols.values()) - sum(count for _, count in top_protocols)
            
            labels = []
            sizes = []
            colors = []
            
            # Protocol-specific colors
            protocol_colors = {
                'TCP': '#2ECC71',
                'UDP': '#3498DB', 
                'HTTP': '#E67E22',
                'HTTPS': '#27AE60',
                'DNS': '#8E44AD',
                'ICMP': '#E74C3C'
            }
            default_colors = ['#95A5A6', '#34495E', '#F39C12', '#1ABC9C']
            
            for i, (protocol, count) in enumerate(top_protocols):
                labels.append(f"{protocol}\n({count} alerts)")
                sizes.append(count)
                color = protocol_colors.get(protocol, default_colors[i % len(default_colors)])
                colors.append(color)
            
            if others_count > 0:
                labels.append(f"Others\n({others_count} alerts)")
                sizes.append(others_count)
                colors.append('#BDC3C7')
            
            # Create figure
            fig, ax = plt.subplots(figsize=(10, 8))
            
            # Create pie chart
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct='%1.1f%%',
                startangle=90,
                textprops={'fontsize': 10}
            )
            
            # Enhance appearance
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_weight('bold')
            
            ax.set_title('Protocol Distribution Analysis\n(Network Protocols)', 
                        fontsize=16, fontweight='bold', pad=20)
            
            # Add summary
            total_protocols = sum(protocols.values())
            plt.figtext(0.02, 0.02, 
                       f"Total Protocol Alerts: {total_protocols}",
                       fontsize=10, style='italic')
            
            # Save chart
            chart_path = self.charts_dir / f"{prefix}_protocols.png"
            plt.savefig(chart_path, bbox_inches='tight', facecolor='white')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            print(f"❌ Error creating protocol pie chart: {e}")
            plt.close()
            return None
    
    def generate_severity_timeline(self, alerts: List[Dict], 
                                 chart_prefix: str = "severity") -> Optional[str]:
        """Generate timeline chart showing alert severity over time"""
        try:
            if not alerts:
                return None
            
            # Extract timestamp and severity data
            timeline_data = []
            for alert in alerts:
                timestamp = alert.get('timestamp')
                level = alert.get('rule_level', 0)
                
                if timestamp and level:
                    try:
                        # Parse timestamp (adjust format as needed)
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timeline_data.append({'time': dt, 'severity': level})
                    except:
                        continue
            
            if not timeline_data:
                return None
            
            # Create timeline plot
            df = pd.DataFrame(timeline_data)
            
            fig, ax = plt.subplots(figsize=(12, 6))
            
            # Create scatter plot with color-coded severity
            colors = []
            for level in df['severity']:
                if level >= 12:
                    colors.append('#E74C3C')  # Critical - Red
                elif level >= 8:
                    colors.append('#F39C12')  # High - Orange
                elif level >= 5:
                    colors.append('#F1C40F')  # Medium - Yellow
                else:
                    colors.append('#2ECC71')  # Low - Green
            
            ax.scatter(df['time'], df['severity'], c=colors, alpha=0.7, s=50)
            
            ax.set_xlabel('Time')
            ax.set_ylabel('Alert Severity Level')
            ax.set_title('Alert Severity Timeline', fontsize=16, fontweight='bold')
            
            # Add severity level lines
            ax.axhline(y=12, color='red', linestyle='--', alpha=0.5, label='Critical (≥12)')
            ax.axhline(y=8, color='orange', linestyle='--', alpha=0.5, label='High (≥8)')
            ax.axhline(y=5, color='gold', linestyle='--', alpha=0.5, label='Medium (≥5)')
            
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            plt.xticks(rotation=45)
            
            # Save chart
            chart_path = self.charts_dir / f"{chart_prefix}_timeline.png"
            plt.savefig(chart_path, bbox_inches='tight', facecolor='white')
            plt.close()
            
            return str(chart_path)
            
        except Exception as e:
            print(f"❌ Error creating severity timeline: {e}")
            plt.close()
            return None
    
    def cleanup_old_charts(self, max_age_hours: int = 24) -> int:
        """Clean up old chart files"""
        if not self.charts_dir.exists():
            return 0
        
        import time
        cutoff_time = time.time() - (max_age_hours * 3600)
        deleted_count = 0
        
        for chart_file in self.charts_dir.glob("*.png"):
            try:
                if chart_file.stat().st_mtime < cutoff_time:
                    chart_file.unlink()
                    deleted_count += 1
            except Exception as e:
                print(f"⚠️ Error deleting old chart {chart_file}: {e}")
        
        return deleted_count
