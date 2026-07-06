import json
import gzip
import shlex
from datetime import datetime, timedelta
from typing import List, Dict
import paramiko


class SSHConnectionManager:
    """Manages SSH connections to remote servers"""
    
    def __init__(self, host: str, username: str, password: str, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.ssh = None
        self.sftp = None
        self._connected = False
    
    def connect(self) -> bool:
        """Establish SSH connection"""
        try:
            print(f"🔌 Connecting to {self.host}:{self.port} as {self.username}...")
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(
                self.host, 
                port=self.port, 
                username=self.username,
                password=self.password, 
                timeout=30
            )
            self.sftp = self.ssh.open_sftp()
            self._connected = True
            print(f"✅ Successfully connected to {self.host}")
            return True
        except Exception as e:
            print(f"❌ SSH connection failed: {e}")
            self._connected = False
            return False
    
    def disconnect(self):
        """Close SSH connection"""
        try:
            if self.sftp:
                self.sftp.close()
                self.sftp = None
            if self.ssh:
                self.ssh.close()
                self.ssh = None
            self._connected = False
            print("🔌 SSH connection closed")
        except Exception as e:
            print(f"⚠️ Error during disconnect: {e}")
    
    @property
    def is_connected(self) -> bool:
        """Check if connection is active"""
        return self._connected and self.sftp is not None


class AlertsReader:
    """Reads current alerts from Wazuh alerts.json file"""
    
    def __init__(self, connection_manager: SSHConnectionManager, alerts_path: str):
        self.connection_manager = connection_manager
        self.alerts_path = alerts_path
    
    def read_alerts(self, max_lines: int = None) -> List[Dict]:
        """Read current alerts from alerts.json
        
        Args:
            max_lines: If specified, only read the last N lines for performance
        """
        if not self.connection_manager.is_connected:
            print("❌ SSH connection not available for alerts reading")
            return []
        
        alerts = []
        
        try:
            # Check if alerts file exists
            try:
                file_stat = self.connection_manager.sftp.stat(self.alerts_path)
                print(f"📁 Found alerts file: {self.alerts_path} ({file_stat.st_size} bytes)")
            except IOError:
                print(f"❌ Alerts file not found: {self.alerts_path}")
                return alerts
            
            # Use tail for performance if max_lines specified
            if max_lines and max_lines > 0:
                stdin, stdout, stderr = self.connection_manager.ssh.exec_command(
                    f"tail -n {int(max_lines)} {shlex.quote(self.alerts_path)}"
                )
                lines = stdout.readlines()
                
                for idx, line in enumerate(lines, 1):
                    line = line.strip()
                    if line:
                        try:
                            alert = json.loads(line)
                            alerts.append(alert)
                        except json.JSONDecodeError as e:
                            print(f"⚠️ JSON decode error at line {idx}: {e}")
            else:
                # Read entire file (slower for large files)
                with self.connection_manager.sftp.open(self.alerts_path, 'r') as f:
                    line_count = 0
                    for line in f:
                        line_count += 1
                        line = line.strip()
                        if line:
                            try:
                                alert = json.loads(line)
                                alerts.append(alert)
                            except json.JSONDecodeError as e:
                                print(f"⚠️ JSON decode error at line {line_count}: {e}")
                
                print(f"📊 Processed {line_count} lines, found {len(alerts)} alerts")
                            
        except Exception as e:
            print(f"❌ Error reading alerts file: {e}")
            
        return alerts


class ArchiveReader:
    """Reads historical archive logs from Wazuh"""
    
    def __init__(self, connection_manager: SSHConnectionManager, archives_base_path: str):
        self.connection_manager = connection_manager
        self.archives_base = archives_base_path
    
    def get_smart_archive_dates(self, past_days: int) -> List[datetime]:
        """Generate smart date list that handles month/year boundaries"""
        dates = []
        current = datetime.now()
        
        for i in range(1, past_days + 1):
            target_date = current - timedelta(days=i)
            dates.append(target_date)
            
        return dates
    
    def read_archives_smart(self, past_days: int = 7) -> int:
        """Read archive logs with smart date boundary handling"""
        if not self.connection_manager.is_connected:
            print("❌ SSH connection not available for archive reading")
            return 0
        
        total_logs = 0
        dates = self.get_smart_archive_dates(past_days)
        
        print(f"📅 Looking for archives across {len(dates)} days:")
        for date in dates[:3]:  # Show first 3 dates as example
            print(f"   {date.strftime('%Y-%m-%d (%b)')}")
        if len(dates) > 3:
            print(f"   ... and {len(dates)-3} more dates")

        for day in dates:
            year = day.year
            month_name = day.strftime("%b")
            day_num = day.strftime("%d")
            base_path = f"{self.archives_base}/{year}/{month_name}"
            json_path = f"{base_path}/ossec-archive-{day_num}.json"
            gz_path = f"{base_path}/ossec-archive-{day_num}.json.gz"
            
            print(f"🔍 Attempting to stat: {json_path}")
            
            try:
                # Try JSON file first
                day_logs = self._read_json_archive(json_path, day)
                if day_logs > 0:
                    total_logs += day_logs
                    continue
                
                # Try compressed file if JSON not found
                day_logs = self._read_gz_archive(gz_path, day)
                total_logs += day_logs
                if day_logs == 0:
                    print(f"⚠️ {day.strftime('%Y-%m-%d')}: No archives found")
                    
            except Exception as e:
                print(f"⚠️ Error reading archive for {day.strftime('%Y-%m-%d')}: {e}")
                continue
                
        print(f"📊 Total loaded: {total_logs} archive entries from {past_days} days")
        return total_logs
    
    def _read_json_archive(self, json_path: str, day: datetime) -> int:
        """Read uncompressed JSON archive file"""
        day_logs = 0
        
        try:
            if self.connection_manager.sftp.stat(json_path).st_size > 0:
                with self.connection_manager.sftp.open(json_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                log = json.loads(line)
                                if isinstance(log, dict):
                                    log["_archive_source"] = json_path
                                self._append_log(log)
                                day_logs += 1
                            except json.JSONDecodeError:
                                continue
                print(f"✅ {day.strftime('%Y-%m-%d')}: {day_logs} logs from JSON")
        except IOError:
            pass  # File doesn't exist, that's ok
        
        return day_logs
    
    def _read_gz_archive(self, gz_path: str, day: datetime) -> int:
        """Read compressed archive file"""
        day_logs = 0
        
        try:
            if self.connection_manager.sftp.stat(gz_path).st_size > 0:
                with self.connection_manager.sftp.open(gz_path, 'rb') as f:
                    with gzip.GzipFile(fileobj=f) as gz_f:
                        for line in gz_f:
                            line = line.decode('utf-8', errors='ignore').strip()
                            if line:
                                try:
                                    log = json.loads(line)
                                    if isinstance(log, dict):
                                        log["_archive_source"] = gz_path
                                    self._append_log(log)
                                    day_logs += 1
                                except json.JSONDecodeError:
                                    continue
                print(f"✅ {day.strftime('%Y-%m-%d')}: {day_logs} logs from GZ")
        except IOError:
            pass  # File doesn't exist, that's ok
        
        return day_logs
    
    def _append_log(self, log: Dict):
        """Append log to the logs list (to be overridden by parent class)"""
        # This will be handled by the parent SmartSSHLogReader class
        pass


class SmartSSHLogReader:
    """Orchestrator class that combines SSH connection management with data reading"""
    
    def __init__(self, host: str, username: str, password: str, port: int = 22, 
                 alerts_path: str = "/var/ossec/logs/alerts/alerts.json",
                 archives_base_path: str = "/var/ossec/logs/archives"):
        
        # Initialize connection manager
        self.connection_manager = SSHConnectionManager(host, username, password, port)
        
        # Initialize readers
        self.alerts_reader = AlertsReader(self.connection_manager, alerts_path)
        self.archive_reader = ArchiveReader(self.connection_manager, archives_base_path)
        
        # Storage for archive logs (used by archive reader)
        self._archive_logs = []
        
        # Override the archive reader's _append_log method to use our storage
        self.archive_reader._append_log = self._append_archive_log
    
    def _append_archive_log(self, log: Dict):
        """Append log to our internal storage"""
        self._archive_logs.append(log)
    
    def connect(self) -> bool:
        """Establish SSH connection"""
        return self.connection_manager.connect()
    
    def disconnect(self):
        """Close SSH connection"""
        self.connection_manager.disconnect()
    
    @property
    def is_connected(self) -> bool:
        """Check if connection is active"""
        return self.connection_manager.is_connected
    
    def read_alerts(self, max_lines: int = None) -> List[Dict]:
        """Read current alerts from alerts.json
        
        Args:
            max_lines: If specified, only read the last N lines for performance
        """
        return self.alerts_reader.read_alerts(max_lines=max_lines)
    
    def read_archives_smart(self, past_days: int = 7) -> List[Dict]:
        """Read archive logs with smart date boundary handling"""
        # Clear previous archive logs
        self._archive_logs = []
        
        # Read archives
        self.archive_reader.read_archives_smart(past_days)
        
        # Return collected logs
        return self._archive_logs.copy()
