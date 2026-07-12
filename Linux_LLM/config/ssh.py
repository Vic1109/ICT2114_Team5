import errno
import json
import gzip
import logging
import shlex
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional
import paramiko


LOGGER = logging.getLogger(__name__)


class ArchiveReadLimitError(ValueError):
    """Raised when historical archive input exceeds a configured safety bound."""


class ArchiveFormatError(ValueError):
    """Raised when an immutable historical archive contains an invalid record."""


class _ArchiveByteBudget:
    """Request-scoped decompressed-byte budget shared across archive days/files."""

    def __init__(self, maximum: int):
        self.maximum = max(1, int(maximum))
        self.consumed = 0

    @property
    def remaining(self) -> int:
        return max(0, self.maximum - self.consumed)

    def consume(self, byte_count: int) -> None:
        byte_count = max(0, int(byte_count))
        if byte_count > self.remaining:
            raise ArchiveReadLimitError(
                f"Archive input exceeds the decompressed-byte limit ({self.maximum} bytes)"
            )
        self.consumed += byte_count


def _is_missing_remote_file(error: OSError) -> bool:
    """Distinguish an absent archive from timeouts and permission/I/O failures."""
    return isinstance(error, FileNotFoundError) or getattr(error, "errno", None) == errno.ENOENT


class SSHConnectionManager:
    """Manages SSH connections to remote servers"""
    
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 30,
        allow_unknown_host: bool = False,
        known_hosts_path: Optional[str] = None,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.allow_unknown_host = allow_unknown_host
        self.known_hosts_path = known_hosts_path
        self.ssh = None
        self.sftp = None
        self._connected = False

    def _configure_host_key_policy(self):
        if not self.ssh:
            return

        if self.known_hosts_path:
            known_hosts = Path(self.known_hosts_path).expanduser()
            self.ssh.load_host_keys(str(known_hosts))
        else:
            self.ssh.load_system_host_keys()

        if self.allow_unknown_host:
            LOGGER.warning("SSH unknown host keys are allowed by configuration")
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            self.ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    
    def connect(self) -> bool:
        """Establish SSH connection"""
        self._close_handles()
        try:
            LOGGER.info("Connecting to the configured Wazuh SSH endpoint")
            self.ssh = paramiko.SSHClient()
            self._configure_host_key_policy()
            self.ssh.connect(
                self.host, 
                port=self.port, 
                username=self.username,
                password=self.password, 
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                channel_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False
            )
            self.sftp = self.ssh.open_sftp()
            get_channel = getattr(self.sftp, "get_channel", None)
            if callable(get_channel):
                get_channel().settimeout(self.timeout)
            self._connected = True
            LOGGER.info("SSH connection established")
            return True
        except Exception as error:
            LOGGER.warning("SSH connection failed (%s)", type(error).__name__)
            LOGGER.debug("SSH connection failure detail", exc_info=True)
            self._close_handles()
            return False

    @staticmethod
    def _set_remote_file_timeout(remote_file, timeout: int) -> None:
        setter = getattr(remote_file, "settimeout", None)
        if callable(setter):
            setter(timeout)

    def _close_handles(self) -> None:
        """Close SFTP and SSH independently so one close failure cannot leak the other."""
        sftp, ssh = self.sftp, self.ssh
        self.sftp = None
        self.ssh = None
        self._connected = False

        if sftp is not None:
            try:
                sftp.close()
            except Exception as error:
                LOGGER.warning("SFTP cleanup failed (%s)", type(error).__name__)
                LOGGER.debug("SFTP cleanup detail", exc_info=True)
        if ssh is not None:
            try:
                ssh.close()
            except Exception as error:
                LOGGER.warning("SSH cleanup failed (%s)", type(error).__name__)
                LOGGER.debug("SSH cleanup detail", exc_info=True)
    
    def disconnect(self):
        """Close SSH connection"""
        had_handles = self.sftp is not None or self.ssh is not None
        self._close_handles()
        if had_handles:
            LOGGER.info("SSH connection closed")
    
    @property
    def is_connected(self) -> bool:
        """Check if connection is active"""
        return self._connected and self.sftp is not None


class AlertsReader:
    """Reads current alerts from Wazuh alerts.json file"""
    
    def __init__(
        self,
        connection_manager: SSHConnectionManager,
        alerts_path: str,
        default_max_lines: int = 1000,
        max_total_bytes: int = 20 * 1024 * 1024,
        max_line_bytes: int = 1024 * 1024,
    ):
        self.connection_manager = connection_manager
        self.alerts_path = alerts_path
        self.default_max_lines = max(1, int(default_max_lines))
        self.max_total_bytes = max(1, int(max_total_bytes))
        self.max_line_bytes = max(1, int(max_line_bytes))

    def _bounded_output_lines(self, stream):
        """Yield command output without materializing an unbounded alert line."""
        total_bytes = 0
        readline = getattr(stream, "readline", None)
        if callable(readline):
            while True:
                line = readline(self.max_line_bytes + 1)
                if not line:
                    return
                byte_length = len(
                    line if isinstance(line, bytes) else str(line).encode("utf-8", errors="replace")
                )
                if byte_length > self.max_line_bytes:
                    raise ArchiveReadLimitError("Current alert line exceeds the configured size limit")
                total_bytes += byte_length
                if total_bytes > self.max_total_bytes:
                    raise ArchiveReadLimitError("Current alert input exceeds the configured byte limit")
                yield line
        else:  # Compatibility for simple file-like test doubles.
            for line in stream:
                byte_length = len(
                    line if isinstance(line, bytes) else str(line).encode("utf-8", errors="replace")
                )
                if byte_length > self.max_line_bytes:
                    raise ArchiveReadLimitError("Current alert line exceeds the configured size limit")
                total_bytes += byte_length
                if total_bytes > self.max_total_bytes:
                    raise ArchiveReadLimitError("Current alert input exceeds the configured byte limit")
                yield line
    
    def read_alerts(self, max_lines: int = None) -> List[Dict]:
        """Read current alerts from alerts.json
        
        Args:
            max_lines: If specified, only read the last N lines for performance
        """
        if not self.connection_manager.is_connected:
            LOGGER.warning("SSH connection is unavailable for alert reading")
            return []

        effective_max_lines = min(
            self.default_max_lines,
            self.default_max_lines if max_lines is None else int(max_lines),
        )
        if effective_max_lines <= 0:
            raise ValueError("max_lines must be a positive integer")
        
        alerts = []
        
        try:
            # Check if alerts file exists
            try:
                file_stat = self.connection_manager.sftp.stat(self.alerts_path)
                LOGGER.info("Found configured alerts file (%s bytes)", file_stat.st_size)
            except OSError as error:
                if _is_missing_remote_file(error):
                    LOGGER.warning("Configured alerts file was not found")
                    return alerts
                raise
            
            stdin = stdout = stderr = None
            try:
                stdin, stdout, stderr = self.connection_manager.ssh.exec_command(
                    f"tail -n {effective_max_lines} {shlex.quote(self.alerts_path)}",
                    timeout=self.connection_manager.timeout,
                )
                channel = getattr(stdout, "channel", None)
                set_timeout = getattr(channel, "settimeout", None)
                if callable(set_timeout):
                    set_timeout(self.connection_manager.timeout)

                for idx, line in enumerate(self._bounded_output_lines(stdout), 1):
                    line = line.strip()
                    if line:
                        try:
                            alert = json.loads(line)
                            if isinstance(alert, dict):
                                alerts.append(alert)
                        except json.JSONDecodeError:
                            LOGGER.warning("Skipped malformed alert JSON at output line %s", idx)
            finally:
                for stream in (stdin, stdout, stderr):
                    close = getattr(stream, "close", None)
                    if callable(close):
                        try:
                            close()
                        except Exception:
                            LOGGER.debug("SSH command stream cleanup failed", exc_info=True)

            LOGGER.info("Loaded %s current alerts", len(alerts))
                            
        except ArchiveReadLimitError:
            LOGGER.warning("Current alert safety limit reached; alert reading was aborted")
            raise
        except Exception as error:
            LOGGER.warning("Alert reading failed (%s)", type(error).__name__)
            LOGGER.debug("Alert reading failure detail", exc_info=True)
            alerts = []
            
        return alerts


class ArchiveReader:
    """Reads historical archive logs from Wazuh"""
    
    def __init__(
        self,
        connection_manager: SSHConnectionManager,
        archives_base_path: str,
        max_archive_days: int = 31,
        max_archive_records: int = 100000,
        max_archive_bytes: int = 100 * 1024 * 1024,
        max_archive_line_bytes: int = 1024 * 1024,
    ):
        self.connection_manager = connection_manager
        self.archives_base = archives_base_path
        self.max_archive_days = max(1, int(max_archive_days))
        self.max_archive_records = max(1, int(max_archive_records))
        self.max_archive_bytes = max(1, int(max_archive_bytes))
        self.max_archive_line_bytes = max(1, int(max_archive_line_bytes))

    def _read_bounded_line(
        self,
        stream,
        byte_budget: _ArchiveByteBudget,
    ) -> Optional[bytes]:
        """Read one binary line without allocating past line/request limits."""
        read_size = min(self.max_archive_line_bytes, byte_budget.remaining) + 1
        line = stream.readline(read_size)
        if not line:
            return None
        if isinstance(line, str):
            line = line.encode("utf-8", errors="replace")
        if len(line) > self.max_archive_line_bytes:
            raise ArchiveReadLimitError(
                f"Archive line exceeds the line-size limit ({self.max_archive_line_bytes} bytes)"
            )
        byte_budget.consume(len(line))
        return line
    
    def get_smart_archive_dates(self, past_days: int) -> List[datetime]:
        """Generate smart date list that handles month/year boundaries"""
        past_days = int(past_days)
        if not 1 <= past_days <= self.max_archive_days:
            raise ValueError(
                f"past_days must be between 1 and {self.max_archive_days}"
            )
        dates = []
        current = datetime.now()
        
        for i in range(1, past_days + 1):
            target_date = current - timedelta(days=i)
            dates.append(target_date)
            
        return dates
    
    def read_archives_smart(self, past_days: int = 7) -> int:
        """Read archive logs with smart date boundary handling"""
        if not self.connection_manager.is_connected:
            LOGGER.warning("SSH connection is unavailable for archive reading")
            return 0
        
        total_logs = 0
        dates = self.get_smart_archive_dates(past_days)
        byte_budget = _ArchiveByteBudget(self.max_archive_bytes)
        
        LOGGER.info("Reading Wazuh archives across %s day(s)", len(dates))

        for day in dates:
            remaining_records = self.max_archive_records - total_logs
            # Read at most one probe record beyond the remaining allowance. This
            # distinguishes an exact-size request from truncated input while
            # keeping memory bounded to MAX_ARCHIVE_RECORDS + 1.
            read_limit = max(1, remaining_records + 1)

            year = day.year
            month_name = day.strftime("%b")
            day_num = day.strftime("%d")
            base_path = f"{self.archives_base}/{year}/{month_name}"
            json_path = f"{base_path}/ossec-archive-{day_num}.json"
            gz_path = f"{base_path}/ossec-archive-{day_num}.json.gz"
            
            try:
                # Try JSON file first
                day_logs = self._read_json_archive(
                    json_path,
                    day,
                    max_records=read_limit,
                    byte_budget=byte_budget,
                )
                if day_logs > 0:
                    if day_logs > remaining_records:
                        raise ArchiveReadLimitError(
                            f"Archive record limit exceeded ({self.max_archive_records} records)"
                        )
                    total_logs += day_logs
                    continue
                
                # Try compressed file if JSON not found
                day_logs = self._read_gz_archive(
                    gz_path,
                    day,
                    max_records=read_limit,
                    byte_budget=byte_budget,
                )
                if day_logs > remaining_records:
                    raise ArchiveReadLimitError(
                        f"Archive record limit exceeded ({self.max_archive_records} records)"
                    )
                total_logs += day_logs
                if day_logs == 0:
                    LOGGER.info("No archive records found for %s", day.date().isoformat())
                    
            except ArchiveReadLimitError:
                LOGGER.warning("Archive safety limit reached; archive reading was aborted")
                raise
            except Exception as error:
                LOGGER.warning(
                    "Archive reading failed for %s (%s)",
                    day.date().isoformat(),
                    type(error).__name__,
                )
                LOGGER.debug("Archive reading failure detail", exc_info=True)
                # A requested corpus source must not silently activate from a
                # partial set of days. Missing daily files are handled inside
                # the individual readers; all other failures abort the build.
                raise
                
        LOGGER.info("Loaded %s archive records", total_logs)
        return total_logs
    
    def _read_json_archive(
        self,
        json_path: str,
        day: datetime,
        max_records: int,
        byte_budget: Optional[_ArchiveByteBudget] = None,
    ) -> int:
        """Read uncompressed JSON archive file"""
        day_records = []
        byte_budget = byte_budget or _ArchiveByteBudget(self.max_archive_bytes)
        
        try:
            if self.connection_manager.sftp.stat(json_path).st_size > 0:
                with self.connection_manager.sftp.open(json_path, 'rb') as f:
                    self.connection_manager._set_remote_file_timeout(
                        f,
                        self.connection_manager.timeout,
                    )
                    line_number = 0
                    while len(day_records) < max_records:
                        line = self._read_bounded_line(f, byte_budget)
                        if line is None:
                            break
                        line_number += 1
                        try:
                            line = line.decode('utf-8').strip()
                        except UnicodeDecodeError as error:
                            raise ArchiveFormatError(
                                f"Archive record is not UTF-8 for {day.date().isoformat()} at line {line_number}"
                            ) from error
                        if line:
                            try:
                                log = json.loads(line)
                                if not isinstance(log, dict):
                                    raise ArchiveFormatError(
                                        f"Archive record is not an object for {day.date().isoformat()} at line {line_number}"
                                    )
                                day_records.append(log)
                            except json.JSONDecodeError as error:
                                raise ArchiveFormatError(
                                    f"Archive record is invalid JSON for {day.date().isoformat()} at line {line_number}"
                                ) from error
                for log in day_records:
                    self._append_log(log)
                LOGGER.info(
                    "Loaded %s JSON archive records for %s",
                    len(day_records),
                    day.date().isoformat(),
                )
        except OSError as error:
            if not _is_missing_remote_file(error):
                raise
        
        return len(day_records)
    
    def _read_gz_archive(
        self,
        gz_path: str,
        day: datetime,
        max_records: int,
        byte_budget: Optional[_ArchiveByteBudget] = None,
    ) -> int:
        """Read compressed archive file"""
        day_records = []
        byte_budget = byte_budget or _ArchiveByteBudget(self.max_archive_bytes)
        
        try:
            if self.connection_manager.sftp.stat(gz_path).st_size > 0:
                with self.connection_manager.sftp.open(gz_path, 'rb') as f:
                    self.connection_manager._set_remote_file_timeout(
                        f,
                        self.connection_manager.timeout,
                    )
                    with gzip.GzipFile(fileobj=f) as gz_f:
                        line_number = 0
                        while len(day_records) < max_records:
                            line = self._read_bounded_line(gz_f, byte_budget)
                            if line is None:
                                break
                            line_number += 1
                            try:
                                line = line.decode('utf-8').strip()
                            except UnicodeDecodeError as error:
                                raise ArchiveFormatError(
                                    f"Archive record is not UTF-8 for {day.date().isoformat()} at line {line_number}"
                                ) from error
                            if line:
                                try:
                                    log = json.loads(line)
                                    if not isinstance(log, dict):
                                        raise ArchiveFormatError(
                                            f"Archive record is not an object for {day.date().isoformat()} at line {line_number}"
                                        )
                                    day_records.append(log)
                                except json.JSONDecodeError as error:
                                    raise ArchiveFormatError(
                                        f"Archive record is invalid JSON for {day.date().isoformat()} at line {line_number}"
                                    ) from error
                for log in day_records:
                    self._append_log(log)
                LOGGER.info(
                    "Loaded %s compressed archive records for %s",
                    len(day_records),
                    day.date().isoformat(),
                )
        except OSError as error:
            if not _is_missing_remote_file(error):
                raise
        
        return len(day_records)
    
    def _append_log(self, log: Dict):
        """Append log to the logs list (to be overridden by parent class)"""
        # This will be handled by the parent SmartSSHLogReader class
        pass


class SmartSSHLogReader:
    """Orchestrator class that combines SSH connection management with data reading"""
    
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        alerts_path: str = "/var/ossec/logs/alerts/alerts.json",
        archives_base_path: str = "/var/ossec/logs/archives",
        timeout: int = 30,
        allow_unknown_host: bool = False,
        known_hosts_path: Optional[str] = None,
        max_alert_lines: int = 1000,
        max_current_alert_bytes: int = 20 * 1024 * 1024,
        max_alert_line_bytes: int = 1024 * 1024,
        max_archive_days: int = 31,
        max_archive_records: int = 100000,
        max_archive_bytes: int = 100 * 1024 * 1024,
        max_archive_line_bytes: int = 1024 * 1024,
    ):
        
        # Initialize connection manager
        self.connection_manager = SSHConnectionManager(
            host,
            username,
            password,
            port,
            timeout=timeout,
            allow_unknown_host=allow_unknown_host,
            known_hosts_path=known_hosts_path,
        )
        
        # Initialize readers
        self.alerts_reader = AlertsReader(
            self.connection_manager,
            alerts_path,
            default_max_lines=max_alert_lines,
            max_total_bytes=max_current_alert_bytes,
            max_line_bytes=max_alert_line_bytes,
        )
        self.archive_reader = ArchiveReader(
            self.connection_manager,
            archives_base_path,
            max_archive_days=max_archive_days,
            max_archive_records=max_archive_records,
            max_archive_bytes=max_archive_bytes,
            max_archive_line_bytes=max_archive_line_bytes,
        )
        
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
