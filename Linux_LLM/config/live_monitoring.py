import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import hashlib
import logging
import threading
import uuid
from concurrent.futures import Executor
from dataclasses import dataclass
from functools import partial

from runtime_utils import atomic_write_text, log_sanitized_exception


async def _run_bounded_executor(executor, worker_admission, function, *args):
    """Submit one non-preemptible callable without allowing an unbounded queue."""
    if worker_admission is not None and not worker_admission.acquire(blocking=False):
        raise RuntimeError("The bounded worker pool is busy")
    loop = asyncio.get_running_loop()
    try:
        future = loop.run_in_executor(executor, partial(function, *args))
    except BaseException:
        if worker_admission is not None:
            worker_admission.release()
        raise
    if worker_admission is not None:
        future.add_done_callback(lambda _done: worker_admission.release())
    return await asyncio.shield(future)

@dataclass
class AlertSnapshot:
    """Represents a snapshot of current alerts for comparison"""
    timestamp: datetime
    alert_count: int
    high_severity_count: int
    critical_severity_count: int
    alert_hashes: Set[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "alert_count": self.alert_count,
            "high_severity_count": self.high_severity_count,
            "critical_severity_count": self.critical_severity_count,
            "alert_hashes": list(self.alert_hashes)
        }


class AlertHasher:
    """Creates unique hashes for alerts to detect duplicates"""
    
    @staticmethod
    def hash_alert(alert: Dict[str, Any]) -> str:
        """Create a unique hash for an alert based on key fields"""
        # Use key fields that make an alert unique
        key_fields = [
            alert.get("rule_id", ""),
            alert.get("src_ip", ""),
            alert.get("dest_ip", ""),
            alert.get("alert_signature", ""),
            str(alert.get("timestamp") or "")[:16],  # Truncate to minute precision
        ]
        
        # Create hash from concatenated key fields
        key_string = "|".join(str(field) for field in key_fields)
        return hashlib.sha256(key_string.encode()).hexdigest()


class PersistentSSHConnection:
    """Manages a persistent SSH connection for continuous monitoring"""
    
    def __init__(
        self,
        ssh_reader_factory,
        executor: Optional[Executor] = None,
        worker_admission=None,
    ):
        self.ssh_reader_factory = ssh_reader_factory
        self.executor = executor
        self.worker_admission = worker_admission
        self.ssh_reader = None
        self.connection_attempts = 0
        self.max_connection_attempts = 3
        self.last_connection_time = None
        self._io_lock = threading.RLock()

    async def _run_blocking(self, function, *args):
        return await _run_bounded_executor(
            self.executor,
            self.worker_admission,
            function,
            *args,
        )

    def _ensure_connection_sync(self) -> bool:
        """Ensure SSH connection is active while holding the shared I/O lock."""
        with self._io_lock:
            return self._ensure_connection_locked()

    def _ensure_connection_locked(self) -> bool:
        try:
            if self.ssh_reader and self.ssh_reader.is_connected:
                return True
            
            # Need to establish new connection
            if self.ssh_reader:
                try:
                    self.ssh_reader.disconnect()
                except Exception:
                    pass
            
            print(f"🔌 Establishing persistent SSH connection (attempt {self.connection_attempts + 1})...")
            self.ssh_reader = self.ssh_reader_factory()
            
            if self.ssh_reader.connect():
                self.last_connection_time = datetime.now()
                self.connection_attempts = 0
                return True
            else:
                self.connection_attempts += 1
                print(f"❌ SSH connection failed (attempt {self.connection_attempts})")
                return False
                
        except Exception as e:
            self.connection_attempts += 1
            log_sanitized_exception("Persistent SSH connection failed", e)
            return False

    async def ensure_connection(self) -> bool:
        return await self._run_blocking(self._ensure_connection_sync)

    def _read_alerts_sync(self, max_lines: int) -> List[Dict]:
        """Connect and read under one lock so reconnect cannot replace the client."""
        with self._io_lock:
            if not self._ensure_connection_locked():
                return []
            try:
                return self.ssh_reader.read_alerts(max_lines)
            except Exception as error:
                log_sanitized_exception("Persistent remote alert read failed", error)
                if self.ssh_reader:
                    try:
                        self.ssh_reader.disconnect()
                    except Exception:
                        pass
                self.ssh_reader = None
                return []

    async def read_alerts(self, max_lines: int = 1000) -> List[Dict]:
        return await self._run_blocking(self._read_alerts_sync, max(1, int(max_lines)))

    def disconnect(self):
        """Disconnect synchronously; shutdown uses the non-blocking async wrapper."""
        with self._io_lock:
            self._disconnect_locked()

    def _disconnect_locked(self) -> None:
        try:
            if self.ssh_reader:
                self.ssh_reader.disconnect()
                print("🔌 Persistent SSH connection closed")
        except Exception:
            pass
        finally:
            self.ssh_reader = None
            self.last_connection_time = None

    async def disconnect_async(self) -> None:
        # Teardown must not be rejected merely because normal worker admission
        # is saturated. This is a single bounded cleanup submission whose I/O
        # lock waits for any active remote read to finish.
        await asyncio.to_thread(self.disconnect)


class EnhancedLiveMonitoringService:
    def __init__(self, config_manager, report_generator, ssh_reader_factory,
                 executor: Optional[Executor] = None, worker_admission=None):
        self.config = config_manager
        self.report_generator = report_generator
        self.ssh_reader_factory = ssh_reader_factory
        
        self.monitoring_enabled = False
        self.continuous_monitoring = False  
        self.polling_interval = 10  
        self.high_severity_threshold = 8  
        self.critical_severity_threshold = 12 
        
        self.executor = executor
        self.worker_admission = worker_admission
        self.persistent_ssh = PersistentSSHConnection(
            ssh_reader_factory,
            executor=executor,
            worker_admission=worker_admission,
        )
        
        self.last_snapshot: Optional[AlertSnapshot] = None
        self.processed_alert_hashes: Set[str] = set()
        self.inflight_alert_hashes: Set[str] = set()
        self.monitoring_task: Optional[asyncio.Task] = None
        self._shutdown_started = False
        self.statistics = {
            "monitoring_started": None,
            "total_polls": 0,
            "high_alerts_detected": 0,
            "reports_generated": 0,
            "last_poll": None,
            "errors": 0,
            "filtered_low_alerts": 0
        }
        
        self.logger = logging.getLogger("EnhancedLiveMonitoring")
        self.logger.setLevel(logging.INFO)
        self.alert_history: List[AlertSnapshot] = []
        self.max_history_size = 100
        
        self.llm_lock = asyncio.Lock()
        self.llm_running = False
        self.pending_reports_queue = []
        self.max_queue_size = 5
        self.batch_wait_seconds = 5  # Wait 5s to collect more alerts
        self.last_batch_time = None

    async def _run_blocking(self, function, *args):
        return await _run_bounded_executor(
            self.executor,
            self.worker_admission,
            function,
            *args,
        )

    @staticmethod
    def _safe_rule_level(value: Any) -> int:
        try:
            return int(value) if value is not None else 0
        except (ValueError, TypeError):
            return 0
        
    def start_monitoring(self, continuous: bool = False) -> bool:
        """Start the enhanced live monitoring service"""
        if self._shutdown_started:
            self.logger.info("Monitoring start ignored because shutdown is in progress")
            return False
        
        # Check if task exists and is still running
        if self.monitoring_task and not self.monitoring_task.done():
            self.logger.info("🔄 Monitoring already running")
            return False
        
        # If old task exists but finished, clean it up
        if self.monitoring_task and self.monitoring_task.done():
            self.logger.info("🧹 Cleaning up old monitoring task")
            try:
                # Check if it had an exception
                exception = self.monitoring_task.exception()
                if exception:
                    log_sanitized_exception(
                        "Previous monitoring task failed",
                        exception,
                        logger=self.logger,
                    )
            except Exception:
                pass
            self.monitoring_task = None
        
        # Check RAG readiness
        if not self.report_generator.rag_ready:
            self.logger.error("❌ Cannot start monitoring: RAG context not ready")
            return False
        
        # Start fresh monitoring
        self.monitoring_enabled = True
        self.continuous_monitoring = continuous
        self.statistics["monitoring_started"] = datetime.now()
        
        # Create new task
        self.monitoring_task = asyncio.create_task(self._enhanced_monitoring_loop())
        
        mode = "CONTINUOUS" if continuous else f"INTERVAL ({self.polling_interval}s)"
        self.logger.info(f"🚀 Enhanced live monitoring started - {mode} mode")
        self.logger.info(f"📊 Alert threshold: rule_level >= {self.high_severity_threshold}")
        
        # Detect task crashes and reset state so monitoring can be restarted.
        def task_done_callback(task):
            try:
                task.result()  # This will raise exception if task failed
            except asyncio.CancelledError:
                self.logger.info("✅ Monitoring task cancelled gracefully")
            except Exception as e:
                log_sanitized_exception("Monitoring task crashed", e, logger=self.logger)
                # Reset state so it can be restarted
                self.monitoring_enabled = False
        
        self.monitoring_task.add_done_callback(task_done_callback)
        
        return True
    
    async def shutdown(self) -> None:
        """Cancel and await monitoring before closing persistent SSH resources."""
        self._shutdown_started = True
        self.monitoring_enabled = False
        self.continuous_monitoring = False
        task = self.monitoring_task
        self.monitoring_task = None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await self.persistent_ssh.disconnect_async()
    
    def update_config(self, polling_interval: int = None, 
                     high_severity_threshold: int = None,
                     continuous: bool = None) -> Dict[str, Any]:
        """Update monitoring configuration"""
        if polling_interval is not None:
            self.polling_interval = max(5, polling_interval)  # Min 5 seconds
        
        if high_severity_threshold is not None:
            self.high_severity_threshold = max(1, min(16, high_severity_threshold))
        
        if continuous is not None:
            self.continuous_monitoring = continuous
        
        config = self.get_config()
        self.logger.info(f"⚙️ Updated config: {config}")
        return config
    
    def get_config(self) -> Dict[str, Any]:
        """Get current monitoring configuration"""
        return {
            "monitoring_enabled": self.monitoring_enabled,
            "continuous_monitoring": self.continuous_monitoring,
            "polling_interval": self.polling_interval,
            "high_severity_threshold": self.high_severity_threshold,
            "critical_severity_threshold": self.critical_severity_threshold,
            "rag_ready": self.report_generator.rag_ready
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics with JSON-serializable datetime objects"""
        stats = self.statistics.copy()
        
        # Convert datetime objects to ISO strings for JSON serialization
        if stats.get("monitoring_started"):
            stats["monitoring_started"] = stats["monitoring_started"].isoformat()
            # Add calculated uptime
            uptime_seconds = (datetime.now() - datetime.fromisoformat(stats["monitoring_started"])).total_seconds()
            stats["uptime_seconds"] = uptime_seconds
        else:
            stats["uptime_seconds"] = 0
        
        if stats.get("last_poll"):
            stats["last_poll"] = stats["last_poll"].isoformat()
        
        # Add current state info
        stats.update({
            "monitoring_enabled": self.monitoring_enabled,
            "continuous_monitoring": self.continuous_monitoring,
            "processed_alerts": len(self.processed_alert_hashes),
            "history_snapshots": len(self.alert_history),
            "connection_status": self.persistent_ssh.ssh_reader is not None
        })
        
        return stats
    
    async def _enhanced_monitoring_loop(self):
        """Enhanced monitoring loop with persistent connections and proper filtering"""
        self.logger.info("🔄 Starting enhanced monitoring loop")
        
        try:
            iteration = 0
            while self.monitoring_enabled:
                iteration += 1
                try:
                    await self._poll_alerts_enhanced()
                    self.statistics["total_polls"] += 1
                    self.statistics["last_poll"] = datetime.now()
                    
                    # Log every 10 iterations to reduce spam
                    if iteration % 10 == 0:
                        self.logger.info(f"📊 Poll #{iteration} completed - monitoring active")
                    
                except Exception as e:
                    self.statistics["errors"] += 1
                    self.logger.error(f"Monitoring loop error ({type(e).__name__})")
                
                # Wait based on mode
                if self.continuous_monitoring:
                    await asyncio.sleep(1)  # Very short sleep for continuous mode
                else:
                    await asyncio.sleep(self.polling_interval)
                
        except asyncio.CancelledError:
            self.logger.info("🛑 Enhanced monitoring loop cancelled")
        except Exception as e:
            self.logger.error(f"Fatal monitoring loop error ({type(e).__name__})")
            self.monitoring_enabled = False
    
    async def _poll_alerts_enhanced(self):
        """Enhanced alert polling with proper severity filtering"""
        try:
            # Get current alerts via persistent SSH
            current_alerts = await self.persistent_ssh.read_alerts()
            
            if not current_alerts:
                return  # No alerts to process
            
            # Process alerts through AlertAnalyzer with proper filtering
            cleaned_alerts = await self._run_blocking(
                self.report_generator.clean_log_data,
                current_alerts,
            )
            
            # Create current snapshot
            current_snapshot = self._create_enhanced_snapshot(cleaned_alerts)
            
            # Check for new HIGH severity alerts with enhanced filtering
            new_high_alerts = self._detect_high_severity_alerts_enhanced(
                cleaned_alerts, current_snapshot
            )
            
            if new_high_alerts:
                self.logger.info(f"🚨 Detected {len(new_high_alerts)} new HIGH severity alerts (>= level {self.high_severity_threshold})")
                self.statistics["high_alerts_detected"] += len(new_high_alerts)
                
                # Generate report automatically
                success = await self._generate_automatic_report_enhanced(
                    current_alerts, new_high_alerts
                )
                
            # Update state
            self.last_snapshot = current_snapshot
            self._update_alert_history(current_snapshot)
            
        except Exception as e:
            self.logger.error(f"Enhanced alert polling failed ({type(e).__name__})")
            raise
    
    def _create_enhanced_snapshot(self, cleaned_alerts: List[Dict[str, Any]]) -> AlertSnapshot:
        """Create enhanced snapshot with proper severity counting"""
        alert_hashes = set()
        high_severity_count = 0
        critical_severity_count = 0
        
        for alert in cleaned_alerts:
            # Create hash for this alert
            alert_hash = AlertHasher.hash_alert(alert)
            alert_hashes.add(alert_hash)
            
            # Count severity levels properly
            rule_level = alert.get("rule_level", 0)
            
            # Ensure rule_level is an integer
            try:
                rule_level = int(rule_level) if rule_level is not None else 0
            except (ValueError, TypeError):
                rule_level = 0
            
            if rule_level >= self.critical_severity_threshold:
                critical_severity_count += 1
                high_severity_count += 1  # Critical alerts are also high
            elif rule_level >= self.high_severity_threshold:
                high_severity_count += 1
        
        return AlertSnapshot(
            timestamp=datetime.now(),
            alert_count=len(cleaned_alerts),
            high_severity_count=high_severity_count,
            critical_severity_count=critical_severity_count,
            alert_hashes=alert_hashes
        )
    
    def _detect_high_severity_alerts_enhanced(self, cleaned_alerts: List[Dict[str, Any]], 
                                            current_snapshot: AlertSnapshot) -> List[Dict[str, Any]]:
        """Detect new alerts using severity filtering."""
        new_high_alerts = []
        low_severity_filtered = 0
        
        for alert in cleaned_alerts:
            # Get rule level with proper type conversion
            rule_level = alert.get("rule_level", 0)
            
            try:
                rule_level = int(rule_level) if rule_level is not None else 0
            except (ValueError, TypeError):
                rule_level = 0
                self.logger.warning("Invalid rule_level was defaulted to zero")
            
            # Strict severity filtering
            if rule_level >= self.high_severity_threshold:
                alert_hash = AlertHasher.hash_alert(alert)
                
                # Check if we've already processed this alert
                if (
                    alert_hash not in self.processed_alert_hashes
                    and alert_hash not in self.inflight_alert_hashes
                ):
                    new_high_alerts.append(alert)
                    self.inflight_alert_hashes.add(alert_hash)
                    
                    # Debug logging for high alerts
                    alert["rule_description"] = str(alert.get("rule_description") or "Unknown")
                    self.logger.info(f"New high-severity alert reserved (level {rule_level})")
            else:
                low_severity_filtered += 1
        
        # Update statistics
        self.statistics["filtered_low_alerts"] += low_severity_filtered
        
        # Debug logging
        if low_severity_filtered > 0:
            self.logger.info(f"🔽 Filtered {low_severity_filtered} low-severity alerts (< level {self.high_severity_threshold})")
        
        return new_high_alerts
    async def _generate_automatic_report_enhanced(self, all_alerts: List[Dict[str, Any]], 
                                            triggered_alerts: List[Dict[str, Any]]) -> bool:
        """Generate automatic report with concurrency control and intelligent batching"""
        
        if self.llm_running:
            self.logger.warning(f"⚠️ LLM already running - queueing alerts for batching")
            
            if len(self.pending_reports_queue) < self.max_queue_size:
                self.pending_reports_queue.append({
                    "all_alerts": all_alerts,
                    "triggered_alerts": triggered_alerts,
                    "timestamp": datetime.now()
                })
                self.logger.info(f"📋 Alerts queued for batch processing (queue size: {len(self.pending_reports_queue)})")
                return True
            else:
                self.logger.error(f"❌ Report queue full ({self.max_queue_size}) - dropping request")
                self.inflight_alert_hashes.difference_update(
                    AlertHasher.hash_alert(alert) for alert in triggered_alerts
                )
                self.statistics["errors"] += 1
                return False
        
        async with self.llm_lock:
            self.llm_running = True
            try:
                self.logger.info(f"⏳ Waiting {self.batch_wait_seconds}s to batch additional alerts...")
                await asyncio.sleep(self.batch_wait_seconds)
                
                # Merge any alerts that arrived during wait period
                batched_all_alerts = list(all_alerts)
                batched_triggered_alerts = list(triggered_alerts)
                
                if self.pending_reports_queue:
                    initial_queue_size = len(self.pending_reports_queue)
                    self.logger.info(f"🔄 Batching {initial_queue_size} queued alert sets into single report")
                    
                    # Use sets to deduplicate alerts by hash
                    all_alerts_hashes = set()
                    triggered_alerts_hashes = set()
                    
                    # Add initial alerts
                    for alert in batched_all_alerts:
                        all_alerts_hashes.add(AlertHasher.hash_alert(alert))
                    for alert in batched_triggered_alerts:
                        triggered_alerts_hashes.add(AlertHasher.hash_alert(alert))
                    
                    # Merge queued alerts (deduplicate)
                    while self.pending_reports_queue:
                        queued = self.pending_reports_queue.pop(0)
                        
                        for alert in queued["all_alerts"]:
                            alert_hash = AlertHasher.hash_alert(alert)
                            if alert_hash not in all_alerts_hashes:
                                batched_all_alerts.append(alert)
                                all_alerts_hashes.add(alert_hash)
                        
                        for alert in queued["triggered_alerts"]:
                            alert_hash = AlertHasher.hash_alert(alert)
                            if alert_hash not in triggered_alerts_hashes:
                                batched_triggered_alerts.append(alert)
                                triggered_alerts_hashes.add(alert_hash)
                    
                    self.logger.info(
                        f"📊 Batched totals: {len(batched_all_alerts)} total alerts, "
                        f"{len(batched_triggered_alerts)} high-severity alerts "
                        f"(from {initial_queue_size + 1} alert sets)"
                    )
                else:
                    self.logger.info("ℹNo additional alerts to batch - processing single set")
                
                success = await self._execute_report_generation(
                    batched_all_alerts, 
                    batched_triggered_alerts
                )
                completed_hashes = {
                    AlertHasher.hash_alert(alert) for alert in batched_triggered_alerts
                }
                self.inflight_alert_hashes.difference_update(completed_hashes)
                if success:
                    self.processed_alert_hashes.update(completed_hashes)
                    self._bound_processed_hashes()
                
                self.last_batch_time = datetime.now()
                return success
                
            finally:
                if "batched_triggered_alerts" in locals():
                    self.inflight_alert_hashes.difference_update(
                        AlertHasher.hash_alert(alert) for alert in batched_triggered_alerts
                    )
                self.llm_running = False
                self.logger.info("🔓 LLM lock released")
    
    async def _execute_report_generation(self, all_alerts: List[Dict[str, Any]], 
                                        triggered_alerts: List[Dict[str, Any]]) -> bool:
        """Execute the actual report generation (called with lock held)"""
        try:
            self.logger.info(f"📝 Generating automatic report for {len(triggered_alerts)} high-severity alerts...")
            
            high_severity_count = sum(
                1 for alert in triggered_alerts
                if self._safe_rule_level(alert.get("rule_level")) >= self.high_severity_threshold
            )
            critical_severity_count = sum(
                1 for alert in triggered_alerts
                if self._safe_rule_level(alert.get("rule_level")) >= self.critical_severity_threshold
            )
            
            trigger_info = {
                "is_automatic": True,
                "trigger_count": len(triggered_alerts),
                "high_severity_count": high_severity_count,
                "critical_severity_count": critical_severity_count,
                "total_alerts": len(all_alerts),
                "threshold": self.high_severity_threshold,
                "triggered_alerts": triggered_alerts[:5],  # Include up to 5 for context
                "response_priority": "IMMEDIATE" if critical_severity_count > 0 else "HIGH",
                "detected_at": datetime.now().isoformat(),
                "batched": len(all_alerts) != len(triggered_alerts)  # Indicates if batched
            }
            
            def sync_generate():
                """Synchronous LLM generation (runs in executor)"""
                cleaned_all_alerts = self.report_generator.clean_log_data(all_alerts)
                return self.report_generator.generate_report_with_rag(
                    cleaned_all_alerts, 
                    "Monitored Wazuh source",
                    is_automatic=True, 
                    trigger_info=trigger_info
                )
            
            # Let the model client own process termination, with a small async margin.
            generation_timeout = max(1, int(self.config.llm.timeout)) + 30
            self.logger.info(f"Starting LLM report generation (timeout: {generation_timeout}s)")
            start_time = datetime.now()
            
            report_content = await asyncio.wait_for(
                self._run_blocking(sync_generate),
                timeout=generation_timeout
            )
            
            generation_time = (datetime.now() - start_time).total_seconds()
            self.logger.info(f"✅ LLM generation completed in {generation_time:.1f}s")
            
            # Save markdown
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            
            # Filename indicates severity and batching
            severity_prefix = "AUTO_CRITICAL" if critical_severity_count > 0 else "AUTO_HIGH"
            batch_indicator = f"_BATCH{len(all_alerts)}" if trigger_info["batched"] else ""
            filename = f"{severity_prefix}{batch_indicator}_{timestamp}_{uuid.uuid4().hex[:8]}.md"
            
            report_path = Path(self.config.paths.reports_dir) / filename
            
            atomic_write_text(report_path, report_content)
            
            self.logger.info(f"💾 Automatic report saved: {filename}")
            self.logger.info(
                f"   📊 Report stats: {len(all_alerts)} total alerts, "
                f"{high_severity_count} high, {critical_severity_count} critical"
            )
            
            self.statistics["reports_generated"] += 1
            return True
            
        except asyncio.TimeoutError:
            self.report_generator.cancel_active_generations(permanent=False)
            self.logger.error("Report generation timed out")
            self.statistics["errors"] += 1
            return False
            
        except Exception as e:
            log_sanitized_exception("Automatic report generation failed", e, logger=self.logger)
            self.statistics["errors"] += 1
            return False
    
    def _update_alert_history(self, snapshot: AlertSnapshot):
        """Update alert history for trend analysis"""
        self.alert_history.append(snapshot)
        
        # Keep only recent history
        if len(self.alert_history) > self.max_history_size:
            self.alert_history = self.alert_history[-self.max_history_size:]
    
    def _bound_processed_hashes(self) -> None:
        """Bound the in-memory deduplication set."""
        if len(self.processed_alert_hashes) > 10000:
            self.processed_alert_hashes = set(
                list(self.processed_alert_hashes)[-5000:]
            )
            self.logger.info("Bounded processed alert hashes")


# Factory function for easy integration
def create_enhanced_live_monitoring_service(
    config_manager,
    report_generator,
    ssh_reader_factory,
    executor: Optional[Executor] = None,
    worker_admission=None,
):
    """Factory function to create EnhancedLiveMonitoringService"""
    return EnhancedLiveMonitoringService(
        config_manager,
        report_generator,
        ssh_reader_factory,
        executor=executor,
        worker_admission=worker_admission,
    )
