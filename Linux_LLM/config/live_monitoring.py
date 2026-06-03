import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import hashlib
import logging
from dataclasses import dataclass

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
            alert.get("timestamp", "")[:16],  # Truncate to minute precision
        ]
        
        # Create hash from concatenated key fields
        key_string = "|".join(str(field) for field in key_fields)
        return hashlib.md5(key_string.encode()).hexdigest()


class PersistentSSHConnection:
    """Manages a persistent SSH connection for continuous monitoring"""
    
    def __init__(self, ssh_reader_factory):
        self.ssh_reader_factory = ssh_reader_factory
        self.ssh_reader = None
        self.connection_attempts = 0
        self.max_connection_attempts = 3
        self.last_connection_time = None
        # REMOVED: self.connection_timeout = 300  # This was forcing reconnection every 5 minutes
        
    async def ensure_connection(self) -> bool:
        """Ensure SSH connection is active, reconnect if needed"""
        try:
            # Check if connection is still valid - SIMPLIFIED
            if self.ssh_reader and self.ssh_reader.is_connected:
                return True
            
            # Need to establish new connection
            if self.ssh_reader:
                try:
                    self.ssh_reader.disconnect()
                except:
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
            print(f"❌ SSH connection error: {e}")
            return False
    
    async def read_alerts(self) -> List[Dict]:
        """Read alerts using persistent connection"""
        if not await self.ensure_connection():
            return []
        
        try:
            return self.ssh_reader.read_alerts(1000)
        except Exception as e:
            print(f"❌ Error reading alerts: {e}")
            # Only force reconnection if the error indicates connection loss
            if "not connected" in str(e).lower() or "connection" in str(e).lower():
                print(f"⚠️ Connection appears lost, will attempt reconnect on next call")
                self.ssh_reader = None  # Force reconnection
            return []
    
    def disconnect(self):
        """Disconnect SSH connection"""
        if self.ssh_reader:
            try:
                self.ssh_reader.disconnect()
                print("🔌 Persistent SSH connection closed")
            except:
                pass
            self.ssh_reader = None
            self.last_connection_time = None


class EnhancedLiveMonitoringService:
    def __init__(self, config_manager, report_generator, ssh_reader_factory):
        self.config = config_manager
        self.report_generator = report_generator
        self.ssh_reader_factory = ssh_reader_factory
        
        self.monitoring_enabled = False
        self.continuous_monitoring = False  
        self.polling_interval = 10  
        self.high_severity_threshold = 8  
        self.critical_severity_threshold = 12 
        
        self.persistent_ssh = PersistentSSHConnection(ssh_reader_factory)
        
        self.last_snapshot: Optional[AlertSnapshot] = None
        self.processed_alert_hashes: Set[str] = set()
        self.monitoring_task: Optional[asyncio.Task] = None
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
        
    def start_monitoring(self, continuous: bool = False) -> bool:
        """Start the enhanced live monitoring service"""
        
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
                    self.logger.error(f"❌ Previous monitoring task failed: {exception}")
            except:
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
        
        # CRITICAL: Add task callback to detect crashes
        def task_done_callback(task):
            try:
                task.result()  # This will raise exception if task failed
            except asyncio.CancelledError:
                self.logger.info("✅ Monitoring task cancelled gracefully")
            except Exception as e:
                self.logger.error(f"❌ MONITORING TASK CRASHED: {e}")
                import traceback
                self.logger.error(traceback.format_exc())
                # Reset state so it can be restarted
                self.monitoring_enabled = False
        
        self.monitoring_task.add_done_callback(task_done_callback)
        
        return True
    
    def stop_monitoring(self) -> bool:
        if not self.monitoring_enabled:
            self.logger.info("⏹️ Monitoring not running")
            return False
        
        self.monitoring_enabled = False
        self.continuous_monitoring = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            self.monitoring_task = None
        
        # Disconnect persistent SSH
        self.persistent_ssh.disconnect()
        
        self.logger.info("🛑 Enhanced live monitoring stopped")
        return True
    
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
                    self.logger.error(f"❌ Error in monitoring loop: {e}")
                
                # Wait based on mode
                if self.continuous_monitoring:
                    await asyncio.sleep(1)  # Very short sleep for continuous mode
                else:
                    await asyncio.sleep(self.polling_interval)
                
        except asyncio.CancelledError:
            self.logger.info("🛑 Enhanced monitoring loop cancelled")
        except Exception as e:
            self.logger.error(f"❌ Fatal error in monitoring loop: {e}")
            self.monitoring_enabled = False
    
    async def _poll_alerts_enhanced(self):
        """Enhanced alert polling with proper severity filtering"""
        try:
            # Get current alerts via persistent SSH
            current_alerts = await self.persistent_ssh.read_alerts()
            
            if not current_alerts:
                return  # No alerts to process
            
            # Process alerts through AlertAnalyzer with proper filtering
            cleaned_alerts = self.report_generator.clean_log_data(current_alerts)
            
            # Create current snapshot
            current_snapshot = self._create_enhanced_snapshot(cleaned_alerts)
            
            # Check for new HIGH severity alerts with enhanced filtering
            new_high_alerts = self._detect_high_severity_alerts_enhanced(
                cleaned_alerts, current_snapshot
            )
            
            if new_high_alerts:
                self.logger.info(f"🚨 Detected {len(new_high_alerts)} new HIGH severity alerts (>= level {self.high_severity_threshold})")
                self.statistics["high_alerts_detected"] += len(new_high_alerts)
                
                # Log alert details for debugging
                for alert in new_high_alerts[:3]:  # Log first 3 alerts
                    level = alert.get("rule_level", 0)
                    desc = alert.get("rule_description", "Unknown")
                    self.logger.info(f"  📋 Level {level}: {desc[:50]}...")
                
                # Generate report automatically
                success = await self._generate_automatic_report_enhanced(
                    current_alerts, new_high_alerts
                )
                
                if success:
                    self.statistics["reports_generated"] += 1
            
            # Update state
            self.last_snapshot = current_snapshot
            self._update_alert_history(current_snapshot)
            
        except Exception as e:
            self.logger.error(f"❌ Error in enhanced alert polling: {e}")
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
                self.logger.warning(f"⚠️ Invalid rule_level: {alert.get('rule_level')} - defaulting to 0")
            
            # Strict severity filtering
            if rule_level >= self.high_severity_threshold:
                alert_hash = AlertHasher.hash_alert(alert)
                
                # Check if we've already processed this alert
                if alert_hash not in self.processed_alert_hashes:
                    new_high_alerts.append(alert)
                    self.processed_alert_hashes.add(alert_hash)
                    
                    # Debug logging for high alerts
                    self.logger.info(f"🔍 NEW HIGH Alert: Level {rule_level} - {alert.get('rule_description', 'Unknown')[:50]}...")
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
                
                self.last_batch_time = datetime.now()
                return success
                
            finally:
                self.llm_running = False
                self.logger.info("🔓 LLM lock released")
    
    async def _execute_report_generation(self, all_alerts: List[Dict[str, Any]], 
                                        triggered_alerts: List[Dict[str, Any]]) -> bool:
        """Execute the actual report generation (called with lock held)"""
        try:
            self.logger.info(f"📝 Generating automatic report for {len(triggered_alerts)} high-severity alerts...")
            
            high_severity_count = sum(1 for alert in triggered_alerts 
                                    if alert.get("rule_level", 0) >= self.high_severity_threshold)
            critical_severity_count = sum(1 for alert in triggered_alerts 
                                        if alert.get("rule_level", 0) >= self.critical_severity_threshold)
            
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
            
            loop = asyncio.get_event_loop()
            
            def sync_generate():
                """Synchronous LLM generation (runs in executor)"""
                cleaned_all_alerts = self.report_generator.clean_log_data(all_alerts)
                return self.report_generator.generate_report_with_rag(
                    cleaned_all_alerts, 
                    self.config.ssh.host, 
                    is_automatic=True, 
                    trigger_info=trigger_info
                )
            
            # Execute with timeout (3 minutes)
            self.logger.info("🤖 Starting LLM report generation (timeout: 180s)...")
            start_time = datetime.now()
            
            report_content = await asyncio.wait_for(
                loop.run_in_executor(None, sync_generate),
                timeout=180
            )
            
            generation_time = (datetime.now() - start_time).total_seconds()
            self.logger.info(f"✅ LLM generation completed in {generation_time:.1f}s")
            
            # Save markdown
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Filename indicates severity and batching
            severity_prefix = "AUTO_CRITICAL" if critical_severity_count > 0 else "AUTO_HIGH"
            batch_indicator = f"_BATCH{len(all_alerts)}" if trigger_info["batched"] else ""
            filename = f"{severity_prefix}{batch_indicator}_{timestamp}.md"
            
            report_path = Path(self.config.paths.reports_dir) / filename
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            self.logger.info(f"💾 Automatic report saved: {filename}")
            self.logger.info(
                f"   📊 Report stats: {len(all_alerts)} total alerts, "
                f"{high_severity_count} high, {critical_severity_count} critical"
            )
            
            self.statistics["reports_generated"] += 1
            return True
            
        except asyncio.TimeoutError:
            self.logger.error(f"❌ Report generation TIMED OUT after 180s")
            self.logger.error(f"   💡 Consider increasing timeout or reducing alert count")
            self.statistics["errors"] += 1
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Report generation FAILED: {e}")
            self.logger.error(f"   Error type: {type(e).__name__}")
            self.statistics["errors"] += 1
            
            import traceback
            self.logger.error("   📋 Full traceback:")
            for line in traceback.format_exc().split('\n'):
                if line.strip():
                    self.logger.error(f"      {line}")
            
            return False
    
    async def _auto_convert_to_pdf_enhanced(self, report_path: Path):
        """Enhanced automatic PDF conversion with better error handling"""
        try:
            # Check if PDF converter is available
            converter_available = hasattr(self.config, 'pdf_converter')
            
            if not converter_available:
                self.logger.info("📄 PDF converter not available for auto-conversion")
                return
            
            # For now, just log that auto-conversion was requested
            # The actual conversion can be handled by the main application
            self.logger.info(f"📄 Enhanced auto-conversion requested for: {report_path.name}")
            
        except Exception as e:
            self.logger.warning(f"⚠️ Enhanced auto-convert setup failed: {e}")
    
    def _update_alert_history(self, snapshot: AlertSnapshot):
        """Update alert history for trend analysis"""
        self.alert_history.append(snapshot)
        
        # Keep only recent history
        if len(self.alert_history) > self.max_history_size:
            self.alert_history = self.alert_history[-self.max_history_size:]
    
    def get_alert_trends(self, hours: int = 24) -> Dict[str, Any]:
        """Get alert trends over the specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_snapshots = [
            snap for snap in self.alert_history 
            if snap.timestamp >= cutoff_time
        ]
        
        if not recent_snapshots:
            return {"message": "No recent alert data available"}
        
        return {
            "time_period_hours": hours,
            "snapshots": len(recent_snapshots),
            "avg_alerts_per_snapshot": sum(s.alert_count for s in recent_snapshots) / len(recent_snapshots),
            "total_high_alerts": sum(s.high_severity_count for s in recent_snapshots),
            "total_critical_alerts": sum(s.critical_severity_count for s in recent_snapshots),
            "peak_alert_count": max(s.alert_count for s in recent_snapshots),
            "latest_snapshot": recent_snapshots[-1].to_dict() if recent_snapshots else None
        }
    
    def cleanup_old_hashes(self, max_age_hours: int = 24):
        """Clean up old alert hashes to prevent memory growth"""
        # For now, just limit the size. In production, you might want
        # to implement time-based cleanup
        if len(self.processed_alert_hashes) > 10000:
            # Keep only the most recent 5000 hashes
            # Note: This is a simplified approach
            self.processed_alert_hashes = set(
                list(self.processed_alert_hashes)[-5000:]
            )
            self.logger.info(" Cleaned up old alert hashes")


# Factory function for easy integration
def create_enhanced_live_monitoring_service(config_manager, report_generator, ssh_reader_factory):
    """Factory function to create EnhancedLiveMonitoringService"""
    return EnhancedLiveMonitoringService(config_manager, report_generator, ssh_reader_factory)