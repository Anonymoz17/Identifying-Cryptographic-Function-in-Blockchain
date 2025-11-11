"""
Metrics collection and monitoring for dynamic analysis.

This module implements comprehensive metrics collection, health checks,
and monitoring capabilities for the dynamic analysis system. It tracks
execution metrics, resource usage, and system health.

Features:
- Execution metrics (success rate, duration, throughput)
- Resource usage tracking (CPU, memory, storage)
- Health checks (component status, dependencies)
- Alerting (threshold-based alerts)
- Metrics export (Prometheus, JSON)
- Historical trending
- Dashboard data

Author: Dynamic Analysis Team
Date: November 11, 2025
"""

import os
import json
import time
import psutil
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from collections import defaultdict, deque
from enum import Enum


class MetricType(Enum):
    """Types of metrics."""
    COUNTER = "counter"  # Incrementing counter
    GAUGE = "gauge"  # Point-in-time value
    HISTOGRAM = "histogram"  # Distribution of values
    SUMMARY = "summary"  # Summary statistics


class HealthStatus(Enum):
    """Health check statuses."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ExecutionMetrics:
    """Metrics for a single execution."""
    file_hash: str
    user_id: Optional[str]
    start_time: float
    end_time: float
    duration_seconds: float
    success: bool
    error: Optional[str]
    crypto_calls_found: int
    events_captured: int
    peak_memory_mb: float
    cpu_percent: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class AlertConfig:
    """Alert configuration."""
    name: str
    metric: str
    threshold: float
    comparison: str  # 'gt', 'lt', 'eq'
    enabled: bool = True
    cooldown_seconds: int = 300  # 5 minutes between alerts
    
    def check(self, value: float) -> bool:
        """Check if alert should fire."""
        if not self.enabled:
            return False
        
        if self.comparison == 'gt':
            return value > self.threshold
        elif self.comparison == 'lt':
            return value < self.threshold
        elif self.comparison == 'eq':
            return value == self.threshold
        
        return False


@dataclass
class Alert:
    """Active alert."""
    name: str
    message: str
    severity: str  # 'warning', 'critical'
    timestamp: str
    value: float
    threshold: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class HealthCheck:
    """Health check result."""
    component: str
    status: HealthStatus
    message: str
    timestamp: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result['status'] = self.status.value
        return result


class MetricsCollector:
    """
    Collects and aggregates metrics for dynamic analysis.
    
    This class tracks execution metrics, resource usage, and system health.
    It provides real-time metrics, historical data, and alerting capabilities.
    
    Usage:
        # Initialize collector
        collector = MetricsCollector(workspace_dir='workspace')
        
        # Record execution
        collector.record_execution(
            file_hash='abc123',
            user_id='user1',
            duration_seconds=45.2,
            success=True,
            crypto_calls_found=8
        )
        
        # Get metrics summary
        summary = collector.get_metrics_summary()
        print(f"Success rate: {summary['success_rate']}%")
        
        # Check health
        health = collector.check_health()
        print(f"System status: {health['status']}")
    """
    
    def __init__(self, workspace_dir: str, max_history: int = 1000):
        """
        Initialize metrics collector.
        
        Args:
            workspace_dir: Base workspace directory
            max_history: Maximum number of executions to keep in memory
        """
        self.workspace_dir = Path(workspace_dir)
        self.max_history = max_history
        
        # Directories
        self.metrics_dir = self.workspace_dir / "metrics"
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        
        # Metrics storage
        self.executions_log = self.metrics_dir / "executions.jsonl"
        self.metrics_summary = self.metrics_dir / "summary.json"
        
        # In-memory metrics
        self._executions: deque = deque(maxlen=max_history)
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        
        # Alerting
        self._alerts: List[Alert] = []
        self._alert_configs: List[AlertConfig] = []
        self._last_alert_time: Dict[str, float] = {}
        
        # Thread lock
        self._lock = threading.Lock()
        
        # Initialize with default alert configs
        self._setup_default_alerts()
        
        # Load existing metrics
        self._load_metrics()
    
    def _setup_default_alerts(self):
        """Setup default alert configurations."""
        self._alert_configs = [
            AlertConfig(
                name="high_failure_rate",
                metric="failure_rate",
                threshold=0.2,  # 20%
                comparison='gt'
            ),
            AlertConfig(
                name="low_success_rate",
                metric="success_rate",
                threshold=0.8,  # 80%
                comparison='lt'
            ),
            AlertConfig(
                name="high_memory_usage",
                metric="avg_memory_mb",
                threshold=2048,  # 2 GB
                comparison='gt'
            ),
            AlertConfig(
                name="slow_execution",
                metric="avg_duration",
                threshold=300,  # 5 minutes
                comparison='gt'
            ),
            AlertConfig(
                name="quota_exceeded_rate",
                metric="quota_exceeded_rate",
                threshold=0.1,  # 10%
                comparison='gt'
            )
        ]
    
    def _load_metrics(self):
        """Load existing metrics from disk."""
        # Load recent executions
        if self.executions_log.exists():
            try:
                with open(self.executions_log, 'r') as f:
                    for line in f:
                        try:
                            exec_data = json.loads(line.strip())
                            self._executions.append(exec_data)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"[MetricsCollector] Warning: Failed to load executions log: {e}")
    
    def record_execution(
        self,
        file_hash: str,
        duration_seconds: float,
        success: bool,
        user_id: Optional[str] = None,
        crypto_calls_found: int = 0,
        events_captured: int = 0,
        peak_memory_mb: float = 0.0,
        cpu_percent: float = 0.0,
        error: Optional[str] = None
    ):
        """
        Record execution metrics.
        
        Args:
            file_hash: Hash of analyzed binary
            duration_seconds: Execution duration
            success: Whether execution succeeded
            user_id: User who ran the analysis
            crypto_calls_found: Number of crypto calls found
            events_captured: Number of events captured
            peak_memory_mb: Peak memory usage
            cpu_percent: Average CPU usage
            error: Error message if failed
        """
        with self._lock:
            metrics = ExecutionMetrics(
                file_hash=file_hash,
                user_id=user_id,
                start_time=time.time() - duration_seconds,
                end_time=time.time(),
                duration_seconds=duration_seconds,
                success=success,
                error=error,
                crypto_calls_found=crypto_calls_found,
                events_captured=events_captured,
                peak_memory_mb=peak_memory_mb,
                cpu_percent=cpu_percent
            )
            
            # Add to in-memory storage
            self._executions.append(metrics.to_dict())
            
            # Update counters
            self._counters['total_executions'] += 1
            if success:
                self._counters['successful_executions'] += 1
            else:
                self._counters['failed_executions'] += 1
            
            self._counters['total_crypto_calls'] += crypto_calls_found
            self._counters['total_events'] += events_captured
            
            # Update histograms
            self._histograms['duration_seconds'].append(duration_seconds)
            self._histograms['memory_mb'].append(peak_memory_mb)
            self._histograms['cpu_percent'].append(cpu_percent)
            
            # Append to log
            try:
                with open(self.executions_log, 'a') as f:
                    f.write(json.dumps(metrics.to_dict()) + '\n')
            except Exception as e:
                print(f"[MetricsCollector] Warning: Failed to write execution log: {e}")
            
            # Check alerts
            self._check_alerts()
    
    def increment_counter(self, name: str, value: int = 1):
        """Increment a counter."""
        with self._lock:
            self._counters[name] += value
    
    def set_gauge(self, name: str, value: float):
        """Set a gauge value."""
        with self._lock:
            self._gauges[name] = value
    
    def record_histogram_value(self, name: str, value: float):
        """Record a value in a histogram."""
        with self._lock:
            self._histograms[name].append(value)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Get metrics summary.
        
        Returns:
            Dictionary with aggregated metrics
        """
        with self._lock:
            total = self._counters.get('total_executions', 0)
            successful = self._counters.get('successful_executions', 0)
            failed = self._counters.get('failed_executions', 0)
            
            summary = {
                'timestamp': datetime.now().isoformat(),
                'executions': {
                    'total': total,
                    'successful': successful,
                    'failed': failed,
                    'success_rate': (successful / total * 100) if total > 0 else 0.0,
                    'failure_rate': (failed / total * 100) if total > 0 else 0.0
                },
                'crypto_analysis': {
                    'total_calls_found': self._counters.get('total_crypto_calls', 0),
                    'total_events_captured': self._counters.get('total_events', 0),
                    'avg_calls_per_execution': (
                        self._counters.get('total_crypto_calls', 0) / total 
                        if total > 0 else 0.0
                    )
                },
                'performance': self._get_performance_metrics(),
                'resource_usage': self._get_resource_metrics(),
                'recent_executions': list(self._executions)[-10:],  # Last 10
                'alerts': [alert.to_dict() for alert in self._alerts[-10:]]  # Last 10
            }
            
            return summary
    
    def _get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        durations = self._histograms.get('duration_seconds', [])
        
        if not durations:
            return {
                'avg_duration_seconds': 0.0,
                'min_duration_seconds': 0.0,
                'max_duration_seconds': 0.0,
                'p50_duration_seconds': 0.0,
                'p95_duration_seconds': 0.0,
                'p99_duration_seconds': 0.0
            }
        
        sorted_durations = sorted(durations)
        
        return {
            'avg_duration_seconds': sum(durations) / len(durations),
            'min_duration_seconds': min(durations),
            'max_duration_seconds': max(durations),
            'p50_duration_seconds': self._percentile(sorted_durations, 50),
            'p95_duration_seconds': self._percentile(sorted_durations, 95),
            'p99_duration_seconds': self._percentile(sorted_durations, 99)
        }
    
    def _get_resource_metrics(self) -> Dict[str, Any]:
        """Get resource usage metrics."""
        memory = self._histograms.get('memory_mb', [])
        cpu = self._histograms.get('cpu_percent', [])
        
        return {
            'avg_memory_mb': sum(memory) / len(memory) if memory else 0.0,
            'peak_memory_mb': max(memory) if memory else 0.0,
            'avg_cpu_percent': sum(cpu) / len(cpu) if cpu else 0.0,
            'peak_cpu_percent': max(cpu) if cpu else 0.0
        }
    
    def _percentile(self, sorted_values: List[float], percentile: int) -> float:
        """Calculate percentile from sorted values."""
        if not sorted_values:
            return 0.0
        
        index = int(len(sorted_values) * percentile / 100)
        index = min(index, len(sorted_values) - 1)
        
        return sorted_values[index]
    
    def _check_alerts(self):
        """Check if any alerts should fire."""
        summary = self.get_metrics_summary()
        current_time = time.time()
        
        for config in self._alert_configs:
            # Check cooldown
            last_alert = self._last_alert_time.get(config.name, 0)
            if current_time - last_alert < config.cooldown_seconds:
                continue
            
            # Extract metric value
            value = self._extract_metric_value(summary, config.metric)
            if value is None:
                continue
            
            # Check threshold
            if config.check(value):
                alert = Alert(
                    name=config.name,
                    message=f"{config.metric} {config.comparison} {config.threshold} (current: {value:.2f})",
                    severity='critical' if config.comparison == 'gt' and value > config.threshold * 1.5 else 'warning',
                    timestamp=datetime.now().isoformat(),
                    value=value,
                    threshold=config.threshold
                )
                
                self._alerts.append(alert)
                self._last_alert_time[config.name] = current_time
                
                print(f"[MetricsCollector] ALERT: {alert.message} [Severity: {alert.severity}]")
    
    def _extract_metric_value(self, summary: Dict[str, Any], metric_path: str) -> Optional[float]:
        """Extract metric value from summary using dot notation."""
        parts = metric_path.split('.')
        value = summary
        
        try:
            for part in parts:
                value = value[part]
            
            return float(value)
        except (KeyError, TypeError, ValueError):
            return None
    
    def check_health(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check.
        
        Returns:
            Dictionary with health check results
        """
        checks = []
        
        # Check Frida availability
        checks.append(self._check_frida())
        
        # Check workspace access
        checks.append(self._check_workspace())
        
        # Check system resources
        checks.append(self._check_system_resources())
        
        # Check recent execution health
        checks.append(self._check_execution_health())
        
        # Check quota system
        checks.append(self._check_quota_system())
        
        # Determine overall status
        statuses = [check.status for check in checks]
        
        if all(s == HealthStatus.HEALTHY for s in statuses):
            overall_status = HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY for s in statuses):
            overall_status = HealthStatus.UNHEALTHY
        elif any(s == HealthStatus.DEGRADED for s in statuses):
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.UNKNOWN
        
        return {
            'timestamp': datetime.now().isoformat(),
            'status': overall_status.value,
            'checks': [check.to_dict() for check in checks]
        }
    
    def _check_frida(self) -> HealthCheck:
        """Check Frida availability."""
        try:
            import frida
            version = frida.__version__
            
            return HealthCheck(
                component='frida',
                status=HealthStatus.HEALTHY,
                message=f'Frida available (version {version})',
                timestamp=datetime.now().isoformat(),
                details={'version': version}
            )
        except ImportError:
            return HealthCheck(
                component='frida',
                status=HealthStatus.UNHEALTHY,
                message='Frida not installed',
                timestamp=datetime.now().isoformat()
            )
        except Exception as e:
            return HealthCheck(
                component='frida',
                status=HealthStatus.UNHEALTHY,
                message=f'Frida error: {e}',
                timestamp=datetime.now().isoformat()
            )
    
    def _check_workspace(self) -> HealthCheck:
        """Check workspace accessibility."""
        try:
            # Check read/write access
            test_file = self.metrics_dir / '.health_check'
            test_file.write_text('test')
            test_file.unlink()
            
            return HealthCheck(
                component='workspace',
                status=HealthStatus.HEALTHY,
                message='Workspace accessible',
                timestamp=datetime.now().isoformat()
            )
        except Exception as e:
            return HealthCheck(
                component='workspace',
                status=HealthStatus.UNHEALTHY,
                message=f'Workspace error: {e}',
                timestamp=datetime.now().isoformat()
            )
    
    def _check_system_resources(self) -> HealthCheck:
        """Check system resource availability."""
        try:
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(str(self.workspace_dir))
            
            # Check thresholds
            if memory.percent > 90 or disk.percent > 90:
                status = HealthStatus.UNHEALTHY
                message = 'Critical resource usage'
            elif memory.percent > 80 or disk.percent > 80:
                status = HealthStatus.DEGRADED
                message = 'High resource usage'
            else:
                status = HealthStatus.HEALTHY
                message = 'Resources available'
            
            return HealthCheck(
                component='system_resources',
                status=status,
                message=message,
                timestamp=datetime.now().isoformat(),
                details={
                    'memory_percent': memory.percent,
                    'memory_available_gb': memory.available / 1024 / 1024 / 1024,
                    'disk_percent': disk.percent,
                    'disk_free_gb': disk.free / 1024 / 1024 / 1024
                }
            )
        except Exception as e:
            return HealthCheck(
                component='system_resources',
                status=HealthStatus.UNKNOWN,
                message=f'Resource check failed: {e}',
                timestamp=datetime.now().isoformat()
            )
    
    def _check_execution_health(self) -> HealthCheck:
        """Check recent execution health."""
        try:
            with self._lock:
                recent = list(self._executions)[-20:]  # Last 20 executions
                
                if not recent:
                    return HealthCheck(
                        component='executions',
                        status=HealthStatus.UNKNOWN,
                        message='No recent executions',
                        timestamp=datetime.now().isoformat()
                    )
                
                success_count = sum(1 for e in recent if e.get('success', False))
                success_rate = success_count / len(recent)
                
                if success_rate >= 0.95:
                    status = HealthStatus.HEALTHY
                    message = f'High success rate ({success_rate:.1%})'
                elif success_rate >= 0.8:
                    status = HealthStatus.DEGRADED
                    message = f'Moderate success rate ({success_rate:.1%})'
                else:
                    status = HealthStatus.UNHEALTHY
                    message = f'Low success rate ({success_rate:.1%})'
                
                return HealthCheck(
                    component='executions',
                    status=status,
                    message=message,
                    timestamp=datetime.now().isoformat(),
                    details={
                        'recent_executions': len(recent),
                        'success_rate': success_rate,
                        'success_count': success_count,
                        'failure_count': len(recent) - success_count
                    }
                )
        except Exception as e:
            return HealthCheck(
                component='executions',
                status=HealthStatus.UNKNOWN,
                message=f'Execution check failed: {e}',
                timestamp=datetime.now().isoformat()
            )
    
    def _check_quota_system(self) -> HealthCheck:
        """Check quota system health."""
        try:
            quota_dir = self.workspace_dir / "quotas"
            
            if not quota_dir.exists():
                return HealthCheck(
                    component='quota_system',
                    status=HealthStatus.HEALTHY,
                    message='Quota system not initialized',
                    timestamp=datetime.now().isoformat()
                )
            
            return HealthCheck(
                component='quota_system',
                status=HealthStatus.HEALTHY,
                message='Quota system operational',
                timestamp=datetime.now().isoformat()
            )
        except Exception as e:
            return HealthCheck(
                component='quota_system',
                status=HealthStatus.DEGRADED,
                message=f'Quota check warning: {e}',
                timestamp=datetime.now().isoformat()
            )
    
    def export_prometheus(self) -> str:
        """
        Export metrics in Prometheus format.
        
        Returns:
            Prometheus-formatted metrics string
        """
        with self._lock:
            lines = []
            
            # Counters
            for name, value in self._counters.items():
                lines.append(f"# TYPE dynamic_analysis_{name} counter")
                lines.append(f"dynamic_analysis_{name} {value}")
            
            # Gauges
            for name, value in self._gauges.items():
                lines.append(f"# TYPE dynamic_analysis_{name} gauge")
                lines.append(f"dynamic_analysis_{name} {value}")
            
            # Summary statistics
            summary = self.get_metrics_summary()
            
            lines.append(f"# TYPE dynamic_analysis_success_rate gauge")
            lines.append(f"dynamic_analysis_success_rate {summary['executions']['success_rate'] / 100}")
            
            lines.append(f"# TYPE dynamic_analysis_avg_duration_seconds gauge")
            lines.append(f"dynamic_analysis_avg_duration_seconds {summary['performance']['avg_duration_seconds']}")
            
            lines.append(f"# TYPE dynamic_analysis_avg_memory_mb gauge")
            lines.append(f"dynamic_analysis_avg_memory_mb {summary['resource_usage']['avg_memory_mb']}")
            
            return '\n'.join(lines)
    
    def save_summary(self):
        """Save metrics summary to file."""
        summary = self.get_metrics_summary()
        
        try:
            with open(self.metrics_summary, 'w') as f:
                json.dump(summary, f, indent=2)
        except Exception as e:
            print(f"[MetricsCollector] Warning: Failed to save summary: {e}")
