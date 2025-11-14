# Dynamic Analysis Operations Manual

**Version:** 1.0  
**Last Updated:** 2025-11-11  
**Status:** Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Installation & Setup](#installation--setup)
4. [Configuration Reference](#configuration-reference)
5. [Operations Guide](#operations-guide)
6. [Monitoring & Observability](#monitoring--observability)
7. [Performance Optimization](#performance-optimization)
8. [Security Operations](#security-operations)
9. [Troubleshooting Runbook](#troubleshooting-runbook)
10. [Maintenance Procedures](#maintenance-procedures)
11. [Disaster Recovery](#disaster-recovery)
12. [API Reference](#api-reference)

---

## Overview

### Purpose

This manual provides comprehensive operational guidance for deploying, configuring, monitoring, and maintaining the dynamic analysis system for cryptographic function detection in blockchain binaries.

### System Capabilities

- **Dynamic instrumentation** of Windows PE and Linux ELF binaries using Frida
- **Cryptographic API hooking** for Windows Crypto API (bcrypt.dll, crypt32.dll) and OpenSSL
- **Memory scanning** for cryptographic constants (S-boxes, round constants)
- **Call graph analysis** for function relationships
- **Automated trace analysis** with machine learning-based classification
- **Batch processing** for multiple binaries
- **Local-only operation** with no cloud dependencies

### Target Audience

- System administrators deploying the analysis infrastructure
- Operations engineers maintaining production systems
- Security analysts using the system for analysis
- Developers integrating with the system

---

## System Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Web UI (Streamlit)                      │
│              (file upload, config, results)                 │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────┴────────────────────────────────────┐
│                   Dynamic Analysis Runner                   │
│              (orchestration, pipeline control)              │
└┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬──┘
 │      │      │      │      │      │      │      │      │
 ▼      ▼      ▼      ▼      ▼      ▼      ▼      ▼      ▼
┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐
│Quo ││Sec ││Fri ││Scr ││Tra ││San ││Res ││Ret ││Met ││Per │
│ta  ││uri ││da  ││ipt ││ce  ││iti ││ili ││ent ││ric ││f   │
│Mgr ││ty  ││Har ││Gen ││Mgr ││zer ││ence││ion ││s   ││orm │
└────┘└────┘└────┘└────┘└────┘└────┘└────┘└────┘└────┘└────┘

┌─────────────────────────────────────────────────────────────┐
│                   Local Storage Layer                        │
│  (workspace/, quotas/, metrics/, audit/, checkpoints/)      │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Ingestion**: Binary uploaded via UI or API
2. **Validation**: Security checks, quota verification
3. **Analysis**: Frida instrumentation and trace collection
4. **Processing**: Sanitization, classification, packaging
5. **Storage**: Local file system storage with retention policies
6. **Monitoring**: Metrics collection and health checks

### Storage Layout

```
workspace/
├── analysis/
│   └── dynamic/
│       └── {file_hash}/
│           ├── result.json          # Analysis results
│           ├── trace_raw.json       # Raw Frida traces
│           ├── trace_sanitized.json # Sanitized traces
│           └── metadata.json        # Analysis metadata
├── quotas/
│   └── {user_id}.json              # User quota tracking
├── metrics/
│   ├── execution_metrics.jsonl     # Per-execution metrics
│   └── health_checks.jsonl         # System health data
├── audit/
│   └── security_audit.jsonl        # Security events
├── checkpoints/
│   └── {file_hash}.json            # Resume checkpoints
└── profiling/
    └── profiling_{timestamp}.jsonl  # Performance profiles
```

---

## Installation & Setup

### Prerequisites

**Required:**

- Python 3.8+
- Frida 16.0+ (`pip install frida frida-tools`)
- Windows (for PE analysis) or Linux (for ELF analysis)
- 4GB RAM minimum, 8GB recommended
- 10GB free disk space

**Optional:**

- psutil (`pip install psutil`) for resource monitoring
- Prometheus for metrics export

### Installation Steps

1. **Clone repository:**

   ```powershell
   git clone <repository-url>
   cd Identifying-Cryptographic-Function-in-Blockchain
   ```

2. **Install Python dependencies:**

   ```powershell
   pip install -r requirements.txt
   ```

3. **Install Frida:**

   ```powershell
   pip install frida frida-tools
   ```

4. **Verify installation:**

   ```powershell
   python -c "import frida; print(f'Frida {frida.__version__}')"
   ```

5. **Create workspace directory:**

   ```powershell
   mkdir workspace
   mkdir workspace\analysis\dynamic
   mkdir workspace\quotas
   mkdir workspace\metrics
   mkdir workspace\audit
   mkdir workspace\checkpoints
   mkdir workspace\profiling
   ```

6. **Run tests:**

   ```powershell
   pytest tests/test_ghidra_pipeline.py -v
   ```

7. **Start UI:**
   ```powershell
   streamlit run src/app.py
   ```

### Initial Configuration

1. **Create config file** (`config/dynamic_analysis.json`):

   ```json
   {
     "timeout_seconds": 500,
     "mode": "spawn",
     "sandbox_enabled": true,
     "quota_enabled": true,
     "profiling_enabled": true,
     "streaming_threshold_mb": 10.0,
     "max_workers": 4
   }
   ```

2. **Set environment variables** (optional):

   ```powershell
   $env:DYNAMIC_TIMEOUT = "500"
   $env:DYNAMIC_MODE = "spawn"
   $env:DYNAMIC_QUOTA_ENABLED = "true"
   ```

3. **Verify setup:**
   ```powershell
   python -m src.auditor.detectors.dynamic_detection.runner --help
   ```

---

## Configuration Reference

### Core Configuration

| Parameter              | Type   | Default | Description                       |
| ---------------------- | ------ | ------- | --------------------------------- |
| `timeout_seconds`      | int    | 500     | Maximum analysis time per binary  |
| `mode`                 | string | "spawn" | Frida mode: "spawn" or "attach"   |
| `sandbox_enabled`      | bool   | true    | Enable sandboxing for safety      |
| `input_feeder_enabled` | bool   | false   | Enable automated input generation |
| `cache_ttl_hours`      | int    | 24      | Cache time-to-live in hours       |

### Quota Configuration

| Parameter                       | Type | Default | Description                      |
| ------------------------------- | ---- | ------- | -------------------------------- |
| `executions_per_day`            | int  | 100     | Daily execution limit per user   |
| `executions_per_week`           | int  | 500     | Weekly execution limit per user  |
| `executions_per_month`          | int  | 2000    | Monthly execution limit per user |
| `executions_per_binary_per_day` | int  | 5       | Per-binary daily limit           |
| `max_concurrent_executions`     | int  | 3       | Concurrent execution limit       |
| `max_storage_per_user_mb`       | int  | 10240   | Storage quota per user (MB)      |
| `enable_grace_period`           | bool | true    | Allow grace period after limit   |
| `grace_period_minutes`          | int  | 30      | Grace period duration (minutes)  |

### Retention Configuration

| Parameter                | Type | Default | Description                |
| ------------------------ | ---- | ------- | -------------------------- |
| `default_retention_days` | int  | 30      | Default retention period   |
| `compress_after_days`    | int  | 7       | Compress traces after days |
| `enable_auto_cleanup`    | bool | true    | Enable automated cleanup   |
| `cleanup_schedule_hour`  | int  | 2       | Daily cleanup hour (UTC)   |

### Monitoring Configuration

| Parameter               | Type   | Default | Description                           |
| ----------------------- | ------ | ------- | ------------------------------------- |
| `enable_metrics`        | bool   | true    | Enable metrics collection             |
| `enable_health_checks`  | bool   | true    | Enable health monitoring              |
| `metrics_export_format` | string | "json"  | Export format: "json" or "prometheus" |
| `alert_on_failure`      | bool   | false   | Enable alerting                       |

### Security Configuration

| Parameter                  | Type | Default | Description                  |
| -------------------------- | ---- | ------- | ---------------------------- |
| `enable_binary_validation` | bool | true    | Validate binaries before run |
| `max_binary_size_mb`       | int  | 500     | Maximum binary size (MB)     |
| `enable_secrets_redaction` | bool | true    | Redact secrets from traces   |
| `enable_audit_logging`     | bool | true    | Log security events          |

### Performance Configuration

| Parameter                | Type  | Default | Description                       |
| ------------------------ | ----- | ------- | --------------------------------- |
| `enable_profiling`       | bool  | true    | Enable performance profiling      |
| `max_workers`            | int   | 4       | Parallel processing workers       |
| `streaming_threshold_mb` | float | 10.0    | File size threshold for streaming |
| `enable_process_pool`    | bool  | false   | Use process pool vs thread pool   |

---

## Operations Guide

### Starting the System

**UI Mode (Recommended):**

```powershell
streamlit run src/app.py --server.port 8501
```

**CLI Mode:**

```powershell
python -m src.auditor.detectors.dynamic_detection.runner \
  --binary path/to/binary.exe \
  --mode spawn \
  --timeout 500
```

**Batch Mode:**

```python
from src.auditor.detectors.dynamic_detection import runner

# Analyze multiple binaries
binaries = ["binary1.exe", "binary2.exe", "binary3.exe"]
results = runner.analyze_batch(binaries)
```

### Stopping the System

**Graceful Shutdown:**

```powershell
# UI: Press Ctrl+C in terminal
# CLI: Press Ctrl+C
# API: Call /api/shutdown endpoint
```

**Emergency Stop:**

```powershell
# Kill all Frida processes
taskkill /F /IM frida-server.exe
# Kill Python processes
taskkill /F /IM python.exe
```

### Daily Operations

**Morning Checklist:**

1. Check system health: `python -m src.auditor.detectors.dynamic_detection.health_check`
2. Review overnight analysis results
3. Check disk space: `Get-Volume`
4. Review error logs: `workspace/logs/error.log`

**Daily Tasks:**

1. Monitor quota usage
2. Review security audit logs
3. Check performance metrics
4. Validate backup completion

**Weekly Tasks:**

1. Review and optimize retention policies
2. Analyze performance reports
3. Update Frida to latest version
4. Review and archive old analyses

**Monthly Tasks:**

1. Audit quota allocations
2. Performance tuning based on metrics
3. Security review (check audit logs)
4. Capacity planning

### User Management

**Create User:**

```python
from src.auditor.detectors.dynamic_detection.quota_manager import QuotaManager

qm = QuotaManager("workspace")
qm.create_user("user123", custom_limits={
    "executions_per_day": 200,
    "max_storage_mb": 20480
})
```

**Grant Admin Override:**

```python
qm.grant_admin_override("user123", duration_hours=24)
```

**Check User Quota:**

```python
usage = qm.get_user_usage("user123")
print(f"Daily: {usage['executions_today']}/100")
print(f"Storage: {usage['storage_used_mb']}MB")
```

**Reset User Quota:**

```python
qm.reset_user_quota("user123", period="daily")
```

---

## Monitoring & Observability

### Health Checks

**System Health Check:**

```python
from src.auditor.detectors.dynamic_detection.metrics_collector import MetricsCollector

mc = MetricsCollector("workspace")
health = mc.check_health()

print(f"Overall Health: {health['overall_health']}")
print(f"Frida: {health['frida_available']}")
print(f"Disk Space: {health['disk_space_mb']} MB free")
print(f"Workspace: {health['workspace_writable']}")
```

**Component Status:**

```python
status = mc.get_component_status()
for component, info in status.items():
    print(f"{component}: {info['status']} ({info['message']})")
```

### Metrics Collection

**Execution Metrics:**

- **Duration**: Time taken for each analysis stage
- **Success Rate**: Percentage of successful analyses
- **Error Rate**: Percentage of failed analyses
- **Resource Usage**: CPU, memory, disk usage

**View Recent Metrics:**

```python
metrics = mc.get_recent_metrics(hours=24)
print(f"Total Analyses: {metrics['total_analyses']}")
print(f"Avg Duration: {metrics['avg_duration_seconds']}s")
print(f"Success Rate: {metrics['success_rate']}%")
```

### Alerting

**Configure Alerts:**

```python
mc.configure_alert(
    alert_type="high_error_rate",
    threshold=0.1,  # 10% error rate
    action="email",  # or "webhook", "log"
    recipients=["admin@example.com"]
)
```

**Alert Types:**

- `high_error_rate`: Error rate exceeds threshold
- `disk_space_low`: Disk space below threshold
- `quota_exceeded`: User exceeds quota
- `long_execution`: Analysis exceeds timeout

### Prometheus Export

**Enable Prometheus:**

```python
mc.export_metrics_prometheus(
    output_file="workspace/metrics/prometheus.txt",
    include_custom_labels=True
)
```

**Prometheus Metrics:**

```
# TYPE dynamic_analysis_total counter
dynamic_analysis_total{status="success"} 1234

# TYPE dynamic_analysis_duration_seconds histogram
dynamic_analysis_duration_seconds_sum 45678.9
dynamic_analysis_duration_seconds_count 1234

# TYPE dynamic_analysis_active_executions gauge
dynamic_analysis_active_executions 3
```

### Dashboards

**Key Metrics Dashboard:**

1. Total analyses (last 24h)
2. Success rate (last 24h)
3. Average duration
4. Active executions
5. Disk space usage
6. Top error types

**Performance Dashboard:**

1. P50, P95, P99 latencies
2. Throughput (analyses/hour)
3. Resource utilization
4. Queue depth

---

## Performance Optimization

### Profiling

**Enable Profiling:**

```python
from src.auditor.detectors.dynamic_detection.performance import PerformanceOptimizer

optimizer = PerformanceOptimizer(
    workspace_root="workspace",
    enable_profiling=True,
    max_workers=4
)

# Profile an operation
with optimizer.profile("frida_spawn"):
    # Your code here
    pass
```

**Generate Performance Report:**

```python
report = optimizer.generate_report("workspace/performance_report.json")
print(f"Avg Duration: {report['summary']['avg_duration_ms']} ms")
print(f"Operations/sec: {report['summary']['operations_per_second']}")
```

### Optimization Recommendations

**Get Recommendations:**

```python
recommendations = optimizer.get_recommendations()
for rec in recommendations:
    print(f"[{rec.category}] {rec.title}")
    print(f"  Impact: {rec.impact}, Effort: {rec.effort}")
    print(f"  Current: {rec.current_value} → Recommended: {rec.recommended_value}")
    print(f"  Improvement: {rec.estimated_improvement}")
```

**Common Optimizations:**

1. **Increase Worker Count:**

   - When: CPU utilization < 50%
   - Action: Increase `max_workers` to CPU count
   - Impact: 30-50% throughput improvement

2. **Enable Process Pool:**

   - When: Avg duration > 1000ms
   - Action: Set `enable_process_pool = True`
   - Impact: 30-50% faster for CPU-bound tasks

3. **Lower Streaming Threshold:**

   - When: Memory usage > 500MB
   - Action: Reduce `streaming_threshold_mb` to 5
   - Impact: 50-70% memory reduction

4. **Disable Profiling:**
   - When: High-volume operations (>10k/day)
   - Action: Set `enable_profiling = False`
   - Impact: 5-10% performance improvement

### Parallel Processing

**Batch Processing:**

```python
def analyze_binary(binary_path):
    # Analysis logic
    return result

binaries = ["bin1.exe", "bin2.exe", "bin3.exe"]
results = optimizer.parallel_process_batch(
    items=binaries,
    process_func=analyze_binary,
    operation_name="batch_analysis"
)
```

### Streaming Large Traces

**Stream Trace File:**

```python
trace_file = Path("workspace/analysis/dynamic/abc123/trace_raw.json")

for chunk in optimizer.stream_trace_file(trace_file, chunk_size=1000):
    # Process chunk of events
    process_events(chunk)
```

---

## Security Operations

### Binary Validation

**Validate Before Analysis:**

```python
from src.auditor.detectors.dynamic_detection.security import SecurityHardening

security = SecurityHardening("workspace")

validation = security.validate_binary("binary.exe")
if not validation.is_valid:
    print(f"Validation failed: {validation.error_message}")
    print(f"Warnings: {validation.warnings}")
else:
    print(f"Binary OK - Hash: {validation.file_hash}")
```

**Validation Checks:**

1. File existence and permissions
2. File type (PE, ELF, Mach-O)
3. Size limits (max 500MB)
4. Extension blocking (dangerous extensions)
5. Hash calculation (SHA256)
6. Dangerous pattern detection

### Secrets Redaction

**Redact Secrets from Traces:**

```python
trace_data = load_trace("trace.json")
sanitized = security.redact_secrets(trace_data)
# All secrets (API keys, passwords, tokens) are redacted
```

**Redacted Patterns:**

- API keys (20+ char alphanumeric)
- Private keys (PEM format)
- Passwords (`password=`, `pwd=`)
- Bearer tokens
- Connection strings
- AWS keys
- Email addresses

### Audit Logging

**View Security Events:**

```python
# Get recent events
events = security.get_recent_security_events(hours=24)
for event in events:
    print(f"{event['timestamp']} [{event['severity']}] {event['event_type']}")
    print(f"  User: {event['user_id']}, File: {event['file_hash']}")
```

**Audit Summary:**

```python
summary = security.get_audit_summary(days=7)
print(f"Total Events: {summary['total_events']}")
print(f"Critical: {summary['by_severity']['critical']}")
print(f"Warnings: {summary['by_severity']['warning']}")
```

### Security Best Practices

1. **Always validate binaries** before analysis
2. **Enable secrets redaction** in production
3. **Review audit logs** regularly
4. **Limit quota** for untrusted users
5. **Run in sandbox mode** for unknown binaries
6. **Keep Frida updated** to latest version
7. **Monitor for escape attempts** in logs
8. **Restrict file system access** via sandbox

---

## Troubleshooting Runbook

### Common Issues

#### Issue: Frida Not Found

**Symptoms:**

```
ModuleNotFoundError: No module named 'frida'
```

**Diagnosis:**

```powershell
pip list | findstr frida
```

**Resolution:**

```powershell
pip install frida frida-tools
python -c "import frida; print(frida.__version__)"
```

---

#### Issue: Analysis Timeout

**Symptoms:**

```
Analysis timed out after 500 seconds
```

**Diagnosis:**

1. Check binary complexity
2. Review Frida logs
3. Check system resources

**Resolution:**

1. Increase timeout: `timeout_seconds = 1000`
2. Reduce instrumentation scope
3. Enable streaming mode
4. Use attach mode instead of spawn

---

#### Issue: High Memory Usage

**Symptoms:**

```
MemoryError: Unable to allocate memory
```

**Diagnosis:**

```python
import psutil
print(f"Memory: {psutil.virtual_memory().percent}%")
```

**Resolution:**

1. Lower streaming threshold: `streaming_threshold_mb = 5`
2. Reduce chunk size
3. Enable compression: `compress_after_days = 1`
4. Clear old traces: Run retention cleanup

---

#### Issue: Quota Exceeded

**Symptoms:**

```
QuotaExceededError: Daily execution limit reached (100/100)
```

**Diagnosis:**

```python
qm = QuotaManager("workspace")
usage = qm.get_user_usage("user123")
```

**Resolution:**

1. Grant admin override: `qm.grant_admin_override("user123")`
2. Increase quota: Modify `config/quotas.json`
3. Reset quota: `qm.reset_user_quota("user123", "daily")`

---

#### Issue: Binary Validation Failed

**Symptoms:**

```
SecurityValidationError: Dangerous patterns detected
```

**Diagnosis:**

```python
validation = security.validate_binary("binary.exe")
print(validation.warnings)
```

**Resolution:**

1. Review warnings
2. Verify binary source
3. Run in sandbox mode
4. Skip validation (not recommended): `skip_validation=True`

---

### Debug Mode

**Enable Debug Logging:**

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

**Frida Debug:**

```python
import frida
frida.get_device_manager().add_remote_device("127.0.0.1")  # Debug remote
```

### Log Files

**Location:**

- `workspace/logs/runner.log` - Main orchestration logs
- `workspace/logs/frida.log` - Frida instrumentation logs
- `workspace/audit/security_audit.jsonl` - Security events
- `workspace/metrics/execution_metrics.jsonl` - Performance data

---

## Maintenance Procedures

### Data Cleanup

**Manual Cleanup:**

```python
from src.auditor.detectors.dynamic_detection.retention_manager import RetentionManager

rm = RetentionManager("workspace")

# Cleanup old analyses
removed = rm.cleanup_old_traces(days=30)
print(f"Removed {removed} old traces")

# Compress large traces
compressed = rm.compress_large_traces()
print(f"Compressed {compressed} traces")
```

**Automated Cleanup:**

```python
# Schedule daily cleanup
rm.schedule_cleanup(
    cleanup_age_days=30,
    compress_age_days=7,
    schedule_hour=2  # 2 AM UTC
)
```

### Backup Procedures

**Backup Workspace:**

```powershell
# Full backup
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Compress-Archive -Path workspace\* -DestinationPath "backup_$timestamp.zip"

# Backup only results
Compress-Archive -Path workspace\analysis\* -DestinationPath "results_$timestamp.zip"
```

**Restore from Backup:**

```powershell
Expand-Archive -Path backup_20251111_020000.zip -DestinationPath workspace\
```

### Quota Reset

**Manual Reset:**

```python
qm = QuotaManager("workspace")
qm.reset_all_daily_quotas()  # Reset daily quotas
qm.reset_all_weekly_quotas()  # Reset weekly quotas
qm.reset_all_monthly_quotas()  # Reset monthly quotas
```

**Scheduled Reset:**

- Daily reset: Midnight UTC
- Weekly reset: Monday 00:00 UTC
- Monthly reset: 1st day 00:00 UTC

### Updates

**Update Frida:**

```powershell
pip install --upgrade frida frida-tools
```

**Update Dependencies:**

```powershell
pip install --upgrade -r requirements.txt
```

**Verify Updates:**

```powershell
pytest tests/ -v
```

---

## Disaster Recovery

### Recovery Procedures

**Scenario: Workspace Corruption**

1. **Stop all services:**

   ```powershell
   taskkill /F /IM python.exe
   ```

2. **Restore from backup:**

   ```powershell
   Remove-Item workspace\* -Recurse -Force
   Expand-Archive -Path backup_latest.zip -DestinationPath workspace\
   ```

3. **Verify integrity:**

   ```python
   # Check workspace structure
   assert Path("workspace/analysis").exists()
   assert Path("workspace/quotas").exists()
   ```

4. **Restart services:**
   ```powershell
   streamlit run src/app.py
   ```

---

**Scenario: Quota Database Corruption**

1. **Backup current state:**

   ```powershell
   Copy-Item workspace\quotas\* backup\quotas\
   ```

2. **Reset quotas:**

   ```python
   qm = QuotaManager("workspace")
   qm.reset_all_quotas()
   ```

3. **Restore from backup (if needed):**
   ```powershell
   Copy-Item backup\quotas\* workspace\quotas\
   ```

---

**Scenario: Frida Process Hang**

1. **Kill Frida processes:**

   ```powershell
   Get-Process | Where-Object {$_.Name -like "*frida*"} | Stop-Process -Force
   ```

2. **Clean up checkpoints:**

   ```python
   rm = ResilienceManager("workspace")
   rm.cleanup_old_checkpoints(hours=1)
   ```

3. **Resume analysis:**
   ```python
   # Load checkpoint and resume
   checkpoint = rm.load_checkpoint(file_hash)
   result = runner.resume_from_checkpoint(checkpoint)
   ```

---

## API Reference

### Runner API

```python
from src.auditor.detectors.dynamic_detection.runner import DynamicDetectionRunner

runner = DynamicDetectionRunner()

# Single analysis
result = runner.run(
    binary_path="binary.exe",
    mode="spawn",
    timeout_seconds=500
)

# Batch analysis
results = runner.run_batch(
    binary_paths=["bin1.exe", "bin2.exe"],
    max_workers=4
)
```

### Quota API

```python
from src.auditor.detectors.dynamic_detection.quota_manager import QuotaManager

qm = QuotaManager("workspace")

# Check quota
can_run, reason = qm.check_quota("user123", "binary.exe")

# Track execution
with qm.track_execution("user123", "binary.exe"):
    # Run analysis
    pass
```

### Metrics API

```python
from src.auditor.detectors.dynamic_detection.metrics_collector import MetricsCollector

mc = MetricsCollector("workspace")

# Record metrics
mc.record_execution(
    file_hash="abc123",
    duration_seconds=45.2,
    success=True
)

# Get metrics
metrics = mc.get_metrics(hours=24)
```

### Security API

```python
from src.auditor.detectors.dynamic_detection.security import SecurityHardening

security = SecurityHardening("workspace")

# Validate binary
validation = security.validate_binary("binary.exe")

# Redact secrets
clean_data = security.redact_secrets(trace_data)

# Log security event
security.log_security_event(
    event_type="validation_failed",
    severity="warning",
    details={"reason": "size_exceeded"}
)
```

### Performance API

```python
from src.auditor.detectors.dynamic_detection.performance import PerformanceOptimizer

optimizer = PerformanceOptimizer("workspace")

# Profile operation
with optimizer.profile("operation_name"):
    # Code to profile
    pass

# Get recommendations
recommendations = optimizer.get_recommendations()

# Generate report
report = optimizer.generate_report("report.json")
```

---

## Appendix

### Error Codes

| Code | Category | Description                 |
| ---- | -------- | --------------------------- |
| 1001 | Quota    | Daily limit exceeded        |
| 1002 | Quota    | Storage limit exceeded      |
| 2001 | Security | Validation failed           |
| 2002 | Security | Dangerous patterns detected |
| 3001 | Frida    | Process spawn failed        |
| 3002 | Frida    | Attach failed               |
| 4001 | Timeout  | Analysis timeout            |
| 4002 | Timeout  | Frida hang detected         |

### Support Contacts

- **Technical Issues**: <technical-support@example.com>
- **Security Issues**: <security@example.com>
- **Operations**: <ops@example.com>

### Related Documentation

- [Design Documentation](dynamic_analysis_design.md)
- [Progress Tracking](dynamic_analysis_progress.md)
- [Troubleshooting Guide](TROUBLESHOOTING_GUIDE.md)
- [Local-Only Architecture](PHASE_8_LOCAL_ONLY.md)

---

**End of Operations Manual**
