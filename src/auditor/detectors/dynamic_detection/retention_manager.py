"""
Retention management system for dynamic analysis results.

This module implements automatic cleanup and retention policies for analysis
results, traces, and cached data. It helps manage storage costs and ensures
old data is properly archived or removed based on configurable policies.

Features:
- Age-based cleanup (7 days, 30 days, 90 days)
- Selective retention (keep important results longer)
- Automatic trace archival with compression
- Scheduled cleanup jobs
- Retention policy enforcement
- Cleanup audit logging

Author: Dynamic Analysis Team
Date: November 11, 2025
"""

import os
import json
import gzip
import shutil
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import threading


class RetentionPeriod(Enum):
    """Standard retention periods."""
    SHORT = 7  # 7 days for incomplete/failed results
    MEDIUM = 30  # 30 days for normal results
    LONG = 90  # 90 days for high-confidence findings
    ARCHIVE = 365  # 1 year for archived results


@dataclass
class RetentionConfig:
    """Configuration for retention policies."""
    default_retention_days: int = 30
    incomplete_results_retention_days: int = 7
    high_confidence_retention_days: int = 90
    compression_after_days: int = 14
    cleanup_schedule: str = "daily_at_2am"  # Cron-like schedule
    enable_compression: bool = True
    min_free_space_gb: float = 10.0  # Trigger cleanup if space low
    max_total_size_gb: float = 100.0  # Maximum total storage
    preserve_patterns: List[str] = None  # Glob patterns to never delete
    
    def __post_init__(self):
        if self.preserve_patterns is None:
            self.preserve_patterns = []


@dataclass
class CleanupAuditEntry:
    """Audit log entry for cleanup operations."""
    timestamp: str
    action: str  # 'delete', 'compress', 'archive'
    file_path: str
    file_hash: str
    age_days: int
    size_bytes: int
    reason: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class RetentionManager:
    """
    Manages retention policies and cleanup for analysis results.
    
    This class implements automatic cleanup of old traces and results
    based on configurable retention periods. It can compress old files,
    archive important results, and enforce storage limits.
    
    Usage:
        # Initialize manager
        manager = RetentionManager(workspace_dir='workspace')
        
        # Run cleanup
        stats = manager.run_cleanup()
        print(f"Deleted {stats['files_deleted']} files")
        
        # Compress old traces
        manager.compress_old_traces(days=14)
        
        # Get retention report
        report = manager.get_retention_report()
    """
    
    def __init__(self, workspace_dir: str, config: RetentionConfig = None):
        """
        Initialize retention manager.
        
        Args:
            workspace_dir: Base workspace directory
            config: Retention configuration (uses defaults if None)
        """
        self.workspace_dir = Path(workspace_dir)
        self.config = config or RetentionConfig()
        
        # Directories to manage
        self.analysis_dir = self.workspace_dir / "analysis" / "dynamic"
        self.retention_dir = self.workspace_dir / "retention"
        self.retention_dir.mkdir(parents=True, exist_ok=True)
        
        # Audit log
        self.audit_log_path = self.retention_dir / "cleanup_audit.jsonl"
        
        # Thread lock
        self._lock = threading.Lock()
        
        # Save config
        self._save_config()
    
    def _save_config(self):
        """Save retention configuration."""
        config_path = self.retention_dir / "config.json"
        
        with open(config_path, 'w') as f:
            json.dump(asdict(self.config), f, indent=2)
    
    def _log_audit(self, entry: CleanupAuditEntry):
        """Append entry to audit log."""
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(entry.to_dict()) + '\n')
        except Exception as e:
            print(f"Warning: Failed to write audit log: {e}")
    
    def _get_file_age_days(self, file_path: Path) -> int:
        """Get file age in days."""
        if not file_path.exists():
            return 0
        
        mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
        age = datetime.now() - mtime
        return age.days
    
    def _should_preserve(self, file_path: Path) -> bool:
        """Check if file matches preserve patterns."""
        file_str = str(file_path)
        
        for pattern in self.config.preserve_patterns:
            if file_path.match(pattern):
                return True
        
        return False
    
    def _get_result_metadata(self, result_path: Path) -> Optional[Dict[str, Any]]:
        """Load result metadata from results.json."""
        try:
            with open(result_path, 'r') as f:
                data = json.load(f)
            return data
        except Exception:
            return None
    
    def _determine_retention_period(self, result_dir: Path) -> int:
        """
        Determine retention period for a result based on its content.
        
        Args:
            result_dir: Path to analysis result directory
        
        Returns:
            Retention period in days
        """
        result_path = result_dir / "dynamic_results.json"
        
        if not result_path.exists():
            return self.config.default_retention_days
        
        metadata = self._get_result_metadata(result_path)
        
        if not metadata:
            return self.config.default_retention_days
        
        # Incomplete results get short retention
        if metadata.get('incomplete', False):
            return self.config.incomplete_results_retention_days
        
        # Check for high-confidence findings
        summary = metadata.get('summary', {})
        crypto_calls = summary.get('crypto_calls', 0)
        
        if crypto_calls > 10:  # Significant crypto usage
            return self.config.high_confidence_retention_days
        
        return self.config.default_retention_days
    
    def run_cleanup(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Run cleanup based on retention policies.
        
        Args:
            dry_run: If True, report what would be deleted without deleting
        
        Returns:
            Dictionary with cleanup statistics
        """
        with self._lock:
            print("[RetentionManager] Starting cleanup...")
            
            stats = {
                'files_scanned': 0,
                'files_deleted': 0,
                'files_compressed': 0,
                'files_preserved': 0,
                'bytes_freed': 0,
                'bytes_compressed': 0,
                'errors': []
            }
            
            if not self.analysis_dir.exists():
                print("[RetentionManager] Analysis directory does not exist")
                return stats
            
            # Iterate through all result directories
            for result_dir in self.analysis_dir.iterdir():
                if not result_dir.is_dir():
                    continue
                
                file_hash = result_dir.name
                stats['files_scanned'] += 1
                
                # Check if should preserve
                if self._should_preserve(result_dir):
                    stats['files_preserved'] += 1
                    continue
                
                # Get age
                result_file = result_dir / "dynamic_results.json"
                age_days = self._get_file_age_days(result_file)
                
                # Determine retention period
                retention_days = self._determine_retention_period(result_dir)
                
                # Check if should delete
                if age_days > retention_days:
                    print(f"[RetentionManager] Deleting {file_hash} (age: {age_days} days, retention: {retention_days} days)")
                    
                    if not dry_run:
                        try:
                            # Calculate size before deletion
                            total_size = sum(
                                f.stat().st_size 
                                for f in result_dir.rglob('*') 
                                if f.is_file()
                            )
                            
                            # Delete directory
                            shutil.rmtree(result_dir)
                            
                            stats['files_deleted'] += 1
                            stats['bytes_freed'] += total_size
                            
                            # Log audit
                            self._log_audit(CleanupAuditEntry(
                                timestamp=datetime.now().isoformat(),
                                action='delete',
                                file_path=str(result_dir),
                                file_hash=file_hash,
                                age_days=age_days,
                                size_bytes=total_size,
                                reason=f'exceeded_retention_{retention_days}d'
                            ))
                            
                        except Exception as e:
                            error_msg = f"Failed to delete {file_hash}: {e}"
                            print(f"[RetentionManager] Error: {error_msg}")
                            stats['errors'].append(error_msg)
                    
                    else:
                        print(f"[RetentionManager] Would delete {file_hash} (dry run)")
                
                # Check if should compress (not yet deleted)
                elif age_days > self.config.compression_after_days and self.config.enable_compression:
                    compressed = self._compress_traces(result_dir, dry_run)
                    if compressed:
                        stats['files_compressed'] += compressed['count']
                        stats['bytes_compressed'] += compressed['bytes_saved']
            
            print(f"[RetentionManager] Cleanup complete:")
            print(f"  Scanned: {stats['files_scanned']}")
            print(f"  Deleted: {stats['files_deleted']}")
            print(f"  Compressed: {stats['files_compressed']}")
            print(f"  Preserved: {stats['files_preserved']}")
            print(f"  Freed: {stats['bytes_freed'] / 1024 / 1024:.1f} MB")
            print(f"  Errors: {len(stats['errors'])}")
            
            return stats
    
    def _compress_traces(self, result_dir: Path, dry_run: bool = False) -> Optional[Dict[str, Any]]:
        """
        Compress trace files in result directory.
        
        Args:
            result_dir: Path to result directory
            dry_run: If True, report without compressing
        
        Returns:
            Dictionary with compression statistics or None
        """
        trace_path = result_dir / "trace.ndjson"
        
        if not trace_path.exists():
            return None
        
        # Check if already compressed
        compressed_path = result_dir / "trace.ndjson.gz"
        if compressed_path.exists():
            return None
        
        original_size = trace_path.stat().st_size
        
        if dry_run:
            print(f"[RetentionManager] Would compress {trace_path.name}")
            return {'count': 1, 'bytes_saved': int(original_size * 0.7)}  # Estimate 70% compression
        
        try:
            # Compress
            with open(trace_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            compressed_size = compressed_path.stat().st_size
            bytes_saved = original_size - compressed_size
            
            # Delete original
            trace_path.unlink()
            
            print(f"[RetentionManager] Compressed {trace_path.name}: {original_size / 1024:.1f} KB -> {compressed_size / 1024:.1f} KB (saved {bytes_saved / 1024:.1f} KB)")
            
            # Log audit
            self._log_audit(CleanupAuditEntry(
                timestamp=datetime.now().isoformat(),
                action='compress',
                file_path=str(trace_path),
                file_hash=result_dir.name,
                age_days=self._get_file_age_days(result_dir),
                size_bytes=bytes_saved,
                reason=f'age_exceeded_{self.config.compression_after_days}d'
            ))
            
            return {'count': 1, 'bytes_saved': bytes_saved}
        
        except Exception as e:
            print(f"[RetentionManager] Failed to compress {trace_path}: {e}")
            return None
    
    def compress_old_traces(self, days: int = None) -> Dict[str, Any]:
        """
        Compress traces older than specified days.
        
        Args:
            days: Age threshold (uses config if None)
        
        Returns:
            Dictionary with compression statistics
        """
        if days is None:
            days = self.config.compression_after_days
        
        print(f"[RetentionManager] Compressing traces older than {days} days...")
        
        stats = {
            'files_scanned': 0,
            'files_compressed': 0,
            'bytes_saved': 0,
            'errors': []
        }
        
        if not self.analysis_dir.exists():
            return stats
        
        for result_dir in self.analysis_dir.iterdir():
            if not result_dir.is_dir():
                continue
            
            stats['files_scanned'] += 1
            
            age_days = self._get_file_age_days(result_dir / "dynamic_results.json")
            
            if age_days > days:
                result = self._compress_traces(result_dir, dry_run=False)
                if result:
                    stats['files_compressed'] += result['count']
                    stats['bytes_saved'] += result['bytes_saved']
        
        print(f"[RetentionManager] Compression complete:")
        print(f"  Scanned: {stats['files_scanned']}")
        print(f"  Compressed: {stats['files_compressed']}")
        print(f"  Saved: {stats['bytes_saved'] / 1024 / 1024:.1f} MB")
        
        return stats
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get storage statistics for analysis results.
        
        Returns:
            Dictionary with storage statistics
        """
        stats = {
            'total_results': 0,
            'total_size_bytes': 0,
            'total_size_mb': 0.0,
            'compressed_files': 0,
            'uncompressed_files': 0,
            'by_age': {
                '0-7d': {'count': 0, 'size_bytes': 0},
                '7-30d': {'count': 0, 'size_bytes': 0},
                '30-90d': {'count': 0, 'size_bytes': 0},
                '90d+': {'count': 0, 'size_bytes': 0}
            }
        }
        
        if not self.analysis_dir.exists():
            return stats
        
        for result_dir in self.analysis_dir.iterdir():
            if not result_dir.is_dir():
                continue
            
            stats['total_results'] += 1
            
            # Calculate directory size
            dir_size = sum(
                f.stat().st_size 
                for f in result_dir.rglob('*') 
                if f.is_file()
            )
            
            stats['total_size_bytes'] += dir_size
            
            # Check for compressed traces
            if (result_dir / "trace.ndjson.gz").exists():
                stats['compressed_files'] += 1
            elif (result_dir / "trace.ndjson").exists():
                stats['uncompressed_files'] += 1
            
            # Categorize by age
            age_days = self._get_file_age_days(result_dir / "dynamic_results.json")
            
            if age_days <= 7:
                bucket = '0-7d'
            elif age_days <= 30:
                bucket = '7-30d'
            elif age_days <= 90:
                bucket = '30-90d'
            else:
                bucket = '90d+'
            
            stats['by_age'][bucket]['count'] += 1
            stats['by_age'][bucket]['size_bytes'] += dir_size
        
        stats['total_size_mb'] = stats['total_size_bytes'] / 1024 / 1024
        
        return stats
    
    def get_retention_report(self) -> Dict[str, Any]:
        """
        Get detailed retention policy report.
        
        Returns:
            Dictionary with retention statistics and recommendations
        """
        storage_stats = self.get_storage_stats()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'config': asdict(self.config),
            'storage': storage_stats,
            'recommendations': []
        }
        
        # Check if cleanup needed
        total_size_gb = storage_stats['total_size_mb'] / 1024
        
        if total_size_gb > self.config.max_total_size_gb:
            report['recommendations'].append({
                'level': 'critical',
                'message': f'Storage limit exceeded: {total_size_gb:.1f} GB > {self.config.max_total_size_gb} GB',
                'action': 'run_cleanup_immediately'
            })
        elif total_size_gb > self.config.max_total_size_gb * 0.8:
            report['recommendations'].append({
                'level': 'warning',
                'message': f'Storage approaching limit: {total_size_gb:.1f} GB / {self.config.max_total_size_gb} GB',
                'action': 'schedule_cleanup'
            })
        
        # Check compression opportunities
        if storage_stats['uncompressed_files'] > 0:
            report['recommendations'].append({
                'level': 'info',
                'message': f'{storage_stats["uncompressed_files"]} files could be compressed',
                'action': 'run_compression'
            })
        
        return report
    
    def force_cleanup_by_size(self, target_size_gb: float) -> Dict[str, Any]:
        """
        Force cleanup to achieve target storage size.
        
        Deletes oldest results first until target is reached.
        
        Args:
            target_size_gb: Target storage size in GB
        
        Returns:
            Dictionary with cleanup statistics
        """
        print(f"[RetentionManager] Force cleanup to reach {target_size_gb:.1f} GB...")
        
        stats = {
            'files_deleted': 0,
            'bytes_freed': 0
        }
        
        if not self.analysis_dir.exists():
            return stats
        
        # Get all results sorted by age (oldest first)
        results = []
        
        for result_dir in self.analysis_dir.iterdir():
            if not result_dir.is_dir():
                continue
            
            if self._should_preserve(result_dir):
                continue
            
            age_days = self._get_file_age_days(result_dir / "dynamic_results.json")
            dir_size = sum(
                f.stat().st_size 
                for f in result_dir.rglob('*') 
                if f.is_file()
            )
            
            results.append({
                'path': result_dir,
                'hash': result_dir.name,
                'age_days': age_days,
                'size_bytes': dir_size
            })
        
        # Sort by age (oldest first)
        results.sort(key=lambda x: x['age_days'], reverse=True)
        
        # Calculate current size
        current_size_bytes = sum(r['size_bytes'] for r in results)
        current_size_gb = current_size_bytes / 1024 / 1024 / 1024
        target_size_bytes = target_size_gb * 1024 * 1024 * 1024
        
        print(f"[RetentionManager] Current size: {current_size_gb:.1f} GB")
        
        # Delete oldest until target reached
        for result in results:
            if current_size_bytes <= target_size_bytes:
                break
            
            try:
                shutil.rmtree(result['path'])
                
                stats['files_deleted'] += 1
                stats['bytes_freed'] += result['size_bytes']
                current_size_bytes -= result['size_bytes']
                
                # Log audit
                self._log_audit(CleanupAuditEntry(
                    timestamp=datetime.now().isoformat(),
                    action='delete',
                    file_path=str(result['path']),
                    file_hash=result['hash'],
                    age_days=result['age_days'],
                    size_bytes=result['size_bytes'],
                    reason='force_cleanup_by_size'
                ))
                
                print(f"[RetentionManager] Deleted {result['hash']} (age: {result['age_days']}d, size: {result['size_bytes'] / 1024 / 1024:.1f} MB)")
            
            except Exception as e:
                print(f"[RetentionManager] Failed to delete {result['hash']}: {e}")
        
        final_size_gb = current_size_bytes / 1024 / 1024 / 1024
        
        print(f"[RetentionManager] Force cleanup complete:")
        print(f"  Files deleted: {stats['files_deleted']}")
        print(f"  Space freed: {stats['bytes_freed'] / 1024 / 1024:.1f} MB")
        print(f"  Final size: {final_size_gb:.1f} GB")
        
        return stats


# Utility functions

def run_scheduled_cleanup(workspace_dir: str, dry_run: bool = False):
    """
    Run scheduled cleanup (called by cron or task scheduler).
    
    Args:
        workspace_dir: Base workspace directory
        dry_run: If True, report without deleting
    """
    manager = RetentionManager(workspace_dir)
    stats = manager.run_cleanup(dry_run=dry_run)
    
    print(f"\nScheduled cleanup completed at {datetime.now().isoformat()}")
    print(f"Files deleted: {stats['files_deleted']}")
    print(f"Space freed: {stats['bytes_freed'] / 1024 / 1024:.1f} MB")
    
    return stats
