"""
Quota management system for dynamic analysis.

This module implements resource quotas to prevent abuse and ensure fair usage
across users and processes. It tracks execution counts, storage usage, CPU time,
and memory consumption with configurable limits.

Features:
- Per-user execution quotas (daily/weekly/monthly)
- Per-binary execution limits
- Concurrent execution limits
- Storage quota tracking
- CPU time and memory limits
- Quota reset schedules
- Admin override capabilities
- Grace period handling

Author: Dynamic Analysis Team
Date: November 11, 2025
"""

import json
import os
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


class QuotaType(Enum):
    """Types of quotas that can be enforced."""
    EXECUTIONS_PER_DAY = "executions_per_day"
    EXECUTIONS_PER_WEEK = "executions_per_week"
    EXECUTIONS_PER_MONTH = "executions_per_month"
    EXECUTIONS_PER_BINARY_PER_DAY = "executions_per_binary_per_day"
    MAX_CONCURRENT_EXECUTIONS = "max_concurrent_executions"
    MAX_STORAGE_MB = "max_storage_mb"
    MAX_CPU_TIME_SECONDS = "max_cpu_time_seconds"
    MAX_MEMORY_MB = "max_memory_mb"


class QuotaExceededError(Exception):
    """Raised when a quota limit is exceeded."""
    
    def __init__(self, quota_type: QuotaType, current: int, limit: int, message: str = None):
        self.quota_type = quota_type
        self.current = current
        self.limit = limit
        if message is None:
            message = f"Quota exceeded: {quota_type.value} (current: {current}, limit: {limit})"
        super().__init__(message)


@dataclass
class QuotaUsage:
    """Tracks quota usage for a user."""
    user_id: str
    executions_today: int = 0
    executions_this_week: int = 0
    executions_this_month: int = 0
    storage_used_mb: float = 0.0
    concurrent_executions: int = 0
    last_reset_daily: str = None
    last_reset_weekly: str = None
    last_reset_monthly: str = None
    binary_executions_today: Dict[str, int] = None
    
    def __post_init__(self):
        if self.binary_executions_today is None:
            self.binary_executions_today = {}
        if self.last_reset_daily is None:
            self.last_reset_daily = datetime.now().strftime("%Y-%m-%d")
        if self.last_reset_weekly is None:
            self.last_reset_weekly = datetime.now().strftime("%Y-W%W")
        if self.last_reset_monthly is None:
            self.last_reset_monthly = datetime.now().strftime("%Y-%m")


@dataclass
class QuotaConfig:
    """Configuration for quota limits."""
    executions_per_day: int = 100
    executions_per_week: int = 500
    executions_per_month: int = 2000
    executions_per_binary_per_day: int = 5
    max_concurrent_executions: int = 3
    max_storage_per_user_mb: float = 10240.0  # 10 GB
    max_cpu_time_per_execution_seconds: int = 600  # 10 minutes
    max_memory_per_execution_mb: int = 4096  # 4 GB
    grace_period_enabled: bool = True
    grace_period_percentage: float = 0.1  # 10% grace over limit
    admin_users: List[str] = None
    
    def __post_init__(self):
        if self.admin_users is None:
            self.admin_users = []


class QuotaManager:
    """
    Manages resource quotas for dynamic analysis.
    
    This class tracks and enforces various resource limits to prevent
    abuse and ensure fair usage across users. It persists quota data
    to disk and automatically resets quotas based on configured schedules.
    
    Usage:
        # Initialize manager
        manager = QuotaManager(workspace_dir='workspace')
        
        # Check if user can run analysis
        try:
            manager.check_quota('user123', 'binary_hash')
        except QuotaExceededError as e:
            print(f"Quota exceeded: {e}")
        
        # Start tracking execution
        with manager.track_execution('user123', 'binary_hash'):
            # Run analysis
            pass
        
        # Update storage usage
        manager.update_storage_usage('user123', 1024.5)  # MB
    """
    
    def __init__(self, workspace_dir: str, config: QuotaConfig = None):
        """
        Initialize quota manager.
        
        Args:
            workspace_dir: Base workspace directory
            config: Quota configuration (uses defaults if None)
        """
        self.workspace_dir = Path(workspace_dir)
        self.config = config or QuotaConfig()
        
        # Quota storage directory
        self.quota_dir = self.workspace_dir / "quotas"
        self.quota_dir.mkdir(parents=True, exist_ok=True)
        
        # Thread lock for concurrent access
        self._lock = threading.Lock()
        
        # Load or initialize config
        self._save_config()
    
    def _get_user_quota_path(self, user_id: str) -> Path:
        """Get path to user's quota file."""
        return self.quota_dir / f"{user_id}.json"
    
    def _load_user_quota(self, user_id: str) -> QuotaUsage:
        """Load user's quota usage from disk."""
        quota_path = self._get_user_quota_path(user_id)
        
        if not quota_path.exists():
            return QuotaUsage(user_id=user_id)
        
        try:
            with open(quota_path, 'r') as f:
                data = json.load(f)
            
            # Convert to QuotaUsage
            return QuotaUsage(**data)
        
        except (json.JSONDecodeError, TypeError) as e:
            # Corrupted quota file, reset
            print(f"Warning: Corrupted quota file for {user_id}, resetting: {e}")
            return QuotaUsage(user_id=user_id)
    
    def _save_user_quota(self, usage: QuotaUsage):
        """Save user's quota usage to disk."""
        quota_path = self._get_user_quota_path(usage.user_id)
        
        # Atomic write
        temp_path = quota_path.with_suffix('.tmp')
        
        try:
            with open(temp_path, 'w') as f:
                json.dump(asdict(usage), f, indent=2)
            
            # Atomic rename
            temp_path.replace(quota_path)
        
        except Exception as e:
            print(f"Error saving quota for {usage.user_id}: {e}")
            if temp_path.exists():
                temp_path.unlink()
    
    def _save_config(self):
        """Save quota configuration."""
        config_path = self.quota_dir / "config.json"
        
        with open(config_path, 'w') as f:
            json.dump(asdict(self.config), f, indent=2)
    
    def _check_and_reset_quotas(self, usage: QuotaUsage) -> QuotaUsage:
        """Check if quotas need to be reset and reset them if necessary."""
        now = datetime.now()
        today = now.strftime("%Y-%m-%d")
        this_week = now.strftime("%Y-W%W")
        this_month = now.strftime("%Y-%m")
        
        modified = False
        
        # Reset daily quota
        if usage.last_reset_daily != today:
            usage.executions_today = 0
            usage.binary_executions_today = {}
            usage.last_reset_daily = today
            modified = True
        
        # Reset weekly quota
        if usage.last_reset_weekly != this_week:
            usage.executions_this_week = 0
            usage.last_reset_weekly = this_week
            modified = True
        
        # Reset monthly quota
        if usage.last_reset_monthly != this_month:
            usage.executions_this_month = 0
            usage.last_reset_monthly = this_month
            modified = True
        
        if modified:
            self._save_user_quota(usage)
        
        return usage
    
    def _is_admin(self, user_id: str) -> bool:
        """Check if user is an admin (bypasses quotas)."""
        return user_id in self.config.admin_users
    
    def _apply_grace_period(self, limit: int) -> int:
        """Apply grace period to limit if enabled."""
        if self.config.grace_period_enabled:
            return int(limit * (1 + self.config.grace_period_percentage))
        return limit
    
    def check_quota(self, user_id: str, file_hash: str = None) -> Dict[str, Any]:
        """
        Check if user can run analysis within quota limits.
        
        Args:
            user_id: User identifier
            file_hash: Binary file hash (optional, for per-binary limits)
        
        Returns:
            Dictionary with quota status:
            {
                'allowed': bool,
                'violations': List[str],
                'usage': Dict[str, Any]
            }
        
        Raises:
            QuotaExceededError: If any quota is exceeded
        """
        with self._lock:
            # Admins bypass quotas
            if self._is_admin(user_id):
                return {
                    'allowed': True,
                    'violations': [],
                    'usage': {},
                    'admin': True
                }
            
            # Load and reset quotas if needed
            usage = self._load_user_quota(user_id)
            usage = self._check_and_reset_quotas(usage)
            
            violations = []
            
            # Check daily executions
            daily_limit = self._apply_grace_period(self.config.executions_per_day)
            if usage.executions_today >= daily_limit:
                violations.append(f"Daily execution limit exceeded ({usage.executions_today}/{self.config.executions_per_day})")
            
            # Check weekly executions
            weekly_limit = self._apply_grace_period(self.config.executions_per_week)
            if usage.executions_this_week >= weekly_limit:
                violations.append(f"Weekly execution limit exceeded ({usage.executions_this_week}/{self.config.executions_per_week})")
            
            # Check monthly executions
            monthly_limit = self._apply_grace_period(self.config.executions_per_month)
            if usage.executions_this_month >= monthly_limit:
                violations.append(f"Monthly execution limit exceeded ({usage.executions_this_month}/{self.config.executions_per_month})")
            
            # Check per-binary daily executions
            if file_hash:
                binary_count = usage.binary_executions_today.get(file_hash, 0)
                binary_limit = self._apply_grace_period(self.config.executions_per_binary_per_day)
                if binary_count >= binary_limit:
                    violations.append(f"Per-binary daily limit exceeded ({binary_count}/{self.config.executions_per_binary_per_day})")
            
            # Check concurrent executions
            if usage.concurrent_executions >= self.config.max_concurrent_executions:
                violations.append(f"Concurrent execution limit reached ({usage.concurrent_executions}/{self.config.max_concurrent_executions})")
            
            # Check storage quota
            storage_limit = self._apply_grace_period(self.config.max_storage_per_user_mb)
            if usage.storage_used_mb >= storage_limit:
                violations.append(f"Storage quota exceeded ({usage.storage_used_mb:.1f}/{self.config.max_storage_per_user_mb:.1f} MB)")
            
            # Return status
            status = {
                'allowed': len(violations) == 0,
                'violations': violations,
                'usage': {
                    'executions_today': usage.executions_today,
                    'executions_this_week': usage.executions_this_week,
                    'executions_this_month': usage.executions_this_month,
                    'storage_used_mb': usage.storage_used_mb,
                    'concurrent_executions': usage.concurrent_executions
                }
            }
            
            if not status['allowed']:
                raise QuotaExceededError(
                    QuotaType.EXECUTIONS_PER_DAY,
                    usage.executions_today,
                    self.config.executions_per_day,
                    "; ".join(violations)
                )
            
            return status
    
    def track_execution(self, user_id: str, file_hash: str):
        """
        Context manager to track execution and update quotas.
        
        Usage:
            with manager.track_execution('user123', 'hash'):
                # Run analysis
                pass
        
        Args:
            user_id: User identifier
            file_hash: Binary file hash
        
        Returns:
            Context manager
        """
        return ExecutionTracker(self, user_id, file_hash)
    
    def _start_execution(self, user_id: str, file_hash: str):
        """Called when execution starts."""
        with self._lock:
            usage = self._load_user_quota(user_id)
            usage = self._check_and_reset_quotas(usage)
            
            # Increment counters
            usage.executions_today += 1
            usage.executions_this_week += 1
            usage.executions_this_month += 1
            usage.concurrent_executions += 1
            
            # Track per-binary
            if file_hash:
                usage.binary_executions_today[file_hash] = \
                    usage.binary_executions_today.get(file_hash, 0) + 1
            
            self._save_user_quota(usage)
    
    def _end_execution(self, user_id: str):
        """Called when execution ends."""
        with self._lock:
            usage = self._load_user_quota(user_id)
            
            # Decrement concurrent counter
            usage.concurrent_executions = max(0, usage.concurrent_executions - 1)
            
            self._save_user_quota(usage)
    
    def update_storage_usage(self, user_id: str, storage_mb: float):
        """
        Update user's storage usage.
        
        Args:
            user_id: User identifier
            storage_mb: Current storage usage in MB
        """
        with self._lock:
            usage = self._load_user_quota(user_id)
            usage.storage_used_mb = storage_mb
            self._save_user_quota(usage)
    
    def get_usage_report(self, user_id: str) -> Dict[str, Any]:
        """
        Get detailed usage report for user.
        
        Args:
            user_id: User identifier
        
        Returns:
            Dictionary with usage statistics and limits
        """
        with self._lock:
            usage = self._load_user_quota(user_id)
            usage = self._check_and_reset_quotas(usage)
            
            return {
                'user_id': user_id,
                'is_admin': self._is_admin(user_id),
                'usage': {
                    'executions_today': {
                        'current': usage.executions_today,
                        'limit': self.config.executions_per_day,
                        'percentage': (usage.executions_today / self.config.executions_per_day * 100) if self.config.executions_per_day > 0 else 0
                    },
                    'executions_this_week': {
                        'current': usage.executions_this_week,
                        'limit': self.config.executions_per_week,
                        'percentage': (usage.executions_this_week / self.config.executions_per_week * 100) if self.config.executions_per_week > 0 else 0
                    },
                    'executions_this_month': {
                        'current': usage.executions_this_month,
                        'limit': self.config.executions_per_month,
                        'percentage': (usage.executions_this_month / self.config.executions_per_month * 100) if self.config.executions_per_month > 0 else 0
                    },
                    'storage': {
                        'current_mb': usage.storage_used_mb,
                        'limit_mb': self.config.max_storage_per_user_mb,
                        'percentage': (usage.storage_used_mb / self.config.max_storage_per_user_mb * 100) if self.config.max_storage_per_user_mb > 0 else 0
                    },
                    'concurrent_executions': {
                        'current': usage.concurrent_executions,
                        'limit': self.config.max_concurrent_executions
                    }
                },
                'last_reset': {
                    'daily': usage.last_reset_daily,
                    'weekly': usage.last_reset_weekly,
                    'monthly': usage.last_reset_monthly
                }
            }
    
    def reset_user_quota(self, user_id: str, quota_type: str = 'all'):
        """
        Admin function to reset user's quota.
        
        Args:
            user_id: User identifier
            quota_type: Type of quota to reset ('daily', 'weekly', 'monthly', 'storage', 'all')
        """
        with self._lock:
            usage = self._load_user_quota(user_id)
            
            if quota_type in ('daily', 'all'):
                usage.executions_today = 0
                usage.binary_executions_today = {}
            
            if quota_type in ('weekly', 'all'):
                usage.executions_this_week = 0
            
            if quota_type in ('monthly', 'all'):
                usage.executions_this_month = 0
            
            if quota_type in ('storage', 'all'):
                usage.storage_used_mb = 0.0
            
            self._save_user_quota(usage)
    
    def list_all_users(self) -> List[Dict[str, Any]]:
        """
        Get list of all users with quota usage.
        
        Returns:
            List of user usage reports
        """
        users = []
        
        for quota_file in self.quota_dir.glob("*.json"):
            if quota_file.name == "config.json":
                continue
            
            user_id = quota_file.stem
            try:
                report = self.get_usage_report(user_id)
                users.append(report)
            except Exception as e:
                print(f"Error loading quota for {user_id}: {e}")
        
        return users
    
    def cleanup_old_quotas(self, days: int = 90):
        """
        Remove quota files for inactive users.
        
        Args:
            days: Remove quotas not modified in this many days
        """
        cutoff = datetime.now() - timedelta(days=days)
        
        for quota_file in self.quota_dir.glob("*.json"):
            if quota_file.name == "config.json":
                continue
            
            # Check last modified time
            mtime = datetime.fromtimestamp(quota_file.stat().st_mtime)
            
            if mtime < cutoff:
                try:
                    quota_file.unlink()
                    print(f"Removed inactive quota file: {quota_file.name}")
                except Exception as e:
                    print(f"Error removing {quota_file.name}: {e}")


class ExecutionTracker:
    """Context manager for tracking analysis execution."""
    
    def __init__(self, manager: QuotaManager, user_id: str, file_hash: str):
        self.manager = manager
        self.user_id = user_id
        self.file_hash = file_hash
    
    def __enter__(self):
        self.manager._start_execution(self.user_id, self.file_hash)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.manager._end_execution(self.user_id)
        return False


# Utility functions for easy access

def create_quota_manager(workspace_dir: str, **config_kwargs) -> QuotaManager:
    """
    Create quota manager with custom configuration.
    
    Args:
        workspace_dir: Base workspace directory
        **config_kwargs: Quota configuration parameters
    
    Returns:
        Configured QuotaManager instance
    """
    config = QuotaConfig(**config_kwargs)
    return QuotaManager(workspace_dir, config)


def check_user_quota(workspace_dir: str, user_id: str, file_hash: str = None) -> bool:
    """
    Quick check if user can run analysis.
    
    Args:
        workspace_dir: Base workspace directory
        user_id: User identifier
        file_hash: Binary file hash (optional)
    
    Returns:
        True if within quota, False otherwise
    """
    manager = QuotaManager(workspace_dir)
    
    try:
        status = manager.check_quota(user_id, file_hash)
        return status['allowed']
    except QuotaExceededError:
        return False
