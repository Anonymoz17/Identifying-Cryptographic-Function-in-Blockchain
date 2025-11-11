"""
Error recovery and resilience for dynamic analysis.

This module implements checkpoint/resume capabilities, automatic retry logic,
circuit breaker patterns, and graceful degradation to make the dynamic analysis
system resilient to failures.

Features:
- Checkpoint/resume for interrupted analyses
- Automatic retry with exponential backoff
- Circuit breaker pattern for repeated failures
- Graceful degradation
- Failure tracking and recovery statistics

Author: Dynamic Analysis Team
Date: November 11, 2025
"""

import os
import json
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass, asdict, field
from enum import Enum
import traceback


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failures detected, blocking requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class Checkpoint:
    """Analysis checkpoint for resume capability."""
    file_hash: str
    user_id: Optional[str]
    stage: str  # Which pipeline stage was reached
    timestamp: str
    context: Dict[str, Any]  # Serialized context
    partial_results: Dict[str, Any]  # Results so far
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'Checkpoint':
        """Create from dictionary."""
        return Checkpoint(**data)


@dataclass
class RetryConfig:
    """Retry configuration."""
    max_attempts: int = 3
    initial_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True  # Add randomness to delays
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for given attempt."""
        delay = min(
            self.initial_delay_seconds * (self.exponential_base ** attempt),
            self.max_delay_seconds
        )
        
        if self.jitter:
            import random
            delay = delay * (0.5 + random.random())
        
        return delay


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5  # Open after N failures
    success_threshold: int = 2  # Close after N successes in half-open
    timeout_seconds: float = 60.0  # Time before trying half-open
    
    def __post_init__(self):
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if self.success_threshold < 1:
            raise ValueError("success_threshold must be >= 1")


class CircuitBreaker:
    """
    Circuit breaker for preventing repeated failures.
    
    Implements the circuit breaker pattern to prevent cascading failures
    by temporarily blocking operations that are likely to fail.
    
    States:
    - CLOSED: Normal operation, all requests pass through
    - OPEN: Too many failures, blocking all requests
    - HALF_OPEN: Testing if service recovered, allowing limited requests
    
    Usage:
        breaker = CircuitBreaker('frida_spawn')
        
        if breaker.can_execute():
            try:
                result = risky_operation()
                breaker.record_success()
            except Exception as e:
                breaker.record_failure()
    """
    
    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        """
        Initialize circuit breaker.
        
        Args:
            name: Unique name for this circuit
            config: Configuration (uses defaults if None)
        """
        self.name = name
        self.config = config or CircuitBreakerConfig()
        
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        
        self._lock = threading.Lock()
    
    def can_execute(self) -> bool:
        """Check if operation can execute."""
        with self._lock:
            if self.state == CircuitState.CLOSED:
                return True
            
            elif self.state == CircuitState.OPEN:
                # Check if timeout expired
                if self.last_failure_time:
                    elapsed = time.time() - self.last_failure_time
                    
                    if elapsed >= self.config.timeout_seconds:
                        print(f"[CircuitBreaker:{self.name}] Timeout expired, entering HALF_OPEN")
                        self.state = CircuitState.HALF_OPEN
                        self.success_count = 0
                        return True
                
                return False
            
            elif self.state == CircuitState.HALF_OPEN:
                return True
            
            return False
    
    def record_success(self):
        """Record successful operation."""
        with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                
                if self.success_count >= self.config.success_threshold:
                    print(f"[CircuitBreaker:{self.name}] Success threshold reached, CLOSING circuit")
                    self.state = CircuitState.CLOSED
                    self.failure_count = 0
                    self.success_count = 0
            
            elif self.state == CircuitState.CLOSED:
                # Reset failure count on success
                self.failure_count = 0
    
    def record_failure(self):
        """Record failed operation."""
        with self._lock:
            self.last_failure_time = time.time()
            
            if self.state == CircuitState.HALF_OPEN:
                print(f"[CircuitBreaker:{self.name}] Failure in HALF_OPEN, OPENING circuit")
                self.state = CircuitState.OPEN
                self.failure_count = 0
                self.success_count = 0
            
            elif self.state == CircuitState.CLOSED:
                self.failure_count += 1
                
                if self.failure_count >= self.config.failure_threshold:
                    print(f"[CircuitBreaker:{self.name}] Failure threshold reached, OPENING circuit")
                    self.state = CircuitState.OPEN
    
    def get_state(self) -> Dict[str, Any]:
        """Get current state."""
        with self._lock:
            return {
                'name': self.name,
                'state': self.state.value,
                'failure_count': self.failure_count,
                'success_count': self.success_count,
                'last_failure_time': self.last_failure_time
            }


class ResilienceManager:
    """
    Manages error recovery and resilience features.
    
    This class provides checkpoint/resume, retry logic, circuit breakers,
    and graceful degradation capabilities for the dynamic analysis system.
    
    Usage:
        # Initialize manager
        manager = ResilienceManager(workspace_dir='workspace')
        
        # Execute with retry
        result = manager.execute_with_retry(
            operation=lambda: analyze_binary(ctx),
            operation_name='analyze',
            max_attempts=3
        )
        
        # Save checkpoint
        manager.save_checkpoint(file_hash, stage='frida_execution', context=ctx)
        
        # Resume from checkpoint
        checkpoint = manager.load_checkpoint(file_hash)
        if checkpoint:
            result = resume_from_stage(checkpoint.stage, checkpoint.context)
    """
    
    def __init__(self, workspace_dir: str):
        """
        Initialize resilience manager.
        
        Args:
            workspace_dir: Base workspace directory
        """
        self.workspace_dir = Path(workspace_dir)
        
        # Directories
        self.checkpoints_dir = self.workspace_dir / "checkpoints"
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)
        
        self.recovery_log = self.workspace_dir / "recovery.jsonl"
        
        # Circuit breakers
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._breaker_lock = threading.Lock()
        
        # Retry configs per operation
        self._retry_configs: Dict[str, RetryConfig] = {}
        
        # Default configs
        self._setup_default_configs()
    
    def _setup_default_configs(self):
        """Setup default retry and circuit breaker configs."""
        # Retry configs
        self._retry_configs['frida_spawn'] = RetryConfig(
            max_attempts=3,
            initial_delay_seconds=2.0,
            max_delay_seconds=30.0
        )
        
        self._retry_configs['frida_attach'] = RetryConfig(
            max_attempts=5,
            initial_delay_seconds=1.0,
            max_delay_seconds=10.0
        )
        
        self._retry_configs['trace_collection'] = RetryConfig(
            max_attempts=2,
            initial_delay_seconds=5.0,
            max_delay_seconds=60.0
        )
        
        # Circuit breaker configs
        self.get_circuit_breaker('frida_spawn', CircuitBreakerConfig(
            failure_threshold=5,
            timeout_seconds=120.0
        ))
        
        self.get_circuit_breaker('binary_validation', CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=60.0
        ))
    
    def get_circuit_breaker(
        self,
        name: str,
        config: CircuitBreakerConfig = None
    ) -> CircuitBreaker:
        """
        Get or create circuit breaker.
        
        Args:
            name: Circuit breaker name
            config: Configuration (uses defaults if None)
        
        Returns:
            CircuitBreaker instance
        """
        with self._breaker_lock:
            if name not in self._circuit_breakers:
                self._circuit_breakers[name] = CircuitBreaker(name, config)
            
            return self._circuit_breakers[name]
    
    def save_checkpoint(
        self,
        file_hash: str,
        stage: str,
        context: Dict[str, Any],
        partial_results: Dict[str, Any] = None,
        user_id: Optional[str] = None
    ):
        """
        Save checkpoint for resumption.
        
        Args:
            file_hash: Hash of analyzed binary
            stage: Pipeline stage reached
            context: Serialized analysis context
            partial_results: Results collected so far
            user_id: User who initiated analysis
        """
        checkpoint = Checkpoint(
            file_hash=file_hash,
            user_id=user_id,
            stage=stage,
            timestamp=datetime.now().isoformat(),
            context=context,
            partial_results=partial_results or {}
        )
        
        checkpoint_path = self.checkpoints_dir / f"{file_hash}.json"
        
        try:
            with open(checkpoint_path, 'w') as f:
                json.dump(checkpoint.to_dict(), f, indent=2)
            
            print(f"[ResilienceManager] Checkpoint saved: {file_hash} at stage '{stage}'")
        
        except Exception as e:
            print(f"[ResilienceManager] Warning: Failed to save checkpoint: {e}")
    
    def load_checkpoint(self, file_hash: str) -> Optional[Checkpoint]:
        """
        Load checkpoint for resumption.
        
        Args:
            file_hash: Hash of analyzed binary
        
        Returns:
            Checkpoint if exists, None otherwise
        """
        checkpoint_path = self.checkpoints_dir / f"{file_hash}.json"
        
        if not checkpoint_path.exists():
            return None
        
        try:
            with open(checkpoint_path, 'r') as f:
                data = json.load(f)
            
            checkpoint = Checkpoint.from_dict(data)
            print(f"[ResilienceManager] Checkpoint loaded: {file_hash} from stage '{checkpoint.stage}'")
            
            return checkpoint
        
        except Exception as e:
            print(f"[ResilienceManager] Warning: Failed to load checkpoint: {e}")
            return None
    
    def delete_checkpoint(self, file_hash: str):
        """
        Delete checkpoint (after successful completion).
        
        Args:
            file_hash: Hash of analyzed binary
        """
        checkpoint_path = self.checkpoints_dir / f"{file_hash}.json"
        
        if checkpoint_path.exists():
            try:
                checkpoint_path.unlink()
                print(f"[ResilienceManager] Checkpoint deleted: {file_hash}")
            except Exception as e:
                print(f"[ResilienceManager] Warning: Failed to delete checkpoint: {e}")
    
    def execute_with_retry(
        self,
        operation: Callable,
        operation_name: str,
        max_attempts: int = None,
        retry_config: RetryConfig = None
    ) -> Any:
        """
        Execute operation with automatic retry.
        
        Args:
            operation: Callable to execute
            operation_name: Name for logging
            max_attempts: Max retry attempts (uses config if None)
            retry_config: Retry configuration (uses defaults if None)
        
        Returns:
            Operation result
        
        Raises:
            Exception: If all retries exhausted
        """
        # Get config
        if retry_config is None:
            retry_config = self._retry_configs.get(
                operation_name,
                RetryConfig()
            )
        
        if max_attempts is None:
            max_attempts = retry_config.max_attempts
        
        last_exception = None
        
        for attempt in range(max_attempts):
            try:
                print(f"[ResilienceManager] Executing '{operation_name}' (attempt {attempt + 1}/{max_attempts})")
                
                result = operation()
                
                # Log success
                self._log_recovery({
                    'timestamp': datetime.now().isoformat(),
                    'operation': operation_name,
                    'attempt': attempt + 1,
                    'status': 'success'
                })
                
                return result
            
            except Exception as e:
                last_exception = e
                
                print(f"[ResilienceManager] '{operation_name}' failed (attempt {attempt + 1}/{max_attempts}): {e}")
                
                # Log failure
                self._log_recovery({
                    'timestamp': datetime.now().isoformat(),
                    'operation': operation_name,
                    'attempt': attempt + 1,
                    'status': 'failure',
                    'error': str(e),
                    'traceback': traceback.format_exc()
                })
                
                # Check if should retry
                if attempt < max_attempts - 1:
                    delay = retry_config.get_delay(attempt)
                    print(f"[ResilienceManager] Retrying in {delay:.1f} seconds...")
                    time.sleep(delay)
        
        # All retries exhausted
        print(f"[ResilienceManager] All retries exhausted for '{operation_name}'")
        raise last_exception
    
    def execute_with_circuit_breaker(
        self,
        operation: Callable,
        circuit_name: str,
        fallback: Callable = None
    ) -> Any:
        """
        Execute operation with circuit breaker protection.
        
        Args:
            operation: Callable to execute
            circuit_name: Name of circuit breaker
            fallback: Fallback operation if circuit open
        
        Returns:
            Operation result or fallback result
        
        Raises:
            Exception: If circuit open and no fallback
        """
        breaker = self.get_circuit_breaker(circuit_name)
        
        if not breaker.can_execute():
            print(f"[ResilienceManager] Circuit '{circuit_name}' is OPEN")
            
            if fallback:
                print(f"[ResilienceManager] Executing fallback for '{circuit_name}'")
                return fallback()
            else:
                raise Exception(f"Circuit breaker '{circuit_name}' is OPEN")
        
        try:
            result = operation()
            breaker.record_success()
            return result
        
        except Exception as e:
            breaker.record_failure()
            raise
    
    def execute_with_resilience(
        self,
        operation: Callable,
        operation_name: str,
        circuit_name: str = None,
        fallback: Callable = None,
        max_attempts: int = None
    ) -> Any:
        """
        Execute operation with full resilience (retry + circuit breaker).
        
        Args:
            operation: Callable to execute
            operation_name: Name for logging
            circuit_name: Circuit breaker name (uses operation_name if None)
            fallback: Fallback operation if all fails
            max_attempts: Max retry attempts
        
        Returns:
            Operation result
        """
        if circuit_name is None:
            circuit_name = operation_name
        
        # Wrap operation with circuit breaker
        def protected_operation():
            return self.execute_with_circuit_breaker(
                operation,
                circuit_name,
                fallback=None  # Don't use fallback yet
            )
        
        # Execute with retry
        try:
            return self.execute_with_retry(
                protected_operation,
                operation_name,
                max_attempts=max_attempts
            )
        
        except Exception as e:
            # All retries failed, try fallback
            if fallback:
                print(f"[ResilienceManager] Executing fallback for '{operation_name}'")
                return fallback()
            else:
                raise
    
    def _log_recovery(self, entry: Dict[str, Any]):
        """Log recovery event."""
        try:
            with open(self.recovery_log, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            print(f"[ResilienceManager] Warning: Failed to write recovery log: {e}")
    
    def get_recovery_stats(self) -> Dict[str, Any]:
        """
        Get recovery statistics.
        
        Returns:
            Dictionary with recovery statistics
        """
        stats = {
            'timestamp': datetime.now().isoformat(),
            'checkpoints': {
                'total': 0,
                'files': []
            },
            'circuit_breakers': [],
            'recovery_events': {
                'total': 0,
                'successful_retries': 0,
                'failed_operations': 0
            }
        }
        
        # Count checkpoints
        if self.checkpoints_dir.exists():
            checkpoints = list(self.checkpoints_dir.glob("*.json"))
            stats['checkpoints']['total'] = len(checkpoints)
            stats['checkpoints']['files'] = [cp.stem for cp in checkpoints]
        
        # Circuit breaker states
        with self._breaker_lock:
            for name, breaker in self._circuit_breakers.items():
                stats['circuit_breakers'].append(breaker.get_state())
        
        # Recovery events
        if self.recovery_log.exists():
            try:
                with open(self.recovery_log, 'r') as f:
                    for line in f:
                        try:
                            event = json.loads(line.strip())
                            stats['recovery_events']['total'] += 1
                            
                            if event.get('status') == 'success' and event.get('attempt', 1) > 1:
                                stats['recovery_events']['successful_retries'] += 1
                            elif event.get('status') == 'failure':
                                stats['recovery_events']['failed_operations'] += 1
                        
                        except json.JSONDecodeError:
                            continue
            
            except Exception as e:
                print(f"[ResilienceManager] Warning: Failed to read recovery log: {e}")
        
        return stats
    
    def reset_circuit_breaker(self, name: str):
        """Reset circuit breaker to CLOSED state."""
        breaker = self.get_circuit_breaker(name)
        
        with breaker._lock:
            breaker.state = CircuitState.CLOSED
            breaker.failure_count = 0
            breaker.success_count = 0
            breaker.last_failure_time = None
        
        print(f"[ResilienceManager] Circuit breaker '{name}' reset to CLOSED")
    
    def cleanup_old_checkpoints(self, days: int = 7):
        """
        Delete checkpoints older than specified days.
        
        Args:
            days: Delete checkpoints older than this
        """
        if not self.checkpoints_dir.exists():
            return
        
        cutoff_time = time.time() - (days * 86400)
        deleted = 0
        
        for checkpoint_file in self.checkpoints_dir.glob("*.json"):
            if checkpoint_file.stat().st_mtime < cutoff_time:
                try:
                    checkpoint_file.unlink()
                    deleted += 1
                except Exception as e:
                    print(f"[ResilienceManager] Warning: Failed to delete old checkpoint: {e}")
        
        if deleted > 0:
            print(f"[ResilienceManager] Deleted {deleted} old checkpoints")
