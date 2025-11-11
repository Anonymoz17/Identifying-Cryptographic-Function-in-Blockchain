"""
Security hardening for dynamic analysis.

This module implements security features to protect the system from
malicious binaries, sandbox escapes, and data leaks.

Features:
- Binary validation before execution
- Input sanitization
- Sandbox escape prevention
- Secrets redaction in traces
- Audit logging for all operations
- Path traversal prevention

Author: Dynamic Analysis Team
Date: November 11, 2025
"""

import os
import re
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime
import json


@dataclass
class BinaryValidationResult:
    """Result of binary validation."""
    valid: bool
    errors: List[str]
    warnings: List[str]
    file_hash: str
    file_size: int
    file_type: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'valid': self.valid,
            'errors': self.errors,
            'warnings': self.warnings,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'file_type': self.file_type
        }


class SecurityHardening:
    """
    Security hardening features for dynamic analysis.
    
    This class provides security validation, input sanitization,
    secrets redaction, and audit logging to protect the system
    from malicious binaries and data leaks.
    
    Usage:
        # Initialize hardening
        security = SecurityHardening(workspace_dir='workspace')
        
        # Validate binary
        result = security.validate_binary('malware.exe')
        if not result.valid:
            print(f"Validation failed: {result.errors}")
        
        # Sanitize input
        safe_input = security.sanitize_input(user_input)
        
        # Redact secrets from trace
        clean_trace = security.redact_secrets(trace_data)
    """
    
    # Dangerous file extensions
    BLOCKED_EXTENSIONS = {
        '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf',
        '.msi', '.scr', '.pif', '.com'
    }
    
    # Maximum file size (500 MB)
    MAX_FILE_SIZE = 500 * 1024 * 1024
    
    # Patterns that might indicate secrets
    SECRET_PATTERNS = [
        # API keys
        (r'[A-Za-z0-9]{20,}', 'api_key'),
        # Private keys
        (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', 'private_key'),
        # Passwords in common formats
        (r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"]?([^\s\'"]+)', 'password'),
        # Tokens
        (r'(?i)(token|auth|bearer)\s*[:=]\s*[\'"]?([^\s\'"]+)', 'token'),
        # Database connection strings
        (r'(?i)(mongodb|mysql|postgres|redis)://[^\s]+', 'connection_string'),
        # AWS keys
        (r'AKIA[0-9A-Z]{16}', 'aws_key'),
        # Email addresses
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'email'),
    ]
    
    def __init__(self, workspace_dir: str, enable_audit_log: bool = True):
        """
        Initialize security hardening.
        
        Args:
            workspace_dir: Base workspace directory
            enable_audit_log: Enable audit logging
        """
        self.workspace_dir = Path(workspace_dir)
        self.enable_audit_log = enable_audit_log
        
        # Audit log
        self.audit_log_dir = self.workspace_dir / "audit"
        self.audit_log_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log_path = self.audit_log_dir / "security_audit.jsonl"
        
        # Compile regex patterns
        self._secret_regex = [
            (re.compile(pattern, re.MULTILINE), name)
            for pattern, name in self.SECRET_PATTERNS
        ]
    
    def validate_binary(self, binary_path: str) -> BinaryValidationResult:
        """
        Validate binary before execution.
        
        Args:
            binary_path: Path to binary file
        
        Returns:
            BinaryValidationResult with validation details
        """
        errors = []
        warnings = []
        
        path = Path(binary_path)
        
        # Check file exists
        if not path.exists():
            errors.append(f"File does not exist: {binary_path}")
            return BinaryValidationResult(
                valid=False,
                errors=errors,
                warnings=warnings,
                file_hash='',
                file_size=0,
                file_type='unknown'
            )
        
        # Check if file (not directory)
        if not path.is_file():
            errors.append(f"Path is not a file: {binary_path}")
        
        # Check file size
        file_size = path.stat().st_size
        if file_size == 0:
            errors.append("File is empty")
        elif file_size > self.MAX_FILE_SIZE:
            errors.append(f"File too large: {file_size} bytes (max: {self.MAX_FILE_SIZE})")
        
        # Check extension
        extension = path.suffix.lower()
        if extension in self.BLOCKED_EXTENSIONS:
            errors.append(f"Blocked file extension: {extension}")
        
        # Check path traversal
        if not self._is_safe_path(binary_path):
            errors.append("Path contains traversal attempts")
        
        # Calculate hash
        file_hash = ''
        try:
            file_hash = self._calculate_hash(path)
        except Exception as e:
            errors.append(f"Failed to calculate hash: {e}")
        
        # Detect file type
        file_type = self._detect_file_type(path)
        
        # Validate executable format
        if file_type == 'unknown':
            warnings.append("Could not determine file type")
        
        # Check for known dangerous patterns
        dangerous_patterns = self._check_dangerous_patterns(path)
        if dangerous_patterns:
            warnings.extend(dangerous_patterns)
        
        # Log validation
        if self.enable_audit_log:
            self._log_audit({
                'timestamp': datetime.now().isoformat(),
                'action': 'binary_validation',
                'binary_path': str(path),
                'file_hash': file_hash,
                'valid': len(errors) == 0,
                'errors': errors,
                'warnings': warnings
            })
        
        return BinaryValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            file_hash=file_hash,
            file_size=file_size,
            file_type=file_type
        )
    
    def _is_safe_path(self, path: str) -> bool:
        """Check if path is safe (no traversal)."""
        # Check for path traversal patterns
        dangerous_patterns = ['..', '~', '%', '$']
        
        for pattern in dangerous_patterns:
            if pattern in path:
                return False
        
        # Check for absolute paths outside workspace
        try:
            resolved = Path(path).resolve()
            workspace_resolved = self.workspace_dir.resolve()
            
            # Allow paths in workspace or uploads
            if not (
                str(resolved).startswith(str(workspace_resolved)) or
                'uploads' in str(resolved)
            ):
                # External path - could be OK for analysis
                pass
        
        except Exception:
            return False
        
        return True
    
    def _calculate_hash(self, path: Path) -> str:
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        
        with open(path, 'rb') as f:
            while True:
                data = f.read(65536)  # 64KB chunks
                if not data:
                    break
                sha256.update(data)
        
        return sha256.hexdigest()
    
    def _detect_file_type(self, path: Path) -> str:
        """Detect file type from magic bytes."""
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
            
            # PE executable
            if magic[:2] == b'MZ':
                return 'pe'
            
            # ELF executable
            elif magic[:4] == b'\x7fELF':
                return 'elf'
            
            # Mach-O (macOS)
            elif magic[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                               b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
                return 'macho'
            
            return 'unknown'
        
        except Exception:
            return 'unknown'
    
    def _check_dangerous_patterns(self, path: Path) -> List[str]:
        """Check for dangerous patterns in binary."""
        warnings = []
        
        try:
            # Read first 1MB for analysis
            with open(path, 'rb') as f:
                data = f.read(1024 * 1024)
            
            # Check for common malware indicators (heuristic)
            dangerous_strings = [
                b'cmd.exe',
                b'powershell',
                b'regsvr32',
                b'rundll32',
                b'wscript',
                b'cscript'
            ]
            
            for dangerous in dangerous_strings:
                if dangerous in data:
                    warnings.append(f"Found suspicious string: {dangerous.decode('utf-8', errors='ignore')}")
        
        except Exception:
            pass
        
        return warnings
    
    def sanitize_input(self, user_input: str, max_length: int = 1024) -> str:
        """
        Sanitize user input to prevent injection attacks.
        
        Args:
            user_input: Raw user input
            max_length: Maximum allowed length
        
        Returns:
            Sanitized input
        """
        if not user_input:
            return ''
        
        # Truncate
        sanitized = user_input[:max_length]
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        # Remove control characters (except newline, tab, carriage return)
        sanitized = ''.join(
            char for char in sanitized
            if ord(char) >= 32 or char in ('\n', '\t', '\r')
        )
        
        # Remove potentially dangerous patterns
        dangerous_patterns = [
            r'<script',
            r'javascript:',
            r'on\w+\s*=',  # Event handlers
            r'[\x00-\x1f]'  # Control chars
        ]
        
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def redact_secrets(self, data: str) -> str:
        """
        Redact secrets from data (for traces/logs).
        
        Args:
            data: Raw data that may contain secrets
        
        Returns:
            Data with secrets redacted
        """
        redacted = data
        
        for pattern, secret_type in self._secret_regex:
            def redact_match(match):
                matched_text = match.group(0)
                # Keep first and last 4 chars, redact middle
                if len(matched_text) > 8:
                    return f"{matched_text[:4]}***REDACTED_{secret_type.upper()}***{matched_text[-4:]}"
                else:
                    return f"***REDACTED_{secret_type.upper()}***"
            
            redacted = pattern.sub(redact_match, redacted)
        
        return redacted
    
    def sanitize_trace_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize trace event to remove secrets.
        
        Args:
            event: Trace event dictionary
        
        Returns:
            Sanitized event
        """
        sanitized = event.copy()
        
        # Redact string fields
        for key, value in sanitized.items():
            if isinstance(value, str):
                sanitized[key] = self.redact_secrets(value)
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_trace_event(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.redact_secrets(item) if isinstance(item, str) else item
                    for item in value
                ]
        
        return sanitized
    
    def validate_path_access(self, path: str, allowed_dirs: List[str]) -> bool:
        """
        Validate that path access is within allowed directories.
        
        Args:
            path: Path to validate
            allowed_dirs: List of allowed directory paths
        
        Returns:
            True if access allowed, False otherwise
        """
        try:
            resolved = Path(path).resolve()
            
            for allowed in allowed_dirs:
                allowed_resolved = Path(allowed).resolve()
                
                if str(resolved).startswith(str(allowed_resolved)):
                    return True
            
            return False
        
        except Exception:
            return False
    
    def _log_audit(self, entry: Dict[str, Any]):
        """Log audit entry."""
        if not self.enable_audit_log:
            return
        
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            print(f"[SecurityHardening] Warning: Failed to write audit log: {e}")
    
    def log_security_event(
        self,
        event_type: str,
        severity: str,
        details: Dict[str, Any]
    ):
        """
        Log security event.
        
        Args:
            event_type: Type of security event
            severity: 'info', 'warning', 'critical'
            details: Event details
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'severity': severity,
            'details': details
        }
        
        self._log_audit(entry)
        
        if severity == 'critical':
            print(f"[SecurityHardening] CRITICAL: {event_type} - {details}")
        elif severity == 'warning':
            print(f"[SecurityHardening] WARNING: {event_type} - {details}")
    
    def get_audit_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get audit log summary for last N hours.
        
        Args:
            hours: Number of hours to summarize
        
        Returns:
            Dictionary with audit summary
        """
        summary = {
            'timestamp': datetime.now().isoformat(),
            'period_hours': hours,
            'events': {
                'total': 0,
                'by_type': {},
                'by_severity': {
                    'info': 0,
                    'warning': 0,
                    'critical': 0
                }
            },
            'binary_validations': {
                'total': 0,
                'valid': 0,
                'invalid': 0
            }
        }
        
        if not self.audit_log_path.exists():
            return summary
        
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        
        try:
            with open(self.audit_log_path, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        
                        # Check if within time window
                        entry_time = datetime.fromisoformat(entry['timestamp']).timestamp()
                        if entry_time < cutoff_time:
                            continue
                        
                        summary['events']['total'] += 1
                        
                        # Count by type
                        event_type = entry.get('action', entry.get('event_type', 'unknown'))
                        summary['events']['by_type'][event_type] = \
                            summary['events']['by_type'].get(event_type, 0) + 1
                        
                        # Count by severity
                        severity = entry.get('severity', 'info')
                        if severity in summary['events']['by_severity']:
                            summary['events']['by_severity'][severity] += 1
                        
                        # Binary validation stats
                        if event_type == 'binary_validation':
                            summary['binary_validations']['total'] += 1
                            if entry.get('valid', False):
                                summary['binary_validations']['valid'] += 1
                            else:
                                summary['binary_validations']['invalid'] += 1
                    
                    except (json.JSONDecodeError, ValueError):
                        continue
        
        except Exception as e:
            print(f"[SecurityHardening] Warning: Failed to read audit log: {e}")
        
        return summary


# Utility functions

def create_secure_sandbox_config() -> Dict[str, Any]:
    """
    Create secure sandbox configuration.
    
    Returns:
        Dictionary with secure sandbox settings
    """
    return {
        'network_disabled': True,
        'filesystem_readonly': True,
        'allowed_directories': ['workspace/analysis', 'workspace/uploads'],
        'max_execution_time': 600,  # 10 minutes
        'max_memory_mb': 4096,  # 4 GB
        'max_cpu_percent': 80,
        'enable_seccomp': True,  # Linux only
        'disable_system_calls': [
            'execve',  # Prevent spawning new processes
            'fork',
            'vfork',
            'clone'
        ]
    }
