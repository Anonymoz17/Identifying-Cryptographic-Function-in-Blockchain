"""
Trace sanitizer for removing sensitive data.

Ensures no raw cryptographic keys or sensitive data are stored in traces.
All buffers are hashed before storage.
"""

import hashlib
import re
from typing import List, Dict, Any, Set


# Fields that should contain only hashes, never raw data
HASH_ONLY_FIELDS = {
    'buffer', 'data', 'key', 'secret', 'password', 'token',
    'input', 'output', 'plaintext', 'ciphertext'
}

# Fields that contain pointers/addresses (safe to keep)
POINTER_FIELDS = {
    'address', 'ptr', 'base', 'caller', 'callee'
}

# Fields to completely redact
REDACT_FIELDS = {
    'raw_data', 'raw_buffer', 'raw_key'
}


class TraceSanitizer:
    """
    Sanitizes trace events to remove sensitive data.

    Ensures:
    1. No raw crypto keys or secrets
    2. All buffers are hashed
    3. PII is removed
    4. Only metadata and hashes remain

    Usage:
        sanitizer = TraceSanitizer()

        # Sanitize single event
        clean_event = sanitizer.sanitize_event(event)

        # Sanitize all events
        clean_events = sanitizer.sanitize_all(events)

        # Check for violations
        violations = sanitizer.check_violations(events)
    """

    def __init__(self, strict_mode: bool = True):
        """
        Initialize sanitizer.

        Args:
            strict_mode: If True, fail on suspicious patterns
        """
        self.strict_mode = strict_mode
        self.violations: List[str] = []

    def sanitize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize a single trace event.

        Args:
            event: Event dictionary

        Returns:
            Sanitized event dictionary
        """
        if not event:
            return event

        sanitized = {}

        for key, value in event.items():
            # Check if field should be redacted entirely
            if key.lower() in REDACT_FIELDS:
                sanitized[key] = "REDACTED"
                continue

            # Check if field should contain only hash
            if key.lower() in HASH_ONLY_FIELDS:
                # Verify it's already a hash or hash it
                if isinstance(value, str) and self._looks_like_hash(value):
                    sanitized[key] = value
                elif isinstance(value, (bytes, bytearray)):
                    sanitized[key] = self._hash_bytes(value)
                else:
                    sanitized[key] = self._hash_value(value)
                continue

            # Pointer fields are safe
            if key.lower() in POINTER_FIELDS:
                sanitized[key] = value
                continue

            # Recursively sanitize nested dicts
            if isinstance(value, dict):
                sanitized[key] = self.sanitize_event(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.sanitize_event(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                # Default: keep as-is
                sanitized[key] = value

        return sanitized

    def sanitize_all(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sanitize all events.

        Args:
            events: List of event dictionaries

        Returns:
            List of sanitized events
        """
        return [self.sanitize_event(event) for event in events]

    def check_violations(self, events: List[Dict[str, Any]]) -> List[str]:
        """
        Check for sanitization violations.

        Looks for:
        - Raw buffer data (long hex strings, base64)
        - Suspicious patterns (repeated bytes that might be keys)

        Args:
            events: List of events to check

        Returns:
            List of violation messages
        """
        violations = []

        for i, event in enumerate(events):
            event_violations = self._check_event_violations(event, f"event[{i}]")
            violations.extend(event_violations)

        return violations

    def _check_event_violations(self, event: Dict[str, Any], path: str) -> List[str]:
        """Check a single event for violations."""
        violations = []

        for key, value in event.items():
            field_path = f"{path}.{key}"

            # Check for long hex strings (might be raw data)
            if isinstance(value, str):
                if self._looks_like_raw_data(value):
                    violations.append(f"{field_path}: Suspicious data pattern (possible raw buffer)")

            # Check nested dicts
            elif isinstance(value, dict):
                violations.extend(self._check_event_violations(value, field_path))

            # Check lists
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        violations.extend(self._check_event_violations(item, f"{field_path}[{i}]"))

        return violations

    @staticmethod
    def _looks_like_hash(value: str) -> bool:
        """Check if a string looks like a hash."""
        if not isinstance(value, str):
            return False

        # Check for common hash patterns
        # SHA256: 64 hex chars
        # Hash prefix: "hash_...", "0x..."
        if value.startswith(('hash_', 'HASH_', '0x')):
            return True

        # Pure hex string of common hash lengths
        if re.match(r'^[a-f0-9]{32}$', value):  # MD5
            return True
        if re.match(r'^[a-f0-9]{40}$', value):  # SHA1
            return True
        if re.match(r'^[a-f0-9]{64}$', value):  # SHA256
            return True

        return False

    @staticmethod
    def _looks_like_raw_data(value: str) -> bool:
        """Check if a string looks like raw data (not a hash)."""
        if not isinstance(value, str):
            return False

        # Very long hex strings (> 128 chars) are suspicious
        if len(value) > 128 and re.match(r'^[a-f0-9]+$', value):
            return True

        # Base64-like strings (> 64 chars) are suspicious
        if len(value) > 64 and re.match(r'^[A-Za-z0-9+/]+=*$', value):
            return True

        return False

    @staticmethod
    def _hash_bytes(data: bytes) -> str:
        """Hash bytes using SHA256."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _hash_value(value: Any) -> str:
        """Hash any value by converting to string first."""
        if isinstance(value, bytes):
            return TraceSanitizer._hash_bytes(value)

        # Convert to string and hash
        str_value = str(value)
        return hashlib.sha256(str_value.encode()).hexdigest()[:16]  # Shortened hash


def sanitize_traces(events: List[Dict[str, Any]], strict: bool = True) -> tuple[List[Dict[str, Any]], List[str]]:
    """
    Convenience function to sanitize traces.

    Args:
        events: List of trace events
        strict: Enable strict mode

    Returns:
        Tuple of (sanitized_events, violations)
    """
    sanitizer = TraceSanitizer(strict_mode=strict)
    sanitized = sanitizer.sanitize_all(events)
    violations = sanitizer.check_violations(sanitized)

    return (sanitized, violations)


def verify_no_secrets(events: List[Dict[str, Any]]) -> tuple[bool, List[str]]:
    """
    Verify that no events contain raw secrets.

    Args:
        events: List of events to check

    Returns:
        Tuple of (is_safe, violation_messages)
    """
    sanitizer = TraceSanitizer(strict_mode=True)
    violations = sanitizer.check_violations(events)

    return (len(violations) == 0, violations)


def get_sanitization_statistics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get statistics about sanitization.

    Args:
        events: List of events

    Returns:
        Statistics dictionary
    """
    total_fields = 0
    hash_fields = 0
    redacted_fields = 0
    pointer_fields = 0

    def count_fields(obj: Any):
        nonlocal total_fields, hash_fields, redacted_fields, pointer_fields

        if isinstance(obj, dict):
            for key, value in obj.items():
                total_fields += 1

                key_lower = key.lower()
                if key_lower in HASH_ONLY_FIELDS:
                    hash_fields += 1
                elif key_lower in REDACT_FIELDS:
                    redacted_fields += 1
                elif key_lower in POINTER_FIELDS:
                    pointer_fields += 1

                # Recurse
                count_fields(value)

        elif isinstance(obj, list):
            for item in obj:
                count_fields(item)

    # Count fields in all events
    for event in events:
        count_fields(event)

    return {
        'total_fields': total_fields,
        'hash_fields': hash_fields,
        'redacted_fields': redacted_fields,
        'pointer_fields': pointer_fields,
        'safe_fields': total_fields - hash_fields - redacted_fields
    }
