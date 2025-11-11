"""
Trace manager for collecting and limiting trace events.

Manages trace collection with configurable limits:
- Max events (10,000)
- Max size (10 MB)
- Max crypto calls (100)
"""

import json
from typing import List, Dict, Any
from .context import TraceEvent, TraceSummary


class TraceManager:
    """
    Manages trace collection with limits.

    Ensures traces don't exhaust memory or storage by enforcing limits:
    - Max 10,000 events total
    - Max 10 MB total size
    - Max 100 crypto calls

    Thread-safe for use with Frida message handlers.

    Usage:
        manager = TraceManager(max_events=10000, max_size_mb=10)

        # Add events from Frida
        for event in frida_events:
            if manager.add_event(event):
                print("Added")
            else:
                print("Limit reached")

        # Get summary
        summary = manager.get_summary()
        print(f"Collected {summary.total_events} events")

        # Write to file
        manager.write_ndjson('/path/to/trace.ndjson')
    """

    def __init__(
        self,
        max_events: int = 10000,
        max_size_mb: int = 10,
        max_crypto_calls: int = 100
    ):
        """
        Initialize trace manager.

        Args:
            max_events: Maximum total events
            max_size_mb: Maximum total size in MB
            max_crypto_calls: Maximum crypto call events
        """
        self.max_events = max_events
        self.max_size = max_size_mb * 1024 * 1024  # Convert to bytes
        self.max_crypto_calls = max_crypto_calls

        self.events: List[Dict[str, Any]] = []
        self.total_size = 0
        self.crypto_call_count = 0
        self.crypto_return_count = 0
        self.memory_scan_count = 0
        self.call_graph_edge_count = 0

        # Limit flags
        self.max_events_reached = False
        self.max_size_reached = False
        self.max_crypto_calls_reached = False

    def add_event(self, event: Dict[str, Any]) -> bool:
        """
        Add event to collection.

        Args:
            event: Event dictionary from Frida

        Returns:
            True if added, False if limit reached
        """
        # Check total event limit
        if len(self.events) >= self.max_events:
            self.max_events_reached = True
            return False

        # Check event type
        event_type = event.get('type', 'unknown')

        # Diagnostic logging
        if event_type == 'crypto_call':
            function = event.get('function', 'unknown')
            module = event.get('module', 'unknown')
            print(f"[TraceManager] Crypto call captured: {module}!{function}")

        # Check crypto call limit
        if event_type == 'crypto_call':
            if self.crypto_call_count >= self.max_crypto_calls:
                self.max_crypto_calls_reached = True
                print(f"[TraceManager] Crypto call limit reached ({self.max_crypto_calls})")
                return False  # Skip this crypto call
            self.crypto_call_count += 1

        elif event_type == 'crypto_return':
            self.crypto_return_count += 1

        elif event_type == 'memory_scan':
            self.memory_scan_count += 1

        elif event_type == 'call_graph':
            self.call_graph_edge_count += 1

        else:
            print(f"[TraceManager] Unknown event type: {event_type}")

        # Estimate event size
        event_size = len(json.dumps(event, separators=(',', ':')))

        # Check size limit
        if self.total_size + event_size > self.max_size:
            self.max_size_reached = True
            print(f"[TraceManager] Size limit reached ({self.total_size + event_size} > {self.max_size})")
            return False

        # Add event
        self.events.append(event)
        self.total_size += event_size

        return True

    def get_events(self) -> List[Dict[str, Any]]:
        """Get all collected events (creates copy)."""
        return self.events.copy()

    def get_event_count(self) -> int:
        """Get total number of events."""
        return len(self.events)

    def get_summary(self) -> TraceSummary:
        """
        Get trace collection summary.

        Returns:
            TraceSummary with statistics
        """
        return TraceSummary(
            total_events=len(self.events),
            crypto_calls=self.crypto_call_count,
            crypto_returns=self.crypto_return_count,
            memory_scans=self.memory_scan_count,
            call_graph_edges=self.call_graph_edge_count,
            size_bytes=self.total_size,
            limits_reached={
                'max_events': self.max_events_reached,
                'max_crypto_calls': self.max_crypto_calls_reached,
                'max_size': self.max_size_reached
            }
        )

    def write_ndjson(self, output_path: str):
        """
        Write events as NDJSON (Newline-Delimited JSON).

        Each line is a complete JSON object.

        Args:
            output_path: Path to output file
        """
        with open(output_path, 'w') as f:
            for event in self.events:
                f.write(json.dumps(event, separators=(',', ':')) + '\n')

    def write_ndjson_atomic(self, output_path: str):
        """
        Write events as NDJSON atomically (via temp file).

        Args:
            output_path: Path to output file
        """
        import os

        temp_path = output_path + '.tmp'

        # Write to temp file
        with open(temp_path, 'w') as f:
            for event in self.events:
                f.write(json.dumps(event, separators=(',', ':')) + '\n')

        # Atomic rename
        if os.path.exists(output_path):
            os.remove(output_path)
        os.rename(temp_path, output_path)

    def get_limits_info(self) -> Dict[str, Any]:
        """
        Get information about limits.

        Returns:
            Dictionary with limit status
        """
        return {
            'limits': {
                'max_events': self.max_events,
                'max_size_mb': self.max_size // (1024 * 1024),
                'max_crypto_calls': self.max_crypto_calls
            },
            'current': {
                'events': len(self.events),
                'size_mb': self.total_size / (1024 * 1024),
                'crypto_calls': self.crypto_call_count
            },
            'limits_reached': {
                'max_events': self.max_events_reached,
                'max_size': self.max_size_reached,
                'max_crypto_calls': self.max_crypto_calls_reached
            },
            'percentage_used': {
                'events': (len(self.events) / self.max_events) * 100 if self.max_events > 0 else 0,
                'size': (self.total_size / self.max_size) * 100 if self.max_size > 0 else 0,
                'crypto_calls': (self.crypto_call_count / self.max_crypto_calls) * 100 if self.max_crypto_calls > 0 else 0
            }
        }

    def clear(self):
        """Clear all collected events."""
        self.events.clear()
        self.total_size = 0
        self.crypto_call_count = 0
        self.crypto_return_count = 0
        self.memory_scan_count = 0
        self.call_graph_edge_count = 0
        self.max_events_reached = False
        self.max_size_reached = False
        self.max_crypto_calls_reached = False


def load_ndjson(input_path: str) -> List[Dict[str, Any]]:
    """
    Load events from NDJSON file.

    Args:
        input_path: Path to NDJSON file

    Returns:
        List of event dictionaries
    """
    events = []

    with open(input_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse line {line_num}: {e}")

    return events


def filter_events_by_type(events: List[Dict[str, Any]], event_type: str) -> List[Dict[str, Any]]:
    """
    Filter events by type.

    Args:
        events: List of events
        event_type: Event type to filter (e.g., 'crypto_call')

    Returns:
        Filtered list of events
    """
    return [e for e in events if e.get('type') == event_type]


def get_event_statistics(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Get statistics for a list of events.

    Args:
        events: List of events

    Returns:
        Statistics dictionary
    """
    if not events:
        return {'total': 0}

    # Count by type
    by_type = {}
    for event in events:
        event_type = event.get('type', 'unknown')
        by_type[event_type] = by_type.get(event_type, 0) + 1

    # Get time range
    timestamps = [e.get('timestamp', 0) for e in events if 'timestamp' in e]
    time_range = {
        'start': min(timestamps) if timestamps else None,
        'end': max(timestamps) if timestamps else None,
        'duration_ms': (max(timestamps) - min(timestamps)) if timestamps and len(timestamps) > 1 else 0
    }

    return {
        'total': len(events),
        'by_type': by_type,
        'time_range': time_range
    }
