"""
Context and result data structures for dynamic analysis.

Provides type-safe dataclasses for passing context and returning results
from dynamic analysis runs.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import platform
import sys


@dataclass
class ToolVersions:
    """Tool versions for cache validation."""
    frida: str = ""
    python: str = field(default_factory=lambda: f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    detector_version: str = "dynamic-detect/0.1.0"
    platform: str = field(default_factory=platform.system)


@dataclass
class DynamicContext:
    """
    Context for dynamic analysis run.

    This dataclass encapsulates all configuration and paths needed
    to perform a dynamic analysis run. No global state is used.

    Attributes:
        file_hash: SHA256 hash of the binary being analyzed
        preproc_dir: Path to preprocessing artifacts (preproc/<hash>/)
        hints_path: Path to hints.json from static analysis
        analysis_base: Base directory for analysis outputs
        mode: Execution mode - 'spawn' (launch) or 'attach' (hook running process)
        attach_pid: Process ID for attach mode (required if mode='attach')
        timeout: Wall-clock timeout in seconds (default: 500)
        memory_limit: Memory limit in MB (default: 512)
        force: Bypass cache and force re-analysis
        config_path: Optional path to dynamic_config.json for per-binary settings
        tool_versions: Tool versions for cache validation
        instrumenters: Which instrumenters to enable
        user_id: Optional user identifier for quota tracking (Phase 8)
    """
    file_hash: str
    preproc_dir: str
    hints_path: str
    analysis_base: str
    mode: str = "spawn"  # 'spawn' | 'attach'
    attach_pid: Optional[int] = None
    timeout: int = 500  # seconds
    memory_limit: int = 512  # MB
    force: bool = False
    config_path: Optional[str] = None
    tool_versions: ToolVersions = field(default_factory=ToolVersions)
    instrumenters: Dict[str, bool] = field(default_factory=lambda: {
        'crypto_ops': True,
        'memory_scan': False,  # Optional, lightweight
        'call_graph': False    # Optional
    })
    user_id: Optional[str] = None  # For quota tracking (Phase 8)

    def __post_init__(self):
        """Validate context after initialization."""
        if self.mode not in ['spawn', 'attach']:
            raise ValueError(f"Invalid mode: {self.mode}. Must be 'spawn' or 'attach'")

        if self.mode == 'attach' and self.attach_pid is None:
            raise ValueError("attach_pid required when mode='attach'")

        if self.timeout <= 0:
            raise ValueError(f"Invalid timeout: {self.timeout}. Must be positive")

        if self.memory_limit <= 0:
            raise ValueError(f"Invalid memory_limit: {self.memory_limit}. Must be positive")


@dataclass
class DynamicResult:
    """
    Result from dynamic analysis.

    This dataclass encapsulates the results of a dynamic analysis run.
    It always returns successfully (never throws), with errors captured
    in the errors list.

    Attributes:
        file_hash: SHA256 hash of the analyzed binary
        dynamic_results_path: Path to dynamic_results.json (None if failed)
        trace_path: Path to trace.ndjson (None if failed)
        cached: Whether result was loaded from cache
        incomplete: Whether run was incomplete (timeout/crash)
        incomplete_reason: Reason for incomplete run (e.g., "timeout", "crash")
        summary: High-level summary of findings
        errors: List of error messages (empty if successful)
    """
    file_hash: str
    dynamic_results_path: Optional[str] = None
    trace_path: Optional[str] = None
    cached: bool = False
    incomplete: bool = False
    incomplete_reason: Optional[str] = None
    summary: Dict[str, Any] = field(default_factory=dict)
    errors: Optional[List[str]] = None

    def __post_init__(self):
        """Initialize errors list if None."""
        if self.errors is None:
            self.errors = []

    def add_error(self, error: str):
        """Add an error message."""
        if self.errors is None:
            self.errors = []
        self.errors.append(error)

    def is_success(self) -> bool:
        """Check if analysis was successful."""
        return len(self.errors) == 0 and self.dynamic_results_path is not None

    def is_partial_success(self) -> bool:
        """Check if analysis has partial results (incomplete but usable)."""
        return self.incomplete and self.trace_path is not None


@dataclass
class TraceEvent:
    """
    Single trace event.

    Represents a single event captured during dynamic analysis.
    Different event types have different fields.
    """
    type: str  # 'crypto_call' | 'crypto_return' | 'memory_scan' | 'call_graph'
    timestamp: float
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'type': self.type,
            'timestamp': self.timestamp,
            **self.data
        }


@dataclass
class TraceSummary:
    """Summary statistics for collected traces."""
    total_events: int = 0
    crypto_calls: int = 0
    crypto_returns: int = 0
    memory_scans: int = 0
    call_graph_edges: int = 0
    size_bytes: int = 0
    limits_reached: Dict[str, bool] = field(default_factory=lambda: {
        'max_events': False,
        'max_crypto_calls': False,
        'max_size': False
    })
