"""Data model for Results Page.

Handles loading and managing analysis results from the case folder structure.
Supports both static and dynamic analysis results with caching and statistics.

Case Structure:
case/
├── analysis/
│   ├── static/
│   │   └── <file_hash>/
│   │       ├── static_results.json
│   │       ├── hints.json
│   │       └── .cache_meta.json
│   └── dynamic/
│       └── <file_hash>/
│           ├── dynamic_results.json
│           ├── trace.ndjson
│           └── .cache_meta.json
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import json
import logging

logger = logging.getLogger(__name__)


# Data Classes
@dataclass
class Finding:
    """A single cryptographic finding from static analysis."""

    id: str
    type: str  # constant_table, signature_pattern, instruction_pattern, etc.
    address: Optional[str]  # Hex address if applicable
    confidence: float  # 0.0-1.0
    score: Optional[float] = None
    name: str = ""
    evidence: str = ""
    count: int = 1
    additional_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'type': self.type,
            'address': self.address,
            'confidence': self.confidence,
            'score': self.score,
            'name': self.name,
            'evidence': self.evidence,
            'count': self.count,
            'additional_data': self.additional_data
        }


@dataclass
class DynamicCall:
    """A single dynamic analysis function call or event."""

    timestamp: float
    event_type: str  # crypto_call, crypto_return, memory_scan, call_graph, error
    function_name: Optional[str] = None
    module_name: Optional[str] = None
    address: Optional[str] = None
    confidence: float = 1.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'function_name': self.function_name,
            'module_name': self.module_name,
            'address': self.address,
            'confidence': self.confidence,
            'details': self.details
        }


@dataclass
class AnalysisMetadata:
    """Metadata about the analysis."""

    file_hash: str
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    analysis_date: Optional[str] = None
    static_status: str = "unknown"  # unknown, pending, completed, failed
    dynamic_status: str = "unknown"
    static_findings_count: int = 0
    dynamic_events_count: int = 0
    analysis_duration_seconds: Optional[float] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'file_hash': self.file_hash,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'analysis_date': self.analysis_date,
            'static_status': self.static_status,
            'dynamic_status': self.dynamic_status,
            'static_findings_count': self.static_findings_count,
            'dynamic_events_count': self.dynamic_events_count,
            'analysis_duration_seconds': self.analysis_duration_seconds
        }


class ResultsDataModel:
    """
    Data model for managing analysis results.

    Loads results from the case folder structure and provides
    methods for filtering, searching, and computing statistics.
    """

    def __init__(self, case_path: str, file_hash: str):
        """
        Initialize the data model.

        Args:
            case_path: Path to the case folder (root of analysis)
            file_hash: SHA256 hash of the analyzed file
        """
        self.case_path = Path(case_path)
        self.file_hash = file_hash

        # Result data
        self.static_findings: List[Finding] = []
        self.dynamic_calls: List[DynamicCall] = []
        self.metadata = AnalysisMetadata(file_hash=file_hash)

        # Cache for statistics
        self._stats_cache: Optional[Dict[str, Any]] = None
        self._cache_valid = False

    # ======== File Path Helpers ========

    def _get_static_results_path(self) -> Path:
        """Get path to static_results.json."""
        return (
            self.case_path
            / "analysis" / "static" / self.file_hash / "static_results.json"
        )

    def _get_hints_path(self) -> Path:
        """Get path to hints.json."""
        return (
            self.case_path
            / "analysis" / "static" / self.file_hash / "hints.json"
        )

    def _get_dynamic_results_path(self) -> Path:
        """Get path to dynamic_results.json."""
        return (
            self.case_path
            / "analysis" / "dynamic" / self.file_hash / "dynamic_results.json"
        )

    def _get_trace_path(self) -> Path:
        """Get path to trace.ndjson."""
        return (
            self.case_path
            / "analysis" / "dynamic" / self.file_hash / "trace.ndjson"
        )

    # ======== Loading Methods ========

    def load_static_results(self) -> bool:
        """
        Load static analysis results from JSON file.

        Returns:
            True if loaded successfully, False if file not found or error
        """
        path = self._get_static_results_path()

        if not path.exists():
            logger.warning(f"Static results file not found: {path}")
            self.metadata.static_status = "not_found"
            return False

        try:
            with open(path, 'r') as f:
                data = json.load(f)

            # Parse findings
            self.static_findings = []
            for finding_data in data.get('findings', []):
                finding = Finding(
                    id=finding_data.get('id', f"static_{len(self.static_findings)}"),
                    type=finding_data.get('type', 'unknown'),
                    address=finding_data.get('address'),
                    confidence=float(finding_data.get('confidence', 0.5)),
                    score=finding_data.get('score'),
                    name=finding_data.get('name', ''),
                    evidence=finding_data.get('evidence', ''),
                    count=finding_data.get('count', 1),
                    additional_data=finding_data.get('additional_data', {})
                )
                self.static_findings.append(finding)

            # Update metadata
            self.metadata.static_status = "completed"
            self.metadata.static_findings_count = len(self.static_findings)
            self.metadata.analysis_date = data.get('timestamp')

            logger.info(
                f"Loaded {len(self.static_findings)} static findings from {path}"
            )
            self._invalidate_cache()
            return True

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse static results JSON: {e}")
            self.metadata.static_status = "failed"
            return False
        except Exception as e:
            logger.error(f"Error loading static results: {e}")
            self.metadata.static_status = "failed"
            return False

    def load_dynamic_results(self) -> bool:
        """
        Load dynamic analysis results from JSON file.

        Returns:
            True if loaded successfully, False if file not found or error
        """
        path = self._get_dynamic_results_path()

        if not path.exists():
            logger.warning(f"Dynamic results file not found: {path}")
            self.metadata.dynamic_status = "not_found"
            return False

        try:
            with open(path, 'r') as f:
                data = json.load(f)

            # Parse findings from dynamic results
            self.dynamic_calls = []
            for finding_data in data.get('findings', []):
                # Convert dynamic findings to DynamicCall objects
                call = DynamicCall(
                    timestamp=finding_data.get('timestamp', 0.0),
                    event_type=finding_data.get('type', 'unknown'),
                    function_name=finding_data.get('function'),
                    module_name=finding_data.get('module'),
                    address=finding_data.get('address'),
                    confidence=float(finding_data.get('confidence', 0.5)),
                    details=finding_data
                )
                self.dynamic_calls.append(call)

            # Update metadata from summary
            summary = data.get('summary', {})
            self.metadata.dynamic_status = "completed"
            self.metadata.dynamic_events_count = len(self.dynamic_calls)
            self.metadata.analysis_date = data.get('timestamp')

            logger.info(
                f"Loaded {len(self.dynamic_calls)} dynamic calls from {path}"
            )
            self._invalidate_cache()
            return True

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse dynamic results JSON: {e}")
            self.metadata.dynamic_status = "failed"
            return False
        except Exception as e:
            logger.error(f"Error loading dynamic results: {e}")
            self.metadata.dynamic_status = "failed"
            return False

    def load_all(self) -> bool:
        """
        Load both static and dynamic results.

        Returns:
            True if at least one type loaded successfully
        """
        static_ok = self.load_static_results()
        dynamic_ok = self.load_dynamic_results()
        return static_ok or dynamic_ok

    # ======== Filtering Methods ========

    def get_static_findings(
        self,
        min_confidence: float = 0.0,
        max_confidence: float = 1.0,
        finding_types: Optional[List[str]] = None,
        search_text: Optional[str] = None
    ) -> List[Finding]:
        """
        Get filtered static findings.

        Args:
            min_confidence: Minimum confidence threshold
            max_confidence: Maximum confidence threshold
            finding_types: Filter by types (if None, include all)
            search_text: Search in name/evidence (case-insensitive)

        Returns:
            Filtered list of findings
        """
        results = []

        for finding in self.static_findings:
            # Confidence filter
            if not (min_confidence <= finding.confidence <= max_confidence):
                continue

            # Type filter
            if finding_types and finding.type not in finding_types:
                continue

            # Search filter
            if search_text:
                search_lower = search_text.lower()
                if not (
                    search_lower in finding.name.lower()
                    or search_lower in finding.evidence.lower()
                ):
                    continue

            results.append(finding)

        return results

    def get_dynamic_calls_by_function(self, function_name: str) -> List[DynamicCall]:
        """Get all dynamic calls for a specific function."""
        return [
            call for call in self.dynamic_calls
            if call.function_name == function_name
        ]

    # ======== Statistics ========

    def calculate_statistics(self) -> Dict[str, Any]:
        """
        Calculate summary statistics about the analysis.

        Returns:
            Dictionary with statistical summary
        """
        if self._cache_valid and self._stats_cache:
            return self._stats_cache

        stats = {
            'static': {
                'total_findings': len(self.static_findings),
                'by_type': {},
                'by_confidence_range': {
                    'high': 0,  # 0.8-1.0
                    'medium': 0,  # 0.5-0.8
                    'low': 0  # 0.0-0.5
                },
                'average_confidence': 0.0,
                'max_confidence': 0.0,
                'min_confidence': 1.0,
            },
            'dynamic': {
                'total_calls': len(self.dynamic_calls),
                'by_type': {},
                'unique_functions': set(),
                'average_confidence': 0.0,
            },
            'metadata': self.metadata.to_dict()
        }

        # Static statistics
        if self.static_findings:
            confidences = [f.confidence for f in self.static_findings]
            stats['static']['average_confidence'] = sum(confidences) / len(confidences)
            stats['static']['max_confidence'] = max(confidences)
            stats['static']['min_confidence'] = min(confidences)

            # Count by type
            for finding in self.static_findings:
                finding_type = finding.type
                stats['static']['by_type'][finding_type] = \
                    stats['static']['by_type'].get(finding_type, 0) + 1

            # Count by confidence range
            for finding in self.static_findings:
                conf = finding.confidence
                if conf >= 0.8:
                    stats['static']['by_confidence_range']['high'] += 1
                elif conf >= 0.5:
                    stats['static']['by_confidence_range']['medium'] += 1
                else:
                    stats['static']['by_confidence_range']['low'] += 1

        # Dynamic statistics
        if self.dynamic_calls:
            confidences = [c.confidence for c in self.dynamic_calls]
            stats['dynamic']['average_confidence'] = sum(confidences) / len(confidences)

            # Count by type
            for call in self.dynamic_calls:
                event_type = call.event_type
                stats['dynamic']['by_type'][event_type] = \
                    stats['dynamic']['by_type'].get(event_type, 0) + 1

                # Track unique functions
                if call.function_name:
                    stats['dynamic']['unique_functions'].add(call.function_name)

            stats['dynamic']['unique_functions'] = len(stats['dynamic']['unique_functions'])

        self._stats_cache = stats
        self._cache_valid = True
        return stats

    # ======== Cache Management ========

    def _invalidate_cache(self):
        """Invalidate the statistics cache."""
        self._cache_valid = False

    def get_statistics(self) -> Dict[str, Any]:
        """Get cached or newly calculated statistics."""
        return self.calculate_statistics()

    # ======== Status Checking ========

    def has_static_results(self) -> bool:
        """Check if static results are available."""
        return self.metadata.static_status == "completed" and len(self.static_findings) > 0

    def has_dynamic_results(self) -> bool:
        """Check if dynamic results are available."""
        return self.metadata.dynamic_status == "completed" and len(self.dynamic_calls) > 0

    def get_status_summary(self) -> str:
        """Get human-readable status summary."""
        parts = []

        if self.metadata.static_status == "completed":
            parts.append(f"Static: {self.metadata.static_findings_count} findings")
        else:
            parts.append(f"Static: {self.metadata.static_status}")

        if self.metadata.dynamic_status == "completed":
            parts.append(f"Dynamic: {self.metadata.dynamic_events_count} events")
        else:
            parts.append(f"Dynamic: {self.metadata.dynamic_status}")

        return " | ".join(parts) if parts else "No analysis available"
