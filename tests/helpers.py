"""Testing helpers and utilities for Results Page tests.

Provides reusable utilities for building test data, validating results,
and testing complex workflows.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

from pages.results_model import Finding, DynamicCall, ResultsDataModel, AnalysisMetadata


class CaseBuilder:
    """Utility for building test case directory structures."""

    @staticmethod
    def create_with_static(
        tmpdir: Path,
        file_hash: str,
        finding_count: int = 5,
        finding_types: Optional[List[str]] = None
    ) -> Path:
        """Create a case directory with static analysis results.

        Args:
            tmpdir: Temporary directory path
            file_hash: File hash for the case
            finding_count: Number of findings to create
            finding_types: List of finding types to cycle through

        Returns:
            Path to the case directory
        """
        case_path = Path(tmpdir) / "test_case"
        case_path.mkdir()

        # Create static results directory
        static_dir = case_path / "analysis" / "static" / file_hash
        static_dir.mkdir(parents=True)

        # Create findings
        types = finding_types or ["constant_table", "signature_pattern", "instruction_pattern"]
        findings = []
        for i in range(finding_count):
            findings.append({
                "id": f"static_{i:04d}",
                "type": types[i % len(types)],
                "address": f"0x{0x400000 + i * 100:x}",
                "confidence": 0.7 + (i * 0.03),
                "score": 0.7 + (i * 0.03),
                "name": f"Finding {i}",
                "evidence": f"Evidence for finding {i}",
                "count": 1,
                "additional_data": {}
            })

        # Write static_results.json
        static_data = {
            "file_hash": file_hash,
            "schema_version": "1.0",
            "timestamp": "2025-11-12T10:00:00Z",
            "findings": findings,
            "meta": {
                "generated_at": "2025-11-12T10:00:00Z",
                "profile": "full"
            }
        }

        with open(static_dir / "static_results.json", "w") as f:
            json.dump(static_data, f)

        return case_path

    @staticmethod
    def create_with_dynamic(
        tmpdir: Path,
        file_hash: str,
        call_count: int = 5,
        functions: Optional[List[str]] = None
    ) -> Path:
        """Create a case directory with dynamic analysis results.

        Args:
            tmpdir: Temporary directory path
            file_hash: File hash for the case
            call_count: Number of dynamic calls to create
            functions: List of function names to cycle through

        Returns:
            Path to the case directory
        """
        case_path = Path(tmpdir) / "test_case"
        case_path.mkdir(exist_ok=True)

        # Create dynamic results directory
        dynamic_dir = case_path / "analysis" / "dynamic" / file_hash
        dynamic_dir.mkdir(parents=True, exist_ok=True)

        # Create calls
        func_list = functions or ["CryptEncrypt", "CryptDecrypt", "CryptHashData"]
        findings = []
        for i in range(call_count):
            findings.append({
                "id": f"dynamic_{i:04d}",
                "type": "crypto_call",
                "function": func_list[i % len(func_list)],
                "module": "advapi32.dll",
                "address": f"0x7ff{i:05x}",
                "count": i + 1,
                "confidence": 0.95 + (i * 0.01),
                "evidence": f"Call to {func_list[i % len(func_list)]}",
                "hint_ids": None
            })

        # Write dynamic_results.json
        dynamic_data = {
            "file_hash": file_hash,
            "schema_version": "1.0",
            "timestamp": "2025-11-12T11:00:00Z",
            "mode": "spawn",
            "incomplete": False,
            "summary": {
                "total_crypto_calls": call_count,
                "unique_functions": len(set(func_list[:call_count])),
                "high_entropy_regions": 2,
                "call_graph_nodes": 15,
                "execution_time_seconds": 5.5
            },
            "findings": findings,
            "trace_summary": {
                "total_events": call_count * 10,
                "crypto_calls": call_count,
                "memory_scans": 10,
                "call_graph_edges": 30,
                "size_bytes": 45000,
                "limits_reached": {
                    "max_events": False,
                    "max_crypto_calls": False,
                    "max_size": False
                }
            },
            "meta": {
                "tool_versions": {
                    "frida": "16.0",
                    "python": "3.11",
                    "detector_version": "1.0",
                    "platform": "Windows"
                },
                "config": {}
            }
        }

        with open(dynamic_dir / "dynamic_results.json", "w") as f:
            json.dump(dynamic_data, f)

        return case_path

    @staticmethod
    def create_complete_case(
        tmpdir: Path,
        file_hash: str,
        static_count: int = 10,
        dynamic_count: int = 5
    ) -> Path:
        """Create a complete case with both static and dynamic results.

        Args:
            tmpdir: Temporary directory path
            file_hash: File hash for the case
            static_count: Number of static findings
            dynamic_count: Number of dynamic calls

        Returns:
            Path to the case directory
        """
        # Create with static
        case_path = CaseBuilder.create_with_static(tmpdir, file_hash, static_count)

        # Create with dynamic (won't recreate case_path)
        CaseBuilder.create_with_dynamic(tmpdir, file_hash, dynamic_count)

        return case_path


class ModelValidator:
    """Utilities for validating ResultsDataModel state."""

    @staticmethod
    def assert_findings_loaded(
        model: ResultsDataModel,
        expected_count: int,
        message: str = ""
    ) -> None:
        """Assert that findings were loaded correctly.

        Args:
            model: ResultsDataModel to validate
            expected_count: Expected number of findings
            message: Custom assertion message

        Raises:
            AssertionError: If validation fails
        """
        assert model.has_static_results(), f"{message} - No static results loaded"
        assert len(model.static_findings) == expected_count, \
            f"{message} - Expected {expected_count} findings, got {len(model.static_findings)}"

    @staticmethod
    def assert_dynamic_calls_loaded(
        model: ResultsDataModel,
        expected_count: int,
        message: str = ""
    ) -> None:
        """Assert that dynamic calls were loaded correctly.

        Args:
            model: ResultsDataModel to validate
            expected_count: Expected number of dynamic calls
            message: Custom assertion message

        Raises:
            AssertionError: If validation fails
        """
        assert model.has_dynamic_results(), f"{message} - No dynamic results loaded"
        assert len(model.dynamic_calls) == expected_count, \
            f"{message} - Expected {expected_count} calls, got {len(model.dynamic_calls)}"

    @staticmethod
    def assert_statistics_valid(
        model: ResultsDataModel,
        min_findings: int = 0,
        max_findings: int = 100000
    ) -> None:
        """Assert that statistics are valid.

        Args:
            model: ResultsDataModel to validate
            min_findings: Minimum expected findings
            max_findings: Maximum expected findings

        Raises:
            AssertionError: If validation fails
        """
        stats = model.get_statistics()

        # Validate structure
        assert "static" in stats, "Statistics missing 'static' key"
        assert "dynamic" in stats, "Statistics missing 'dynamic' key"

        # Validate static stats
        static = stats["static"]
        assert "total_findings" in static
        assert "average_confidence" in static
        assert "by_type" in static

        # Validate ranges
        total = static["total_findings"]
        assert min_findings <= total <= max_findings, \
            f"Finding count {total} outside range [{min_findings}, {max_findings}]"

        # Validate confidence
        conf = static["average_confidence"]
        assert 0.0 <= conf <= 1.0, f"Average confidence {conf} outside [0.0, 1.0]"

    @staticmethod
    def assert_metadata_valid(model: ResultsDataModel) -> None:
        """Assert that metadata is properly set.

        Args:
            model: ResultsDataModel to validate

        Raises:
            AssertionError: If metadata is invalid
        """
        assert model.metadata is not None, "Metadata not set"
        assert model.metadata.file_hash, "file_hash not set"
        assert isinstance(model.metadata.file_hash, str), "file_hash must be string"


class DataValidator:
    """Utilities for validating test data."""

    @staticmethod
    def validate_finding(finding: Finding) -> List[str]:
        """Validate a Finding object and return list of issues.

        Args:
            finding: Finding to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        issues = []

        if not finding.id:
            issues.append("Finding ID is empty")

        if not finding.type:
            issues.append("Finding type is empty")

        if not (0.0 <= finding.confidence <= 1.0):
            issues.append(f"Confidence {finding.confidence} outside [0.0, 1.0]")

        if finding.address and not finding.address.startswith("0x"):
            issues.append(f"Invalid address format: {finding.address}")

        if len(finding.name) > 500:
            issues.append(f"Name too long ({len(finding.name)} chars)")

        return issues

    @staticmethod
    def validate_dynamic_call(call: DynamicCall) -> List[str]:
        """Validate a DynamicCall object and return list of issues.

        Args:
            call: DynamicCall to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        issues = []

        if call.timestamp < 0:
            issues.append(f"Negative timestamp: {call.timestamp}")

        if not call.event_type:
            issues.append("Event type is empty")

        if not (0.0 <= call.confidence <= 1.0):
            issues.append(f"Confidence {call.confidence} outside [0.0, 1.0]")

        return issues


class DataGenerator:
    """Utility for generating test data of various sizes and types."""

    @staticmethod
    def create_findings(
        count: int,
        confidence_range: tuple = (0.5, 1.0),
        types: Optional[List[str]] = None
    ) -> List[Finding]:
        """Generate a list of Finding objects.

        Args:
            count: Number of findings to generate
            confidence_range: (min, max) confidence range
            types: List of types to cycle through

        Returns:
            List of Finding objects
        """
        type_list = types or ["constant_table", "signature_pattern", "instruction_pattern"]
        findings = []

        for i in range(count):
            min_conf, max_conf = confidence_range
            conf = min_conf + (i % 100) * (max_conf - min_conf) / 100

            findings.append(Finding(
                id=f"gen_find_{i:06d}",
                type=type_list[i % len(type_list)],
                name=f"Generated Finding {i}",
                confidence=conf,
                evidence=f"Generated evidence {i}",
                address=f"0x{0x400000 + i * 10:x}",
                additional_data={"generated": True}
            ))

        return findings

    @staticmethod
    def create_dynamic_calls(
        count: int,
        functions: Optional[List[str]] = None
    ) -> List[DynamicCall]:
        """Generate a list of DynamicCall objects.

        Args:
            count: Number of calls to generate
            functions: List of functions to cycle through

        Returns:
            List of DynamicCall objects
        """
        func_list = functions or ["CryptEncrypt", "CryptDecrypt", "CryptHashData", "MD5_Init"]
        calls = []

        for i in range(count):
            calls.append(DynamicCall(
                timestamp=float(i) * 0.01,
                event_type="crypto_call",
                function_name=func_list[i % len(func_list)],
                module_name="advapi32.dll",
                address=f"0x7ff{i % 65536:05x}",
                confidence=0.95 + (i % 5) * 0.01,
                details={"generated": True}
            ))

        return calls


class CallbackCapture:
    """Utility for capturing and verifying callback invocations."""

    def __init__(self):
        """Initialize the callback capture."""
        self.calls: List[tuple] = []
        self.call_count = 0

    def callback(self, *args, **kwargs):
        """Generic callback that captures arguments.

        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
        """
        self.calls.append((args, kwargs))
        self.call_count += 1

    def reset(self):
        """Reset the captured calls."""
        self.calls.clear()
        self.call_count = 0

    def assert_called(self, times: int = 1) -> None:
        """Assert callback was called specific number of times.

        Args:
            times: Expected call count

        Raises:
            AssertionError: If call count doesn't match
        """
        assert self.call_count == times, \
            f"Expected {times} calls, got {self.call_count}"

    def assert_called_with(self, *args, **kwargs) -> None:
        """Assert callback was called with specific arguments.

        Args:
            *args: Expected positional arguments
            **kwargs: Expected keyword arguments

        Raises:
            AssertionError: If arguments don't match
        """
        expected = (args, kwargs)
        assert expected in self.calls, \
            f"Callback not called with {args}, {kwargs}. Calls: {self.calls}"

    def get_last_args(self) -> tuple:
        """Get the last call's positional arguments.

        Returns:
            Positional arguments from last call, or empty tuple if never called
        """
        if self.calls:
            return self.calls[-1][0]
        return ()

    def get_last_kwargs(self) -> dict:
        """Get the last call's keyword arguments.

        Returns:
            Keyword arguments from last call, or empty dict if never called
        """
        if self.calls:
            return self.calls[-1][1]
        return {}
