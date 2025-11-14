import sys
import json
import tempfile
from pathlib import Path

import pytest

# Ensure project root is importable while running tests. Use the helper
# in src/_repo.py so this remains correct after restructuring.
try:
    from _repo import find_repo_root

    repo_root = find_repo_root(Path(__file__).resolve())
except Exception:
    repo_root = Path(__file__).resolve().parents[1]

src_dir = repo_root / "src"
# If project uses a "src/" layout, make that directory importable so tests can
# import top-level package names (e.g. 'auditor', 'core', 'file_handler').
if src_dir.exists() and str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
# Fallback: also ensure repo root is on sys.path for any other imports.
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

# Import data classes for fixtures
from pages.results_model import (
    Finding, DynamicCall, AnalysisMetadata, ResultsDataModel
)


# ============ EXISTING FIXTURES (PRESERVED) ============


# ============ NEW SHARED FIXTURES ============

@pytest.fixture
def sample_metadata():
    """Create a sample AnalysisMetadata instance."""
    return AnalysisMetadata(
        file_hash="test_abc123def456",
        file_name="test_binary.exe",
        file_size=1024000,
        analysis_date="2025-11-12",
        static_findings_count=5,
        dynamic_events_count=3
    )


@pytest.fixture
def sample_findings(count: int = 5):
    """Create sample Finding instances."""
    def _create(num=count):
        return [
            Finding(
                id=f"finding_{i:04d}",
                type="constant_table" if i % 2 == 0 else "signature_pattern",
                name=f"Finding {i}",
                confidence=0.7 + (i * 0.03),
                evidence=f"Evidence for finding {i}",
                address=f"0x{0x400000 + i * 100:x}",
                additional_data={"index": i}
            )
            for i in range(num)
        ]
    return _create


@pytest.fixture
def sample_dynamic_calls(count: int = 3):
    """Create sample DynamicCall instances."""
    def _create(num=count):
        functions = ["CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptGenRandom"]
        return [
            DynamicCall(
                timestamp=float(i) * 0.1,
                event_type="crypto_call",
                function_name=functions[i % len(functions)],
                module_name="advapi32.dll",
                address=f"0x7ff{i:05x}",
                confidence=0.95 + (i * 0.01),
                details={"call_id": i}
            )
            for i in range(num)
        ]
    return _create


@pytest.fixture
def sample_data_model(tmp_path, sample_metadata, sample_findings, sample_dynamic_calls):
    """Create a complete ResultsDataModel with sample data."""
    file_hash = "test_abc123def456"
    model = ResultsDataModel(str(tmp_path), file_hash)

    # Set metadata
    model.metadata = sample_metadata

    # Add findings and calls
    model.static_findings = sample_findings(5)
    model.dynamic_calls = sample_dynamic_calls(3)

    return model


@pytest.fixture
def empty_data_model(tmp_path):
    """Create an empty ResultsDataModel (no findings or calls)."""
    file_hash = "empty_abc123"
    model = ResultsDataModel(str(tmp_path), file_hash)
    model.metadata.file_name = "empty.exe"
    # No findings, no dynamic calls
    return model


@pytest.fixture
def large_dataset(tmp_path):
    """Create a large ResultsDataModel with 1000+ findings."""
    file_hash = "large_abc123def456"
    model = ResultsDataModel(str(tmp_path), file_hash)

    model.metadata.file_name = "large_binary.exe"

    # Create many findings
    model.static_findings = [
        Finding(
            id=f"finding_{i:06d}",
            type="constant_table" if i % 3 == 0 else ("signature_pattern" if i % 3 == 1 else "instruction_pattern"),
            name=f"Finding {i}",
            confidence=0.5 + ((i % 50) * 0.01),
            evidence=f"Evidence for finding {i}",
            address=f"0x{0x400000 + i * 10:x}",
            additional_data={"index": i}
        )
        for i in range(1050)  # 1050 findings
    ]

    # Create many dynamic calls
    functions = ["CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptGenRandom", "MD5_Init", "SHA256_Update"]
    model.dynamic_calls = [
        DynamicCall(
            timestamp=float(i) * 0.001,
            event_type="crypto_call",
            function_name=functions[i % len(functions)],
            module_name="advapi32.dll",
            address=f"0x7ff{i % 65536:05x}",
            confidence=0.95,
            details={"call_id": i}
        )
        for i in range(250)  # 250 dynamic calls
    ]

    return model


@pytest.fixture
def corrupted_findings():
    """Create findings with edge cases and potential issues."""
    return [
        Finding(
            id="find_001",
            type="constant_table",
            name="Normal",
            confidence=0.85,
            evidence="Valid evidence",
            address="0x400000",
            additional_data={}
        ),
        Finding(
            id="find_002",
            type="unknown_type",
            name="Unknown Type",
            confidence=0.85,
            evidence="This has unknown type",
            address="0x400000",
            additional_data={}
        ),
        Finding(
            id="find_003",
            type="constant_table",
            name="Very " + "Long " * 100 + "Name",  # Very long name
            confidence=1.5,  # Invalid confidence (>1.0)
            evidence="",  # Empty evidence
            address="not_hex",  # Invalid address
            additional_data={}
        ),
        Finding(
            id="",  # Empty ID
            type="constant_table",
            name="No ID",
            confidence=0.5,
            evidence="Missing ID",
            address="0x400000",
            additional_data={}
        ),
    ]


@pytest.fixture
def temp_export_dir():
    """Create a temporary directory for export tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "unit: Unit tests (fast, isolated)"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests (slower, multiple components)"
    )
    config.addinivalue_line(
        "markers", "slow: Slow tests (>1 second)"
    )
    config.addinivalue_line(
        "markers", "ui: UI-related tests (may require display)"
    )
    config.addinivalue_line(
        "markers", "export: Export-related tests"
    )
    config.addinivalue_line(
        "markers", "filtering: Filtering-related tests"
    )
    config.addinivalue_line(
        "markers", "stress: Performance/stress tests"
    )
