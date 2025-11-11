"""
Unit tests for dynamic detection components.

Tests individual modules and components in isolation.
Covers context, config, sanitizer, trace manager, and packaging.
"""

import sys
import json
import tempfile
import os
from pathlib import Path

# Fix encoding for Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from auditor.detectors.dynamic_detection.context import (
    DynamicContext, DynamicResult, TraceEvent, ToolVersions, TraceSummary
)
from auditor.detectors.dynamic_detection.config import Config
from auditor.detectors.dynamic_detection.traces_sanitizer import TraceSanitizer, sanitize_traces
from auditor.detectors.dynamic_detection.trace_manager import TraceManager
from auditor.detectors.dynamic_detection.results_packager import (
    generate_findings, generate_summary, validate_results_structure
)


def test_context_dataclass():
    """Test DynamicContext creation and validation."""
    print("\n" + "="*60)
    print("TEST: DynamicContext Dataclass")
    print("="*60)

    try:
        ctx = DynamicContext(
            file_hash="abc123",
            preproc_dir="/tmp/preproc/abc123",
            hints_path="/tmp/analysis/static/abc123/hints.json",
            analysis_base="/tmp",
            mode="spawn",
            timeout=500,
            memory_limit=1024,
            instrumenters={"crypto_ops": True, "memory_scan": False}
        )

        assert ctx.file_hash == "abc123"
        assert ctx.mode == "spawn"
        assert ctx.timeout == 500
        assert ctx.memory_limit == 1024
        assert ctx.instrumenters["crypto_ops"] == True
        assert ctx.tool_versions.python is not None

        print("[OK] Context created with all required fields")
        print(f"     File hash: {ctx.file_hash}")
        print(f"     Mode: {ctx.mode}")
        print(f"     Timeout: {ctx.timeout}s")
        print(f"     Memory: {ctx.memory_limit}MB")
        print(f"     Tool versions: python={ctx.tool_versions.python}")

        return True
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_dynamic_result_state():
    """Test DynamicResult state management."""
    print("\n" + "="*60)
    print("TEST: DynamicResult State Management")
    print("="*60)

    try:
        result = DynamicResult(file_hash="test123")

        # Test initial state
        assert not result.is_success(), "Should not be successful initially"
        assert result.cached == False, "Should not be cached initially"
        assert len(result.errors) == 0, "Should have no errors initially"
        print("[OK] Initial state correct")

        # Test adding errors
        result.add_error("Test error 1")
        result.add_error("Test error 2")
        assert len(result.errors) == 2, "Should have 2 errors"
        print("[OK] Error tracking works")

        # Test setting paths
        result.dynamic_results_path = "/tmp/results.json"
        result.trace_path = "/tmp/traces.ndjson"
        assert result.dynamic_results_path == "/tmp/results.json"
        assert result.trace_path == "/tmp/traces.ndjson"
        print("[OK] Path setting works")

        # Test incomplete status
        result.incomplete = True
        result.incomplete_reason = "Timeout"
        assert result.incomplete == True
        assert result.incomplete_reason == "Timeout"
        print("[OK] Incomplete status works")

        return True
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_trace_event_creation():
    """Test TraceEvent dataclass creation."""
    print("\n" + "="*60)
    print("TEST: TraceEvent Creation")
    print("="*60)

    try:
        event = TraceEvent(
            type="crypto_call",
            timestamp=1000,
            data={
                "function": "BCryptEncrypt",
                "module": "bcrypt.dll",
                "args_hashes": {"arg0": "hash123"}
            }
        )

        assert event.type == "crypto_call"
        assert event.timestamp == 1000
        assert event.data["function"] == "BCryptEncrypt"
        print("[OK] TraceEvent created successfully")
        print(f"     Type: {event.type}")
        print(f"     Timestamp: {event.timestamp}")
        print(f"     Function: {event.data['function']}")

        return True
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_trace_sanitizer():
    """Test trace sanitization."""
    print("\n" + "="*60)
    print("TEST: Trace Sanitization")
    print("="*60)

    try:
        sanitizer = TraceSanitizer(strict_mode=True)

        # Test buffer hashing
        event = {
            "type": "crypto_call",
            "function": "BCryptEncrypt",
            "buffer": "raw_secret_data_here",
            "address": "0x1000"
        }

        sanitized = sanitizer.sanitize_event(event)

        # Buffer should be hashed
        assert sanitized["buffer"] != "raw_secret_data_here"
        assert sanitized["address"] == "0x1000"  # Address preserved
        print("[OK] Buffer hashing works")
        print(f"     Original buffer: raw_secret_data_here")
        print(f"     Sanitized buffer: {sanitized['buffer'][:16]}...")

        # Test hash detection
        is_hash = sanitizer._looks_like_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert is_hash, "Should recognize SHA256 hash"
        print("[OK] Hash detection works")

        # Test violation detection
        suspicious_event = {
            "field": "a" * 200  # Very long hex-like string
        }
        violations = sanitizer.check_violations([suspicious_event])
        print(f"[OK] Violation detection works ({len(violations)} violations found)")

        return True
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_trace_manager():
    """Test trace manager event collection."""
    print("\n" + "="*60)
    print("TEST: Trace Manager")
    print("="*60)

    try:
        manager = TraceManager(max_events=100, max_crypto_calls=10, max_size_mb=10)

        # Add events
        for i in range(5):
            manager.add_event({
                "type": "crypto_call",
                "timestamp": i * 100,
                "function": f"Func{i}",
                "module": "test.dll"
            })

        assert manager.get_event_count() == 5
        print(f"[OK] Events collected: {manager.get_event_count()}")

        # Test summary
        summary = manager.get_summary()
        assert summary.total_events == 5
        assert summary.crypto_calls == 5
        print(f"[OK] Summary generated")
        print(f"     Total events: {summary.total_events}")
        print(f"     Crypto calls: {summary.crypto_calls}")

        # Test event retrieval
        events = manager.get_events()
        assert len(events) == 5
        assert events[0]["timestamp"] == 0
        print(f"[OK] Events retrieved correctly")

        # Test limit enforcement
        manager2 = TraceManager(max_events=3, max_crypto_calls=2, max_size_mb=1)
        for i in range(5):
            manager2.add_event({
                "type": "crypto_call",
                "timestamp": i,
                "data": f"data_{i}" * 100
            })

        assert manager2.get_event_count() <= 3
        print(f"[OK] Limits enforced: {manager2.get_event_count()} events (max 3)")

        return True
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_findings_generation():
    """Test findings generation from events."""
    print("\n" + "="*60)
    print("TEST: Findings Generation")
    print("="*60)

    try:
        events = [
            {"type": "crypto_call", "function": "BCryptEncrypt", "module": "bcrypt.dll", "hint_id": "h1"},
            {"type": "crypto_call", "function": "BCryptEncrypt", "module": "bcrypt.dll", "hint_id": "h1"},
            {"type": "crypto_call", "function": "CryptDecrypt", "module": "crypt32.dll", "hint_id": "h2"},
            {"type": "memory_scan", "range": "0x1000-0x2000", "entropy": 7.5}
        ]

        hints_data = {
            "hints": [
                {"id": "h1", "name": "BCrypt usage", "type": "crypto_function"},
                {"id": "h2", "name": "Crypt32 usage", "type": "crypto_function"}
            ]
        }

        findings = generate_findings(events, hints_data)

        assert len(findings) >= 2
        print(f"[OK] Generated {len(findings)} findings")

        # Check crypto findings
        crypto_findings = [f for f in findings if f.get("type") == "crypto_call"]
        assert len(crypto_findings) >= 2
        print(f"     Crypto findings: {len(crypto_findings)}")

        # Check BCryptEncrypt
        bcrypt_finding = next((f for f in crypto_findings if f.get("function") == "BCryptEncrypt"), None)
        assert bcrypt_finding is not None
        assert bcrypt_finding["count"] == 2
        print(f"     BCryptEncrypt: {bcrypt_finding['count']} calls")

        # Check memory findings
        memory_findings = [f for f in findings if f.get("type") == "high_entropy_memory"]
        if memory_findings:
            print(f"     Memory findings: {len(memory_findings)}")

        return True
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_summary_generation():
    """Test summary generation from events."""
    print("\n" + "="*60)
    print("TEST: Summary Generation")
    print("="*60)

    try:
        events = [
            {"type": "crypto_call", "function": "BCryptEncrypt", "module": "bcrypt.dll"},
            {"type": "crypto_call", "function": "BCryptEncrypt", "module": "bcrypt.dll"},
            {"type": "crypto_call", "function": "CryptDecrypt", "module": "crypt32.dll"},
            {"type": "memory_scan", "range": "0x1000-0x2000", "entropy": 7.5},
            {"type": "call_graph", "caller": "func1", "callee": "func2"}
        ]

        summary = generate_summary(events, execution_time_seconds=12.5)

        assert summary["total_crypto_calls"] == 3
        assert len(summary["unique_functions"]) == 2
        assert summary["high_entropy_regions"] == 1
        assert summary["call_graph_nodes"] == 1
        assert summary["execution_time_seconds"] == 12.5

        print("[OK] Summary generated correctly")
        print(f"     Total crypto calls: {summary['total_crypto_calls']}")
        print(f"     Unique functions: {len(summary['unique_functions'])}")
        print(f"     Functions: {summary['unique_functions']}")
        print(f"     High-entropy regions: {summary['high_entropy_regions']}")
        print(f"     Call graph nodes: {summary['call_graph_nodes']}")
        print(f"     Execution time: {summary['execution_time_seconds']}s")

        return True
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_results_validation():
    """Test results structure validation."""
    print("\n" + "="*60)
    print("TEST: Results Structure Validation")
    print("="*60)

    try:
        # Valid results
        valid_results = {
            "file_hash": "abc123",
            "schema_version": "1.0",
            "timestamp": "2025-11-11T12:00:00Z",
            "mode": "spawn",
            "incomplete": False,
            "summary": {
                "total_crypto_calls": 5,
                "unique_functions": ["BCryptEncrypt"],
                "execution_time_seconds": 10.0
            },
            "findings": [
                {
                    "id": "dynamic_1",
                    "type": "crypto_call",
                    "function": "BCryptEncrypt",
                    "count": 5
                }
            ],
            "trace_summary": {
                "total_events": 10,
                "crypto_calls": 5,
                "size_bytes": 1024,
                "limits_reached": {"max_events": False, "max_crypto_calls": False, "max_size": False}
            },
            "meta": {
                "tool_versions": {"frida": "16.0", "python": "3.11", "detector_version": "1.0", "platform": "win32"},
                "config": {"timeout": 500, "memory_limit": 1024, "instrumenters": {}}
            }
        }

        is_valid, errors = validate_results_structure(valid_results)
        assert is_valid, f"Valid results should pass: {errors}"
        print("[OK] Valid results pass validation")

        # Invalid results (missing required field)
        invalid_results = {
            "file_hash": "abc123",
            "schema_version": "1.0"
            # Missing other required fields
        }

        is_valid, errors = validate_results_structure(invalid_results)
        assert not is_valid, "Invalid results should fail"
        assert len(errors) > 0, "Should have error messages"
        print(f"[OK] Invalid results correctly rejected")
        print(f"     Errors: {len(errors)} issues found")

        return True
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_config_defaults():
    """Test configuration default loading."""
    print("\n" + "="*60)
    print("TEST: Configuration Defaults")
    print("="*60)

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            preproc_dir = Path(tmpdir)

            # Load config with defaults (no config file)
            config = Config.load(preproc_dir=str(preproc_dir))

            # Check defaults
            assert config.get("timeout") == 500
            assert config.get("memory_limit") == 512  # Default is 512MB not 1024
            assert config.get("max_trace_events") == 10000
            assert config.get("max_crypto_calls") == 100
            print("[OK] Configuration defaults loaded")
            print(f"     Timeout: {config.get('timeout')}s")
            print(f"     Memory: {config.get('memory_limit')}MB")
            print(f"     Max events: {config.get('max_trace_events')}")
            print(f"     Max crypto calls: {config.get('max_crypto_calls')}")

            # Create and load config file
            config_data = {
                "timeout": 600,
                "memory_limit": 2048,
                "args": ["--test"],
                "instrumenters": {
                    "crypto_ops": True,
                    "memory_scan": True
                }
            }
            config_file = preproc_dir / "dynamic_config.json"
            with open(config_file, 'w') as f:
                json.dump(config_data, f)

            # Load with custom config
            config2 = Config.load(preproc_dir=str(preproc_dir))
            assert config2.get("timeout") == 600
            assert config2.get("memory_limit") == 2048
            print("[OK] Custom configuration loaded")
            print(f"     Timeout: {config2.get('timeout')}s (custom)")
            print(f"     Memory: {config2.get('memory_limit')}MB (custom)")

            return True
    except Exception as e:
        print(f"[FAIL] {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """Run all unit tests."""
    print("\n" + "="*60)
    print("DYNAMIC DETECTION UNIT TESTS")
    print("="*60)

    tests = [
        ("Context Dataclass", test_context_dataclass),
        ("DynamicResult State", test_dynamic_result_state),
        ("TraceEvent Creation", test_trace_event_creation),
        ("Trace Sanitization", test_trace_sanitizer),
        ("Trace Manager", test_trace_manager),
        ("Findings Generation", test_findings_generation),
        ("Summary Generation", test_summary_generation),
        ("Results Validation", test_results_validation),
        ("Configuration Defaults", test_config_defaults)
    ]

    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed))
        except Exception as e:
            print(f"[ERROR] Test crashed: {e}")
            results.append((name, False))

    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)

    passed = sum(1 for _, p in results if p)
    total = len(results)

    for name, passed_flag in results:
        status = "[PASS]" if passed_flag else "[FAIL]"
        print(f"{status} {name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n[SUCCESS] All unit tests passed!")
        return 0
    else:
        print(f"\n[FAILURE] {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
