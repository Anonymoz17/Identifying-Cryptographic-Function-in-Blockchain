"""Comprehensive workflow tests for static detection system.

Tests the complete batch processing flow including:
- Single binary analysis
- Batch processing of multiple binaries
- Caching behavior
- Error handling
- Ghidra integration
"""

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from auditor.detectors.static_detection.runner import StaticRunner
from auditor.detectors.static_detection.context import RunContext, ToolVersions


# Test fixtures
@pytest.fixture
def mock_case_dir(tmp_path):
    """Create a mock case directory with multiple preprocessed binaries."""
    case_dir = tmp_path / "test_case"
    preproc_dir = case_dir / "preproc"
    
    # Create 3 mock binaries
    binaries = []
    for i in range(3):
        file_hash = f"hash{'0' * (60 - len(str(i)))}{i}"
        binary_dir = preproc_dir / file_hash
        binary_dir.mkdir(parents=True)
        
        # Create input.bin with different content
        input_bin = binary_dir / "input.bin"
        input_bin.write_bytes(b"binary content " + str(i).encode() * 100)
        
        # Create metadata.json
        metadata = {
            "producer": "test",
            "file_hash": file_hash,
            "size": input_bin.stat().st_size,
            "format": "ELF",
            "arch": "x86_64"
        }
        (binary_dir / "metadata.json").write_text(json.dumps(metadata))
        binaries.append(file_hash)
    
    return case_dir, binaries


@pytest.fixture
def single_binary_case(tmp_path):
    """Create a case with a single binary for testing."""
    case_dir = tmp_path / "single_case"
    preproc_dir = case_dir / "preproc"
    file_hash = "abc123" + "0" * 58
    binary_dir = preproc_dir / file_hash
    binary_dir.mkdir(parents=True)
    
    # Create input.bin
    input_bin = binary_dir / "input.bin"
    input_bin.write_bytes(b"test binary content")
    
    # Create metadata.json
    metadata = {
        "producer": "test",
        "file_hash": file_hash,
        "size": input_bin.stat().st_size
    }
    (binary_dir / "metadata.json").write_text(json.dumps(metadata))
    
    return case_dir, file_hash


# Test 1: Single binary analysis
def test_single_binary_analysis(single_binary_case):
    """Test analyzing a single binary in a case."""
    case_dir, file_hash = single_binary_case
    
    runner = StaticRunner()
    ctx = RunContext(
        file_hash=file_hash,
        preproc_dir=str(case_dir),
        analysis_base=str(case_dir),
        profile="quick",
        force=False
    )
    
    result = runner.run(ctx)
    
    # Verify results
    assert result.file_hash == file_hash
    assert not result.cached  # First run should not be cached
    assert result.errors is None or result.errors == []
    assert result.static_results_path is not None
    assert Path(result.static_results_path).exists()
    
    # Verify analysis directory structure
    analysis_dir = case_dir / "analysis" / "static" / file_hash
    assert analysis_dir.exists()
    assert (analysis_dir / "static_results.json").exists()
    assert (analysis_dir / "hints.json").exists()
    assert (analysis_dir / ".cache_meta.json").exists()


# Test 2: Auto-select single binary (no file_hash specified)
def test_auto_select_single_binary(single_binary_case):
    """Test that runner auto-selects when only one binary exists."""
    case_dir, file_hash = single_binary_case
    
    runner = StaticRunner()
    ctx = RunContext(
        file_hash="",  # Empty - should auto-select
        preproc_dir=str(case_dir),
        analysis_base=str(case_dir),
        profile="quick"
    )
    
    result = runner.run(ctx)
    
    assert result.file_hash == file_hash
    assert result.errors is None or result.errors == []


# Test 3: Multiple binaries require explicit file_hash
def test_multiple_binaries_require_hash(mock_case_dir):
    """Test that runner requires file_hash when multiple binaries exist."""
    case_dir, binaries = mock_case_dir
    
    runner = StaticRunner()
    ctx = RunContext(
        file_hash="",  # Empty - should fail
        preproc_dir=str(case_dir),
        analysis_base=str(case_dir),
        profile="quick"
    )
    
    result = runner.run(ctx)
    
    # Should have error about multiple preproc cases
    assert result.errors is not None
    assert len(result.errors) > 0
    assert "multiple preproc cases" in result.errors[0]


# Test 4: Batch processing simulation
def test_batch_processing_multiple_binaries(mock_case_dir):
    """Test processing all binaries in a case (simulates UI batch mode)."""
    case_dir, binaries = mock_case_dir
    
    runner = StaticRunner()
    results = []
    
    # Process each binary
    for file_hash in binaries:
        ctx = RunContext(
            file_hash=file_hash,
            preproc_dir=str(case_dir),
            analysis_base=str(case_dir),
            profile="quick",
            force=False
        )
        result = runner.run(ctx)
        results.append((file_hash, result))
    
    # Verify all succeeded
    assert len(results) == 3
    for file_hash, result in results:
        assert result.file_hash == file_hash
        assert result.errors is None or result.errors == []
        assert result.static_results_path is not None
        
        # Check analysis directory exists
        analysis_dir = case_dir / "analysis" / "static" / file_hash
        assert analysis_dir.exists()
        assert (analysis_dir / "static_results.json").exists()


# Test 5: Caching behavior
def test_caching_on_second_run(single_binary_case):
    """Test that second run uses cache."""
    case_dir, file_hash = single_binary_case
    
    runner = StaticRunner()
    ctx = RunContext(
        file_hash=file_hash,
        preproc_dir=str(case_dir),
        analysis_base=str(case_dir),
        profile="quick",
        force=False
    )
    
    # First run
    result1 = runner.run(ctx)
    assert not result1.cached
    
    # Second run - should use cache
    result2 = runner.run(ctx)
    assert result2.cached
    assert result2.file_hash == file_hash


# Test 6: Force re-run ignores cache
def test_force_rerun_ignores_cache(single_binary_case):
    """Test that force=True bypasses cache."""
    case_dir, file_hash = single_binary_case
    
    runner = StaticRunner()
    
    # First run
    ctx1 = RunContext(
        file_hash=file_hash,
        preproc_dir=str(case_dir),
        analysis_base=str(case_dir),
        profile="quick",
        force=False
    )
    result1 = runner.run(ctx1)
    assert not result1.cached
    
    # Second run with force - should NOT use cache
    ctx2 = RunContext(
        file_hash=file_hash,
        preproc_dir=str(case_dir),
        analysis_base=str(case_dir),
        profile="quick",
        force=True
    )
    result2 = runner.run(ctx2)
    assert not result2.cached


# Test 7: Results structure validation
def test_results_structure(single_binary_case):
    """Test that static_results.json has correct structure."""
    case_dir, file_hash = single_binary_case
    
    runner = StaticRunner()
    ctx = RunContext(
        file_hash=file_hash,
        preproc_dir=str(case_dir),
        analysis_base=str(case_dir),
        profile="quick"
    )
    
    result = runner.run(ctx)
    
    # Load and validate static_results.json
    with open(result.static_results_path, 'r') as f:
        results_data = json.load(f)
    
    # Check required fields
    assert "file_hash" in results_data
    assert results_data["file_hash"] == file_hash
    assert "schema_version" in results_data
    assert "timestamp" in results_data
    assert "findings" in results_data
    assert isinstance(results_data["findings"], list)


# Test 8: Hints generation
def test_hints_generation(single_binary_case):
    """Test that hints.json is generated correctly."""
    case_dir, file_hash = single_binary_case
    
    runner = StaticRunner()
    ctx = RunContext(
        file_hash=file_hash,
        preproc_dir=str(case_dir),
        analysis_base=str(case_dir),
        profile="quick"
    )
    
    result = runner.run(ctx)
    
    # Check hints files exist
    analysis_dir = case_dir / "analysis" / "static" / file_hash
    hints_file = analysis_dir / "hints.json"
    hints_public = analysis_dir / "hints.public.json"
    
    assert hints_file.exists()
    assert hints_public.exists()
    
    # Validate hints structure
    with open(hints_file, 'r') as f:
        hints = json.load(f)
    
    assert "file_hash" in hints
    assert "hints" in hints
    assert isinstance(hints["hints"], list)


# Test 9: Error handling - missing input.bin
def test_error_missing_input_bin(tmp_path):
    """Test error handling when input.bin is missing."""
    case_dir = tmp_path / "error_case"
    preproc_dir = case_dir / "preproc"
    file_hash = "error" + "0" * 59
    binary_dir = preproc_dir / file_hash
    binary_dir.mkdir(parents=True)
    
    # Only metadata, no input.bin
    metadata = {"producer": "test", "file_hash": file_hash}
    (binary_dir / "metadata.json").write_text(json.dumps(metadata))
    
    runner = StaticRunner()
    ctx = RunContext(
        file_hash=file_hash,
        preproc_dir=str(case_dir),
        analysis_base=str(case_dir),
        profile="quick"
    )
    
    result = runner.run(ctx)
    
    # Should have errors
    assert result.errors is not None
    assert len(result.errors) > 0


# Test 10: Ghidra integration check
def test_ghidra_integration_detection():
    """Test that Ghidra detection works (checks for installation)."""
    from auditor.detectors.static_detection import ghidra_adapter
    
    # Try to resolve Ghidra
    ghidra_path = ghidra_adapter.resolve_ghidra({})
    
    if ghidra_path:
        print(f"✓ Ghidra found at: {ghidra_path}")
        
        # Try to verify version
        try:
            version = ghidra_adapter.verify_ghidra(ghidra_path)
            print(f"✓ Ghidra version: {version}")
            assert version is not None
        except Exception as e:
            print(f"⚠ Could not verify Ghidra version: {e}")
    else:
        print("✗ Ghidra not found (install or set GHIDRA_INSTALL_DIR)")
        pytest.skip("Ghidra not installed")


# Test 11: Profile switching
def test_different_profiles(single_binary_case):
    """Test running with different analysis profiles."""
    case_dir, file_hash = single_binary_case
    
    runner = StaticRunner()
    
    profiles = ["quick", "thorough"]
    results = {}
    
    for profile in profiles:
        ctx = RunContext(
            file_hash=file_hash,
            preproc_dir=str(case_dir),
            analysis_base=str(case_dir),
            profile=profile,
            force=True  # Force to avoid cache between profiles
        )
        result = runner.run(ctx)
        results[profile] = result
        
        assert result.errors is None or result.errors == []
        assert result.file_hash == file_hash


# Test 12: Concurrent safety simulation
def test_concurrent_runs_different_binaries(mock_case_dir):
    """Test that analyzing different binaries concurrently is safe."""
    case_dir, binaries = mock_case_dir
    
    # Simulate concurrent runs by processing in parallel
    import concurrent.futures
    
    def analyze_binary(file_hash):
        runner = StaticRunner()
        ctx = RunContext(
            file_hash=file_hash,
            preproc_dir=str(case_dir),
            analysis_base=str(case_dir),
            profile="quick"
        )
        return runner.run(ctx)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(analyze_binary, h) for h in binaries]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]
    
    # All should succeed
    assert len(results) == 3
    for result in results:
        assert result.errors is None or result.errors == []


# Test 13: Tool versions tracking
def test_tool_versions_recorded(single_binary_case):
    """Test that tool versions are recorded in results."""
    case_dir, file_hash = single_binary_case
    
    runner = StaticRunner()
    ctx = RunContext(
        file_hash=file_hash,
        preproc_dir=str(case_dir),
        analysis_base=str(case_dir),
        profile="quick"
    )
    ctx.tool_versions = ToolVersions(python="3.11.0", ghidra=None)
    
    result = runner.run(ctx)
    
    # Check cache_meta has tool_versions
    analysis_dir = case_dir / "analysis" / "static" / file_hash
    cache_meta_path = analysis_dir / ".cache_meta.json"
    
    with open(cache_meta_path, 'r') as f:
        cache_meta = json.load(f)
    
    assert "tool_versions" in cache_meta


if __name__ == "__main__":
    # Run tests manually for debugging
    import sys
    sys.exit(pytest.main([__file__, "-v", "-s"]))
