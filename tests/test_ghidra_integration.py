import os
import shutil
import pytest

from src.auditor.detectors.static_detection import ghidra_adapter as ga


@pytest.mark.skipif(not os.environ.get('GHIDRA_INSTALL_DIR') or not os.environ.get('GHIDRA_SAMPLE_BIN'),
                    reason='Requires GHIDRA_INSTALL_DIR and GHIDRA_SAMPLE_BIN to run')
def test_real_ghidra_headless_run(tmp_path):
    """Integration test: runs analyzeHeadless against a real sample binary.

    This test is gated and should be executed manually by developers who have
    a local Ghidra installation and a small sample binary to analyze.

    Requirements:
      - Set environment variable GHIDRA_INSTALL_DIR to the Ghidra install path
      - Set GHIDRA_SAMPLE_BIN to a path to a small binary file that Ghidra can import

    Example (PowerShell):

      $env:GHIDRA_INSTALL_DIR = 'C:\path\to\ghidra'
      $env:GHIDRA_SAMPLE_BIN = 'C:\path\to\sample.exe'
      pytest -q -k ghidra_integration tests/test_ghidra_integration.py

    """
    ghidra_dir = os.environ.get('GHIDRA_INSTALL_DIR')
    sample = os.environ.get('GHIDRA_SAMPLE_BIN')
    assert ghidra_dir and sample

    out_dir = tmp_path / 'ghidra_out'
    in_path = sample
    file_hash = 'integration-test'

    # ensure analyzeHeadless exists
    analyze = ga.find_analyze_headless({'ghidra_install_dir': ghidra_dir})
    assert analyze, 'analyzeHeadless not found at GHIDRA_INSTALL_DIR'

    # Run the adapter - this will actually call analyzeHeadless; can be slow
    res = ga.ensure_ghidra_export(in_path, str(out_dir), file_hash, options={'ghidra_install_dir': ghidra_dir, 'timeout': 900})
    assert res is not None
    funcs = ga.read_ghidra_functions(res)
    # basic sanity: we expect at least one function in a real binary
    assert isinstance(funcs, list)
    assert len(funcs) >= 1