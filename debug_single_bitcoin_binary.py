#!/usr/bin/env python3
"""
Debug script for single Bitcoin binary dynamic analysis.

This script runs dynamic analysis on ONE Bitcoin binary with full debug logging
to identify the root cause of the "Incomplete: error" issue.

Run with:
    python debug_single_bitcoin_binary.py
"""

import os
import sys
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from auditor.detectors.dynamic_detection import DynamicRunner, DynamicContext


def main():
    """Run debug analysis on first Bitcoin binary."""

    print("\n" + "=" * 80)
    print("BITCOIN BINARY DYNAMIC ANALYSIS - DEBUG MODE")
    print("=" * 80 + "\n")

    # Get first Bitcoin binary
    bitcoin_dir = Path("BITCOIN")
    preproc_dir = bitcoin_dir / "preproc"

    if not preproc_dir.exists():
        print(f"ERROR: BITCOIN preproc directory not found at {preproc_dir}")
        sys.exit(1)

    # Find first hash directory
    hash_dirs = sorted([d for d in preproc_dir.iterdir() if d.is_dir()])
    if not hash_dirs:
        print(f"ERROR: No preproc directories found in {preproc_dir}")
        sys.exit(1)

    file_hash = hash_dirs[0].name
    print(f"Testing with binary hash: {file_hash}\n")

    # Verify all required files exist
    binary_path = preproc_dir / file_hash / "input.bin"
    hints_path = bitcoin_dir / "analysis" / "static" / file_hash / "hints.json"
    metadata_path = preproc_dir / file_hash / "metadata.json"

    print("File checks:")
    print(f"  Binary: {binary_path}")
    print(f"    Exists: {binary_path.exists()}")
    if binary_path.exists():
        print(f"    Size: {binary_path.stat().st_size} bytes")

    print(f"  Hints: {hints_path}")
    print(f"    Exists: {hints_path.exists()}")
    if hints_path.exists():
        try:
            with open(hints_path) as f:
                hints_data = json.load(f)
                hint_count = len(hints_data.get('hints', []))
                print(f"    Hints count: {hint_count}")
        except Exception as e:
            print(f"    Error reading hints: {e}")

    print(f"  Metadata: {metadata_path}")
    print(f"    Exists: {metadata_path.exists()}")

    if not binary_path.exists():
        print(f"\nERROR: Binary not found at {binary_path}")
        sys.exit(1)

    if not hints_path.exists():
        print(f"\nERROR: Hints not found at {hints_path}")
        print("  → Run static analysis first")
        sys.exit(1)

    print("\n" + "=" * 80)
    print("STARTING DYNAMIC ANALYSIS WITH DEBUG LOGGING")
    print("=" * 80 + "\n")

    # Create context
    ctx = DynamicContext(
        file_hash=file_hash,
        preproc_dir=str(preproc_dir / file_hash),
        hints_path=str(hints_path),
        analysis_base=str(bitcoin_dir),
        mode="spawn",
        timeout=120,  # 2 minutes for debugging
        force=True    # Force re-analysis
    )

    # Run analysis
    runner = DynamicRunner()
    result = runner.run(ctx)

    # Display results
    print("\n" + "=" * 80)
    print("ANALYSIS RESULTS")
    print("=" * 80)

    print(f"\nFile Hash: {result.file_hash}")
    print(f"Success: {result.is_success()}")
    print(f"Incomplete: {result.incomplete}")
    print(f"Incomplete Reason: {result.incomplete_reason}")
    print(f"Cached: {result.cached}")

    if result.errors:
        print(f"\nErrors ({len(result.errors)}):")
        for i, error in enumerate(result.errors, 1):
            print(f"  {i}. {error}")
    else:
        print("\nNo errors!")

    if result.summary:
        print(f"\nSummary:")
        for key, value in result.summary.items():
            print(f"  {key}: {value}")

    print(f"\nDynamic Results Path: {result.dynamic_results_path}")
    if result.dynamic_results_path and os.path.exists(result.dynamic_results_path):
        print(f"  File size: {os.path.getsize(result.dynamic_results_path)} bytes")

    print(f"\nTrace Path: {result.trace_path}")
    if result.trace_path and os.path.exists(result.trace_path):
        size = os.path.getsize(result.trace_path)
        print(f"  File size: {size} bytes")
        if size > 0:
            with open(result.trace_path) as f:
                line_count = sum(1 for _ in f)
            print(f"  Line count: {line_count}")
        else:
            print(f"  ⚠️ EMPTY FILE - No traces collected!")

    print("\n" + "=" * 80)
    print("DEBUG COMPLETE")
    print("=" * 80 + "\n")

    # Return appropriate exit code
    return 0 if result.is_success() else 1


if __name__ == "__main__":
    sys.exit(main())
