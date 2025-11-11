#!/usr/bin/env python3
"""
Test dynamic analysis execution manually.

This script mimics what the UI does to run dynamic analysis.
"""

import sys
import os
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from auditor.detectors.dynamic_detection import (
    DynamicRunner,
    DynamicContext,
)

def test_dynamic_analysis():
    """Run dynamic analysis on caseOK test case."""
    
    case_root = Path(__file__).parent / "test_case" / "caseOK"
    
    print("=" * 60)
    print("DYNAMIC ANALYSIS EXECUTION TEST")
    print("=" * 60)
    
    # Get first file hash
    preproc_dir = case_root / "preproc"
    file_hashes = [d.name for d in preproc_dir.iterdir() if d.is_dir()]
    
    if not file_hashes:
        print("ERROR: No preprocessed files found")
        return False
    
    file_hash = file_hashes[0]
    print(f"\nRunning dynamic analysis on: {file_hash}")
    print(f"Case workdir: {case_root}")
    
    # Build context
    hints_path = case_root / "analysis" / "static" / file_hash / "hints.json"
    preproc_path = preproc_dir / file_hash
    
    print(f"\nChecking prerequisites:")
    print(f"  - preproc_dir exists: {preproc_path.exists()}")
    print(f"  - input.bin exists: {(preproc_path / 'input.bin').exists()}")
    print(f"  - hints.json exists: {hints_path.exists()}")
    
    if not all([preproc_path.exists(), (preproc_path / 'input.bin').exists(), hints_path.exists()]):
        print("ERROR: Prerequisites not met")
        return False
    
    # Create context
    ctx = DynamicContext(
        file_hash=file_hash,
        preproc_dir=str(preproc_path),
        hints_path=str(hints_path),
        analysis_base=str(case_root),
        mode='spawn',  # Try spawn mode
        timeout=30,  # 30 seconds
        memory_limit=512,
        instrumenters={
            'crypto_ops': True,
            'memory_scan': False,
            'call_graph': False
        }
    )
    
    print(f"\n[OK] Context created")
    print(f"  - Mode: {ctx.mode}")
    print(f"  - Timeout: {ctx.timeout}s")
    print(f"  - Binary: {os.path.join(ctx.preproc_dir, 'input.bin')}")
    
    # Run analysis
    print(f"\nRunning dynamic analysis...")
    print("=" * 60)
    
    runner = DynamicRunner()
    result = runner.run(ctx)
    
    print("=" * 60)
    print(f"\nAnalysis completed!")
    
    # Check results
    print(f"\nResult Summary:")
    print(f"  - file_hash: {result.file_hash}")
    print(f"  - is_success: {result.is_success()}")
    print(f"  - cached: {result.cached}")
    print(f"  - incomplete: {result.incomplete}")
    print(f"  - incomplete_reason: {result.incomplete_reason}")
    print(f"  - dynamic_results_path: {result.dynamic_results_path}")
    print(f"  - trace_path: {result.trace_path}")
    print(f"\nErrors ({len(result.errors)} total):")
    for i, err in enumerate(result.errors, 1):
        print(f"  {i}. {err}")
    
    # Check if files exist
    if result.dynamic_results_path:
        exists = os.path.exists(result.dynamic_results_path)
        print(f"\n  Dynamic results file exists: {exists}")
        
        if exists:
            try:
                with open(result.dynamic_results_path, 'r') as f:
                    data = json.load(f)
                    print(f"\n  Summary from results file:")
                    summary = data.get('summary', {})
                    for key, val in summary.items():
                        print(f"    - {key}: {val}")
                    
                    trace_summary = data.get('trace_summary', {})
                    print(f"\n  Trace Summary:")
                    for key, val in trace_summary.items():
                        print(f"    - {key}: {val}")
            except Exception as e:
                print(f"  ERROR reading results file: {e}")
    
    if result.trace_path:
        exists = os.path.exists(result.trace_path)
        print(f"\n  Trace file exists: {exists}")
        
        if exists:
            try:
                with open(result.trace_path, 'r') as f:
                    lines = f.readlines()
                    print(f"  Trace events: {len(lines)}")
                    
                    if lines:
                        print(f"\n  First few trace events:")
                        for line in lines[:3]:
                            try:
                                event = json.loads(line)
                                print(f"    - {event.get('type', 'unknown')}: {event.get('function', event.get('name', ''))}")
                            except:
                                print(f"    - {line[:60]}")
            except Exception as e:
                print(f"  ERROR reading trace file: {e}")
    
    print("\n" + "=" * 60)
    if result.is_success():
        print("✓ Dynamic analysis SUCCEEDED")
        return True
    else:
        print("✗ Dynamic analysis FAILED")
        return False


if __name__ == '__main__':
    try:
        success = test_dynamic_analysis()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(130)
    except Exception as e:
        print(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
