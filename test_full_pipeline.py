#!/usr/bin/env python3
"""
Full pipeline test: Setup -> Static -> Dynamic on test_case folder.

This script tests the complete pipeline to verify the fixes work.
"""

import sys
import os
import json
import subprocess
from pathlib import Path

def run_phase(phase_name, python_code):
    """Run a phase and check results."""
    print(f"\n{'='*60}")
    print(f"PHASE: {phase_name}")
    print('='*60)
    
    # This will be run inside the app context
    return python_code

def main():
    """Main test function."""
    project_root = Path(__file__).parent
    test_case = project_root / "test_case"
    
    print("="*60)
    print("FULL PIPELINE TEST: Setup -> Static -> Dynamic")
    print("="*60)
    print(f"Project root: {project_root}")
    print(f"Test case folder: {test_case}")
    
    # Check prerequisites
    print("\nChecking prerequisites...")
    if not (test_case / "certutil.exe").exists():
        print("ERROR: Real binaries not found in test_case folder")
        return False
    
    print("OK - Real binaries found")
    print(f"  - certutil.exe: {(test_case / 'certutil.exe').stat().st_size} bytes")
    print(f"  - cipher.exe: {(test_case / 'cipher.exe').stat().st_size} bytes")
    print(f"  - certreq.exe: {(test_case / 'certreq.exe').stat().st_size} bytes")
    print(f"  - bcdedit.exe: {(test_case / 'bcdedit.exe').stat().st_size} bytes")
    print(f"  - dism.exe: {(test_case / 'dism.exe').stat().st_size} bytes")
    print(f"  - powershell.exe: {(test_case / 'powershell.exe').stat().st_size} bytes")
    print(f"  - minimal_crypto.exe: {(test_case / 'minimal_crypto.exe').stat().st_size} bytes")
    
    # Import pipeline
    print("\n" + "="*60)
    print("Importing pipeline modules...")
    sys.path.insert(0, str(project_root / 'src'))
    
    try:
        from auditor.intake_flow.runner import SetupRunner, SetupContext
        from auditor.detectors.static_detection import StaticRunner, StaticContext
        from auditor.detectors.dynamic_detection import DynamicRunner, DynamicContext
        print("OK - Modules imported")
    except Exception as e:
        print(f"ERROR: Failed to import: {e}")
        return False
    
    # Phase 1: Setup
    print("\n" + "="*60)
    print("PHASE 1: Setup")
    print("="*60)
    
    try:
        setup_ctx = SetupContext(
            source_dir=str(test_case),
            output_dir=str(test_case),
            dedupe_mode='none',
            include_metadata=True
        )
        
        setup_runner = SetupRunner()
        setup_result = setup_runner.run(setup_ctx)
        
        if setup_result.is_success():
            print("OK - Setup completed successfully")
            print(f"  - Files processed: {setup_result.total_files}")
            print(f"  - Binaries: {setup_result.binary_count}")
            print(f"  - Source files: {setup_result.source_count}")
        else:
            print(f"ERROR - Setup failed: {setup_result.errors}")
            return False
            
    except Exception as e:
        print(f"ERROR - Setup exception: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Phase 2: Static Analysis
    print("\n" + "="*60)
    print("PHASE 2: Static Analysis")
    print("="*60)
    
    preproc_dir = test_case / "preproc"
    file_hashes = [d.name for d in preproc_dir.iterdir() if d.is_dir()]
    print(f"Found {len(file_hashes)} files to analyze")
    
    try:
        static_runner = StaticRunner()
        static_count = 0
        
        for file_hash in file_hashes[:3]:  # Test first 3 files
            static_ctx = StaticContext(
                file_hash=file_hash,
                preproc_dir=str(preproc_dir / file_hash),
                analysis_base=str(test_case)
            )
            
            result = static_runner.run(static_ctx)
            
            if result.is_success():
                static_count += 1
                # Check hints were created
                hints_path = test_case / "analysis" / "static" / file_hash / "hints.json"
                if hints_path.exists():
                    with open(hints_path) as f:
                        hints = json.load(f)
                    print(f"  {file_hash[:16]}... -> {len(hints.get('hints', []))} hints")
                else:
                    print(f"  {file_hash[:16]}... -> NO HINTS FILE")
            else:
                print(f"  {file_hash[:16]}... -> FAILED")
        
        print(f"OK - {static_count} files analyzed")
        
    except Exception as e:
        print(f"ERROR - Static analysis exception: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Phase 3: Dynamic Analysis
    print("\n" + "="*60)
    print("PHASE 3: Dynamic Analysis")
    print("="*60)
    
    try:
        dynamic_runner = DynamicRunner()
        dynamic_count = 0
        
        for file_hash in file_hashes[:1]:  # Test first file only
            hints_path = test_case / "analysis" / "static" / file_hash / "hints.json"
            
            if not hints_path.exists():
                print(f"  {file_hash[:16]}... -> NO HINTS, skipping")
                continue
            
            ctx = DynamicContext(
                file_hash=file_hash,
                preproc_dir=str(preproc_dir / file_hash),
                hints_path=str(hints_path),
                analysis_base=str(test_case),
                mode='spawn',
                timeout=30,
                memory_limit=512,
                instrumenters={'crypto_ops': True, 'memory_scan': False, 'call_graph': False}
            )
            
            print(f"  Running dynamic analysis on {file_hash[:16]}...")
            result = dynamic_runner.run(ctx)
            
            if result.is_success():
                print(f"  {file_hash[:16]}... -> SUCCESS (incomplete={result.incomplete})")
                dynamic_count += 1
                
                # Check results
                if result.dynamic_results_path and os.path.exists(result.dynamic_results_path):
                    with open(result.dynamic_results_path) as f:
                        results = json.load(f)
                    summary = results.get('summary', {})
                    print(f"    - Total crypto calls: {summary.get('total_crypto_calls', 0)}")
                    print(f"    - Execution time: {summary.get('execution_time_seconds', 0):.3f}s")
            else:
                print(f"  {file_hash[:16]}... -> FAILED")
                print(f"    Errors: {result.errors}")
        
        print(f"OK - {dynamic_count} files analyzed")
        
    except Exception as e:
        print(f"ERROR - Dynamic analysis exception: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "="*60)
    print("ALL PHASES COMPLETED SUCCESSFULLY!")
    print("="*60)
    return True


if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(130)
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
