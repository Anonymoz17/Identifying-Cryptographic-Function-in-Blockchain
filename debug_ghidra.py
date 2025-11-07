"""Debug script to trace exact Ghidra execution."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

# Patch run_headless_export to see what command is being run
original_run = None

def debug_run_headless_export(cmd, timeout=600):
    print("\n" + "=" * 70)
    print("GHIDRA COMMAND BEING EXECUTED:")
    print("=" * 70)
    print("Command:", ' '.join(cmd))
    print(f"Timeout: {timeout}s")
    print("=" * 70)
    
    # Actually run it
    result = original_run(cmd, timeout)
    
    print("\nRESULT:")
    print(f"  Exit code: {result[0]}")
    print(f"  STDOUT length: {len(result[1])} chars")
    print(f"  STDERR length: {len(result[2])} chars")
    
    if result[1]:
        print("\nSTDOUT (first 500 chars):")
        print(result[1][:500])
    
    if result[2]:
        print("\nSTDERR (first 500 chars):")
        print(result[2][:500])
    
    return result

from auditor.detectors.static_detection import ghidra_adapter
original_run = ghidra_adapter.run_headless_export
ghidra_adapter.run_headless_export = debug_run_headless_export

from auditor.detectors.static_detection.runner import StaticRunner
from auditor.detectors.static_detection.context import RunContext, ToolVersions

print("Finding test case...")
cases_dir = os.path.join(os.environ.get("LOCALAPPDATA", ""), "CryptoScope", "cases")

for case_name in os.listdir(cases_dir):
    case_path = os.path.join(cases_dir, case_name)
    preproc_path = os.path.join(case_path, "preproc")
    
    if os.path.isdir(preproc_path):
        hash_folders = os.listdir(preproc_path)
        if hash_folders:
            test_hash = hash_folders[0]
            print(f"Using case: {case_name}, hash: {test_hash}")
            
            runner = StaticRunner()
            ctx = RunContext(
                file_hash=test_hash,
                preproc_dir=case_path,
                analysis_base=case_path,
                profile="full",
                force=True,
                tool_versions=ToolVersions()
            )
            
            print("\nRunning static detection...")
            result = runner.run(ctx)
            print(f"\nDone! Cached: {result.cached}")
            
            # Check result
            ghidra_export_dir = os.path.join(case_path, "analysis", "static", test_hash, "ghidra-export")
            json_file = os.path.join(ghidra_export_dir, f"{test_hash}-functions.json")
            
            if os.path.isfile(json_file):
                print(f"\n✓ SUCCESS! JSON file created: {os.path.getsize(json_file)} bytes")
            else:
                print(f"\n✗ FAILED! No JSON file at: {json_file}")
                print(f"   Files in ghidra-export:")
                if os.path.isdir(ghidra_export_dir):
                    for f in os.listdir(ghidra_export_dir):
                        print(f"      - {f}")
            
            break
    break
