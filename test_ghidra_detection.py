"""Test script to debug Ghidra detection pipeline."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from auditor.detectors.static_detection import ghidra_adapter
from auditor.detectors.static_detection.runner import StaticRunner
from auditor.detectors.static_detection.context import RunContext, ToolVersions

print("=" * 70)
print("GHIDRA DETECTION PIPELINE TEST")
print("=" * 70)

# Step 1: Check Ghidra resolution
print("\n[1] Testing Ghidra Resolution...")
resolved = ghidra_adapter.resolve_ghidra({})
if resolved:
    print(f"   ✓ Ghidra resolved: {resolved}")
    print(f"   ✓ File exists: {os.path.isfile(resolved)}")
else:
    print("   ✗ ERROR: Ghidra NOT resolved!")
    print("   This means the config is not being read properly.")
    sys.exit(1)

# Step 2: Find a test case with preprocessed binaries
print("\n[2] Looking for test case with preprocessed binaries...")
cases_dir = os.path.join(os.environ.get("LOCALAPPDATA", ""), "CryptoScope", "cases")
test_case = None
test_hash = None

if os.path.isdir(cases_dir):
    print(f"   Checking: {cases_dir}")
    for case_name in os.listdir(cases_dir):
        case_path = os.path.join(cases_dir, case_name)
        preproc_path = os.path.join(case_path, "preproc")
        
        if os.path.isdir(preproc_path):
            # Look for a hash folder with input.bin
            for hash_name in os.listdir(preproc_path):
                hash_path = os.path.join(preproc_path, hash_name)
                input_bin = os.path.join(hash_path, "input.bin")
                metadata_json = os.path.join(hash_path, "metadata.json")
                
                if os.path.isfile(input_bin) and os.path.isfile(metadata_json):
                    test_case = case_path
                    test_hash = hash_name
                    print(f"   ✓ Found test case: {case_name}")
                    print(f"   ✓ Test hash: {test_hash}")
                    print(f"   ✓ Input binary: {input_bin} ({os.path.getsize(input_bin)} bytes)")
                    break
        
        if test_case:
            break

if not test_case:
    print("   ✗ ERROR: No test case found!")
    print("   Please run the application and preprocess at least one binary.")
    sys.exit(1)

# Step 3: Run static detection on the test binary
print("\n[3] Running Static Detection...")
print(f"   Case: {test_case}")
print(f"   Hash: {test_hash}")

try:
    runner = StaticRunner()
    ctx = RunContext(
        file_hash=test_hash,
        preproc_dir=test_case,
        analysis_base=test_case,
        profile="full",
        force=True,  # Force re-analysis
        tool_versions=ToolVersions()
    )
    
    print(f"   Running analysis (force={ctx.force})...")
    result = runner.run(ctx)
    
    print(f"\n   ✓ Analysis completed!")
    print(f"   - File hash: {result.file_hash}")
    print(f"   - Cached: {result.cached}")
    print(f"   - Summary: {result.summary}")
    
    # Step 4: Check if ghidra-export folder was created
    print("\n[4] Checking Ghidra Export...")
    analysis_dir = os.path.join(test_case, "analysis", "static", test_hash)
    ghidra_export_dir = os.path.join(analysis_dir, "ghidra-export")
    
    print(f"   Analysis dir: {analysis_dir}")
    print(f"   Ghidra export dir: {ghidra_export_dir}")
    
    if os.path.isdir(ghidra_export_dir):
        print(f"   ✓ ghidra-export folder EXISTS")
        
        # Check for files
        files = os.listdir(ghidra_export_dir)
        if files:
            print(f"   ✓ Files found: {len(files)}")
            for f in files:
                fpath = os.path.join(ghidra_export_dir, f)
                size = os.path.getsize(fpath) if os.path.isfile(fpath) else 0
                print(f"      - {f} ({size} bytes)")
        else:
            print(f"   ✗ EMPTY! No files in ghidra-export folder!")
            
            # Check for log file
            log_file = os.path.join(ghidra_export_dir, "ghidra-export.log")
            if os.path.isfile(log_file):
                print(f"\n   Log file found:")
                with open(log_file, 'r') as f:
                    print(f.read())
            else:
                print(f"   No log file found either!")
    else:
        print(f"   ✗ ERROR: ghidra-export folder NOT created!")
        print(f"   This means ensure_ghidra_export() returned None")
    
    # Check static_results.json
    static_results_path = os.path.join(analysis_dir, "static_results.json")
    if os.path.isfile(static_results_path):
        print(f"\n   ✓ static_results.json exists")
        import json
        with open(static_results_path, 'r') as f:
            results = json.load(f)
            print(f"   - Findings: {len(results.get('findings', []))}")
    
except Exception as e:
    print(f"\n   ✗ ERROR during analysis: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 70)
print("TEST COMPLETE")
print("=" * 70)
