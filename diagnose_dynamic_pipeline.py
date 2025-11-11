#!/usr/bin/env python3
"""
diagnose_dynamic_pipeline.py - Diagnose why dynamic analysis shows no results

Checks:
1. What files are being processed by setup
2. What hints.json contains
3. What binary files exist in preproc
4. If Frida can attach to test binaries
5. If the dynamic runner is being called correctly
"""

import os
import sys
import json
from pathlib import Path

def check_setup():
    """Check if setup has created preproc directory."""
    print("\n" + "="*60)
    print("CHECKING SETUP OUTPUT")
    print("="*60)
    
    project_root = Path(__file__).parent
    preproc_dir = project_root / "preproc"
    
    if not preproc_dir.exists():
        print("❌ preproc/ directory NOT found")
        print("   Setup may not have completed successfully")
        return False
    
    print(f"✓ preproc/ directory exists")
    
    # Count subdirectories (each is a SHA256-hashed artifact)
    artifacts = list(preproc_dir.glob("*/"))
    print(f"✓ Found {len(artifacts)} artifact directories (files processed)")
    
    if not artifacts:
        print("   WARNING: No artifacts found - Setup may have processed 0 files")
        return False
    
    # Check first few artifacts
    for i, artifact in enumerate(sorted(artifacts)[:3]):
        files = list(artifact.glob("*"))
        input_bin = artifact / "input.bin"
        metadata = artifact / "metadata.json"
        
        print(f"\n  Artifact {i+1}: {artifact.name}")
        print(f"    Files: {len(files)}")
        if input_bin.exists():
            size_mb = input_bin.stat().st_size / (1024*1024)
            print(f"    ✓ input.bin exists ({size_mb:.2f} MB)")
        else:
            print(f"    ❌ input.bin NOT FOUND")
        
        if metadata.exists():
            with open(metadata) as f:
                meta = json.load(f)
            print(f"    ✓ metadata.json exists")
            print(f"      - mime: {meta.get('mime')}")
            print(f"      - is_binary: {meta.get('is_binary')}")
            print(f"      - binary_format: {meta.get('binary_format')}")
            print(f"      - language: {meta.get('language')}")
        else:
            print(f"    ❌ metadata.json NOT FOUND")
    
    return True

def check_hints():
    """Check if hints.json was created by static analysis."""
    print("\n" + "="*60)
    print("CHECKING STATIC ANALYSIS HINTS")
    print("="*60)
    
    project_root = Path(__file__).parent
    hints_path = project_root / "hints.json"
    
    if not hints_path.exists():
        print(f"❌ hints.json NOT found at {hints_path}")
        print("   Static Analysis may not have completed")
        return False
    
    print(f"✓ hints.json exists")
    
    with open(hints_path) as f:
        hints = json.load(f)
    
    hint_list = hints.get('hints', [])
    print(f"✓ Contains {len(hint_list)} hints")
    
    if not hint_list:
        print("   WARNING: hints.json is empty - Static Analysis may have found nothing")
        return False
    
    # Show sample hints
    print(f"\n  Sample hints (first 5):")
    for hint in hint_list[:5]:
        print(f"    - {hint.get('function_name', '?')} (pattern: {hint.get('pattern', '?')})")
    
    return True

def check_config():
    """Check if dynamic detection config exists."""
    print("\n" + "="*60)
    print("CHECKING DYNAMIC DETECTION CONFIG")
    print("="*60)
    
    project_root = Path(__file__).parent
    
    # Check several possible config locations
    config_paths = [
        project_root / "preproc" / "config.json",
        project_root / "src" / "auditor" / "detectors" / "dynamic_detection" / "config.py",
    ]
    
    for cfg_path in config_paths:
        if cfg_path.exists():
            print(f"✓ Found config: {cfg_path.relative_to(project_root)}")
            if cfg_path.suffix == ".json":
                with open(cfg_path) as f:
                    config = json.load(f)
                print(f"  Config keys: {list(config.keys())}")

def check_frida():
    """Check if Frida is installed and working."""
    print("\n" + "="*60)
    print("CHECKING FRIDA AVAILABILITY")
    print("="*60)
    
    try:
        import frida
        print(f"✓ Frida installed: version {frida.__version__}")
        
        # Try to enumerate processes
        processes = frida.enumerate_processes()
        print(f"✓ Frida can see {len(processes)} processes")
        
        # Try to find certutil.exe
        certutil_found = False
        for proc in processes:
            if "certutil" in proc.name.lower():
                print(f"✓ Found certutil.exe process: PID {proc.pid}")
                certutil_found = True
                break
        
        if not certutil_found:
            print("ℹ certutil.exe not currently running (will be spawned during analysis)")
        
        return True
        
    except ImportError:
        print("❌ Frida not installed")
        return False
    except Exception as e:
        print(f"⚠ Error checking Frida: {e}")
        return False

def check_test_binaries():
    """Check if test case binaries exist."""
    print("\n" + "="*60)
    print("CHECKING TEST CASE BINARIES")
    print("="*60)
    
    project_root = Path(__file__).parent
    test_case_dir = project_root / "test_case"
    
    if not test_case_dir.exists():
        print(f"❌ test_case directory not found")
        return False
    
    exe_files = list(test_case_dir.glob("*.exe"))
    print(f"✓ Found {len(exe_files)} .exe files in test_case/")
    
    for exe in sorted(exe_files)[:5]:
        size_mb = exe.stat().st_size / (1024*1024)
        print(f"  - {exe.name} ({size_mb:.2f} MB)")
    
    return len(exe_files) > 0

def main():
    """Run all diagnostics."""
    print("\n╔════════════════════════════════════════════════════════════╗")
    print("║  Dynamic Analysis Pipeline Diagnostic                      ║")
    print("╚════════════════════════════════════════════════════════════╝")
    
    results = {
        "Setup Output": check_setup(),
        "Static Hints": check_hints(),
        "Dynamic Config": check_config(),
        "Frida": check_frida(),
        "Test Binaries": check_test_binaries(),
    }
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    for check, status in results.items():
        symbol = "✓" if status else "❌"
        print(f"{symbol} {check}")
    
    all_passed = all(results.values())
    
    if all_passed:
        print("\n✓ All checks passed! Pipeline should work.")
    else:
        print("\n❌ Some checks failed. Review above for details.")
        print("\nCommon issues:")
        print("1. Setup not completed - run Setup phase in Detectors page")
        print("2. Static Analysis not completed - run Static Analysis phase")
        print("3. hints.json is empty - Static Analysis found no patterns")
        print("4. Frida not installed - pip install frida-tools")
        print("5. Test binaries missing - copy .exe files to test_case/")

if __name__ == "__main__":
    main()
