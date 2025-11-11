"""Quick verification script for static detection system.

This script performs basic checks without requiring full test framework.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

def check_imports():
    """Verify all core modules can be imported."""
    print("=" * 60)
    print("CHECKING IMPORTS")
    print("=" * 60)
    
    try:
        from auditor.detectors.static_detection.runner import StaticRunner
        print("✓ StaticRunner imported")
        
        from auditor.detectors.static_detection.context import RunContext, ToolVersions
        print("✓ RunContext imported")
        
        from auditor.detectors.static_detection import ghidra_adapter
        print("✓ ghidra_adapter imported")
        
        from auditor.detectors.static_detection import preproc_adapter
        print("✓ preproc_adapter imported")
        
        from auditor.detectors.static_detection import heuristics_manager
        print("✓ heuristics_manager imported")
        
        from auditor.detectors.static_detection import cache
        print("✓ cache imported")
        
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False


def check_ghidra():
    """Check if Ghidra is installed."""
    print("\n" + "=" * 60)
    print("CHECKING GHIDRA")
    print("=" * 60)
    
    try:
        from auditor.detectors.static_detection import ghidra_adapter
        
        # Try to resolve Ghidra
        ghidra_path = ghidra_adapter.resolve_ghidra({})
        
        if ghidra_path:
            print(f"✓ Ghidra found: {ghidra_path}")
            
            # Try to verify version
            try:
                version = ghidra_adapter.verify_ghidra(ghidra_path)
                print(f"✓ Ghidra version: {version}")
                return True
            except Exception as e:
                print(f"⚠ Could not verify version: {e}")
                return False
        else:
            print("✗ Ghidra not found")
            print("\nTo install Ghidra:")
            print("  1. Download from https://ghidra-sre.org/")
            print("  2. Extract to a directory (e.g., C:\\ghidra_10.4)")
            print("  3. Set environment variable:")
            print("     $env:GHIDRA_INSTALL_DIR = 'C:\\ghidra_10.4'")
            print("     [System.Environment]::SetEnvironmentVariable('GHIDRA_INSTALL_DIR', 'C:\\ghidra_10.4', 'User')")
            return False
            
    except Exception as e:
        print(f"✗ Error checking Ghidra: {e}")
        return False


def check_test_files():
    """Check if test files exist."""
    print("\n" + "=" * 60)
    print("CHECKING TEST FILES")
    print("=" * 60)
    
    repo_root = Path(__file__).parent.parent
    test_files = [
        "tests/test_static_detection_workflow.py",
        "tests/test_ghidra_adapter.py",
        "tests/test_ghidra_integration.py",
        "tests/test_heuristics_with_ghidra.py",
        "tests/test_runner_cache_shortcircuit.py",
    ]
    
    all_exist = True
    for test_file in test_files:
        full_path = repo_root / test_file
        if full_path.exists():
            print(f"✓ {test_file}")
        else:
            print(f"✗ {test_file} - NOT FOUND")
            all_exist = False
    
    return all_exist


def check_documentation():
    """Check if documentation exists."""
    print("\n" + "=" * 60)
    print("CHECKING DOCUMENTATION")
    print("=" * 60)
    
    repo_root = Path(__file__).parent.parent
    doc_files = [
        "docs/pipeline.md",
        "docs/batch-static-detection.md",
        "docs/static-detection-status.md",
        "docs/analysis-storage.md",
    ]
    
    all_exist = True
    for doc_file in doc_files:
        full_path = repo_root / doc_file
        if full_path.exists():
            size_kb = full_path.stat().st_size / 1024
            print(f"✓ {doc_file} ({size_kb:.1f} KB)")
        else:
            print(f"✗ {doc_file} - NOT FOUND")
            all_exist = False
    
    return all_exist


def check_detectors_page():
    """Check if detectors page exists and has batch processing."""
    print("\n" + "=" * 60)
    print("CHECKING DETECTORS PAGE")
    print("=" * 60)
    
    repo_root = Path(__file__).parent.parent
    detectors_file = repo_root / "src" / "pages" / "detectors.py"
    
    if not detectors_file.exists():
        print("✗ detectors.py not found")
        return False
    
    print(f"✓ detectors.py exists")
    
    content = detectors_file.read_text(encoding='utf-8')
    
    # Check for key methods
    required_methods = [
        "_scan_all_cases",
        "_batch_analysis_thread",
        "_display_batch_results",
        "_open_results_folder",
    ]
    
    for method in required_methods:
        if f"def {method}" in content:
            print(f"✓ Method {method} found")
        else:
            print(f"✗ Method {method} NOT FOUND")
            return False
    
    return True


def main():
    """Run all checks."""
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 10 + "STATIC DETECTION VERIFICATION" + " " * 18 + "║")
    print("╚" + "=" * 58 + "╝")
    
    results = {}
    
    results['imports'] = check_imports()
    results['ghidra'] = check_ghidra()
    results['tests'] = check_test_files()
    results['docs'] = check_documentation()
    results['ui'] = check_detectors_page()
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    
    for category, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {category.upper()}")
    
    print(f"\nTotal: {passed}/{total} checks passed")
    
    if results['imports'] and results['tests'] and results['docs'] and results['ui']:
        if results['ghidra']:
            print("\n🎉 SYSTEM FULLY OPERATIONAL")
            print("   All components working, including Ghidra!")
        else:
            print("\n⚠️  SYSTEM READY (Ghidra Not Installed)")
            print("   Core functionality works, but Ghidra needed for full analysis")
    else:
        print("\n❌ SYSTEM HAS ISSUES")
        print("   Some components are missing or broken")
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
