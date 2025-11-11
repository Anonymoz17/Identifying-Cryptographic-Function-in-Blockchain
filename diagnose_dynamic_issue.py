#!/usr/bin/env python3
"""
Diagnostic script for dynamic detection issues.

Checks:
1. Frida installation and availability
2. Case structure and binary files
3. Hints loading
4. Script generation
5. Sandbox setup
"""

import os
import sys
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))


def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'='*80}")
    print(f"{title:^80}")
    print('='*80)


def check_frida():
    """Check if Frida is installed and available."""
    print_section("1. FRIDA INSTALLATION CHECK")
    
    try:
        import frida
        print(f"✓ Frida package installed: version {frida.__version__}")
        return True
    except ImportError as e:
        print(f"✗ Frida not installed: {e}")
        print("  Fix: pip install frida==16.0.19 frida-tools==12.2.1")
        return False


def check_case_structure(workdir):
    """Check case directory structure and binary files."""
    print_section("2. CASE STRUCTURE CHECK")
    
    workdir_path = Path(workdir)
    if not workdir_path.exists():
        print(f"✗ Workdir not found: {workdir}")
        return False
    
    print(f"✓ Workdir exists: {workdir}")
    
    preproc_dir = workdir_path / "preproc"
    if not preproc_dir.exists():
        print(f"✗ No preproc directory found")
        return False
    
    print(f"✓ Preproc directory found")
    
    # Count files
    binaries = list(preproc_dir.iterdir())
    print(f"  Total file hashes: {len(binaries)}")
    
    if not binaries:
        print("✗ No file hashes in preproc directory")
        return False
    
    # Check first few
    for hash_dir in binaries[:5]:
        if hash_dir.is_dir():
            input_bin = hash_dir / "input.bin"
            metadata = hash_dir / "metadata.json"
            
            print(f"\n  Hash: {hash_dir.name[:16]}...")
            print(f"    - input.bin exists: {input_bin.exists()}")
            print(f"    - metadata.json exists: {metadata.exists()}")
            
            if metadata.exists():
                try:
                    with open(metadata) as f:
                        meta = json.load(f)
                    print(f"    - Type: {meta.get('file_type', 'unknown')}")
                    print(f"    - Size: {meta.get('size_bytes', 0):,} bytes")
                except Exception as e:
                    print(f"    - Error reading metadata: {e}")
            
            if input_bin.exists():
                size = input_bin.stat().st_size
                print(f"    - Input size: {size:,} bytes")
    
    return True


def check_hints(workdir, file_hash=None):
    """Check if hints are available."""
    print_section("3. HINTS CHECK")
    
    workdir_path = Path(workdir)
    analysis_dir = workdir_path / "analysis" / "static"
    
    if not analysis_dir.exists():
        print("✗ No static analysis directory")
        return False
    
    # Get first hash if not provided
    if not file_hash:
        preproc_dir = workdir_path / "preproc"
        hashes = [d.name for d in preproc_dir.iterdir() if d.is_dir()]
        if not hashes:
            print("✗ No file hashes found")
            return False
        file_hash = hashes[0]
    
    hints_path = analysis_dir / file_hash / "hints.json"
    
    print(f"  Checking hints for: {file_hash[:16]}...")
    
    if not hints_path.exists():
        print(f"✗ Hints file not found: {hints_path}")
        return False
    
    print(f"✓ Hints file found")
    
    try:
        with open(hints_path) as f:
            hints = json.load(f)
        
        print(f"  Hints schema version: {hints.get('schema_version', 'unknown')}")
        print(f"  Total hints: {len(hints.get('hints', []))}")
        
        # Count by type
        by_type = {}
        for hint in hints.get('hints', []):
            hint_type = hint.get('type', 'unknown')
            by_type[hint_type] = by_type.get(hint_type, 0) + 1
        
        print(f"  Hints by type:")
        for hint_type, count in sorted(by_type.items()):
            print(f"    - {hint_type}: {count}")
        
        return len(hints.get('hints', [])) > 0
    
    except Exception as e:
        print(f"✗ Error reading hints: {e}")
        return False


def check_script_generation(workdir, file_hash=None):
    """Test script generation."""
    print_section("4. SCRIPT GENERATION CHECK")
    
    try:
        from auditor.detectors.dynamic_detection import (
            Config, hints_adapter, frida_scripter
        )
    except ImportError as e:
        print(f"✗ Failed to import detection modules: {e}")
        return False
    
    workdir_path = Path(workdir)
    
    # Get first hash if not provided
    if not file_hash:
        preproc_dir = workdir_path / "preproc"
        hashes = [d.name for d in preproc_dir.iterdir() if d.is_dir()]
        if not hashes:
            print("✗ No file hashes found")
            return False
        file_hash = hashes[0]
    
    print(f"  Testing script generation for: {file_hash[:16]}...")
    
    try:
        # Load hints
        hints_path = workdir_path / "analysis" / "static" / file_hash / "hints.json"
        if not hints_path.exists():
            print(f"✗ Hints file not found")
            return False
        
        hints = hints_adapter.load_hints(str(hints_path))
        print(f"✓ Hints loaded: {len(hints.get('hints', []))} hints")
        
        # Load config
        preproc_dir = workdir_path / "preproc" / file_hash
        config = Config.load(preproc_dir=str(preproc_dir))
        print(f"✓ Config loaded")
        
        # Generate hooks
        hooks = frida_scripter.generate_hooks(hints, config)
        print(f"✓ Scripts generated: {len(hooks)} script(s)")
        
        # Check script sizes
        for i, script in enumerate(hooks, 1):
            print(f"  - Script {i}: {len(script):,} bytes")
        
        return len(hooks) > 0
    
    except Exception as e:
        print(f"✗ Script generation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_runner(workdir, file_hash=None):
    """Test runner initialization."""
    print_section("5. RUNNER CHECK")
    
    try:
        from auditor.detectors.dynamic_detection import DynamicRunner, DynamicContext
    except ImportError as e:
        print(f"✗ Failed to import runner: {e}")
        return False
    
    workdir_path = Path(workdir)
    
    # Get first hash if not provided
    if not file_hash:
        preproc_dir = workdir_path / "preproc"
        hashes = [d.name for d in preproc_dir.iterdir() if d.is_dir()]
        if not hashes:
            print("✗ No file hashes found")
            return False
        file_hash = hashes[0]
    
    print(f"  Testing runner for: {file_hash[:16]}...")
    
    try:
        runner = DynamicRunner()
        
        # Check Frida availability
        if runner._frida_available:
            print("✓ Frida is available to runner")
        else:
            print("✗ Frida is NOT available to runner")
            return False
        
        # Create context
        hints_path = workdir_path / "analysis" / "static" / file_hash / "hints.json"
        ctx = DynamicContext(
            file_hash=file_hash,
            preproc_dir=str(workdir_path / "preproc" / file_hash),
            hints_path=str(hints_path),
            analysis_base=str(workdir_path),
            mode="spawn",
            timeout=10
        )
        print(f"✓ Context created")
        print(f"  - Mode: {ctx.mode}")
        print(f"  - Timeout: {ctx.timeout}s")
        
        # Run preflight checks
        print(f"\n  Running preflight checks...")
        result_template = type('', (), {})()
        result_template.errors = []
        result_template.incomplete = False
        result_template.incomplete_reason = None
        result_template.add_error = lambda msg: result_template.errors.append(msg)
        
        result = runner._preflight_checks(ctx, result_template)
        
        if result.errors:
            print(f"✗ Preflight checks failed:")
            for error in result.errors:
                print(f"  - {error}")
            return False
        else:
            print(f"✓ Preflight checks passed")
        
        return True
    
    except Exception as e:
        print(f"✗ Runner check failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_binary_types(workdir):
    """Check what types of files are in the case."""
    print_section("6. BINARY TYPE CHECK")
    
    workdir_path = Path(workdir)
    preproc_dir = workdir_path / "preproc"
    
    if not preproc_dir.exists():
        print("✗ No preproc directory")
        return
    
    binary_types = {}
    total_size = 0
    
    for hash_dir in preproc_dir.iterdir():
        if hash_dir.is_dir():
            metadata_path = hash_dir / "metadata.json"
            if metadata_path.exists():
                try:
                    with open(metadata_path) as f:
                        meta = json.load(f)
                    file_type = meta.get('file_type', 'unknown')
                    size = meta.get('size_bytes', 0)
                    
                    if file_type not in binary_types:
                        binary_types[file_type] = {'count': 0, 'total_size': 0}
                    
                    binary_types[file_type]['count'] += 1
                    binary_types[file_type]['total_size'] += size
                    total_size += size
                except:
                    pass
    
    print(f"  Total files: {sum(t['count'] for t in binary_types.values())}")
    print(f"  Total size: {total_size:,} bytes ({total_size / 1024 / 1024:.1f} MB)")
    print(f"\n  By type:")
    
    for file_type, info in sorted(binary_types.items(), key=lambda x: x[1]['count'], reverse=True):
        count = info['count']
        size = info['total_size']
        avg_size = size / count if count > 0 else 0
        print(f"    - {file_type}: {count} files ({size:,} bytes, avg {avg_size:,.0f} bytes)")
    
    # Check if mostly source code
    source_types = ['python', 'javascript', 'c', 'cpp', 'java', 'text', 'source']
    source_count = sum(
        info['count'] 
        for file_type, info in binary_types.items() 
        if any(st in file_type.lower() for st in source_types)
    )
    
    if source_count > 0:
        total_count = sum(info['count'] for info in binary_types.values())
        percent = (source_count / total_count * 100) if total_count > 0 else 0
        print(f"\n  ⚠️ WARNING: {source_count}/{total_count} ({percent:.0f}%) are source code files!")
        print(f"     Dynamic analysis requires compiled binaries, not source code.")
        print(f"     Source code files won't have crypto function calls at runtime.")


def main():
    """Run all diagnostics."""
    print("╔" + "═"*78 + "╗")
    print("║" + "DYNAMIC DETECTION DIAGNOSTIC TOOL".center(78) + "║")
    print("╚" + "═"*78 + "╝")
    
    if len(sys.argv) < 2:
        print("\nUsage: python diagnose_dynamic_issue.py <workdir> [file_hash]")
        print("\nExample:")
        print("  python diagnose_dynamic_issue.py C:\\path\\to\\workspace")
        print("\n" + "="*80)
        print("QUICK CHECKS:")
        print("="*80)
        
        # Run quick checks without workdir
        check_frida()
        
        print("\n" + "="*80)
        print("NEXT STEPS:")
        print("="*80)
        print("1. Run this script with your workspace path:")
        print("   python diagnose_dynamic_issue.py C:\\path\\to\\workspace")
        print("\n2. Check the results for any ✗ marks")
        print("\n3. Common issues:")
        print("   - Source code files instead of compiled binaries")
        print("   - Missing static analysis hints (run static detector first)")
        print("   - Frida not installed")
        return
    
    workdir = sys.argv[1]
    file_hash = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Run all checks
    checks = [
        ("Frida Installation", lambda: check_frida()),
        ("Case Structure", lambda: check_case_structure(workdir)),
        ("Binary Types", lambda: check_binary_types(workdir)),
        ("Hints Availability", lambda: check_hints(workdir, file_hash)),
        ("Script Generation", lambda: check_script_generation(workdir, file_hash)),
        ("Runner Setup", lambda: check_runner(workdir, file_hash)),
    ]
    
    results = {}
    for name, check_func in checks:
        try:
            result = check_func()
            results[name] = "✓ PASS" if result else "✗ FAIL"
        except Exception as e:
            results[name] = f"✗ ERROR: {e}"
    
    # Summary
    print_section("DIAGNOSTIC SUMMARY")
    
    for name, result in results.items():
        status = "✓" if result.startswith("✓") else "✗"
        print(f"{status} {name:.<40} {result}")
    
    # Recommendations
    print("\n" + "="*80)
    print("RECOMMENDATIONS:")
    print("="*80)
    
    if results.get("Binary Types", "").startswith("✗"):
        print("\n⚠️ LIKELY ISSUE: Your case contains source code files, not binaries!")
        print("\nDynamic analysis (Frida) requires COMPILED BINARIES to analyze.")
        print("It intercepts function calls at runtime, but source code files:")
        print("  • Are not executable")
        print("  • Don't have compiled crypto functions")
        print("  • Won't run, so no calls to hook")
        print("\nSOLUTION: Either:")
        print("  1. Compile your source code to binaries (.exe, .dll, etc.)")
        print("  2. Use only static analysis for source code detection")
        print("  3. Provide actual binary files in your test case")
    
    print("\n")


if __name__ == "__main__":
    main()
