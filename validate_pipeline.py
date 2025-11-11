"""
Comprehensive validation script for static detection pipeline.
Runs all checks and provides actionable feedback for end users.
"""
import sys
import subprocess
from pathlib import Path

def run_command(cmd, description):
    """Run a command and return (success, output)."""
    print(f"\n{'='*70}")
    print(f"Running: {description}")
    print(f"{'='*70}")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Failed: {e}")
        return False

def main():
    """Run comprehensive validation checks."""
    print("="*70)
    print("STATIC DETECTION PIPELINE COMPREHENSIVE VALIDATION")
    print("="*70)
    
    results = {}
    
    # 1. Setup validation
    results['setup'] = run_command(
        "python -m src.auditor.detectors.static_detection.setup check",
        "Setup Validation"
    )
    
    # 2. Policy unit tests
    results['policy_unit'] = run_command(
        "python test_policy.py",
        "Policy Unit Tests"
    )
    
    # 3. Policy integration tests
    results['policy_integration'] = run_command(
        "python test_policy_integration.py",
        "Policy Integration Tests"
    )
    
    # 4. Optimization verification
    results['optimization'] = run_command(
        "python verify_optimization.py",
        "Optimization Verification"
    )
    
    # 5. Ghidra pipeline test (if Ghidra is configured)
    print(f"\n{'='*70}")
    print("Checking if Ghidra tests should run...")
    print("="*70)
    
    try:
        from src.auditor.detectors.static_detection import config
        policy = config.get_ghidra_run_policy()
        print(f"Current policy: {policy}")
        
        if policy != 'never':
            results['ghidra'] = run_command(
                "python test_ghidra_pipeline.py",
                "Ghidra Pipeline Test"
            )
        else:
            print("⏭️  Skipping Ghidra tests (policy='never')")
            results['ghidra'] = None
    except Exception as e:
        print(f"⚠️  Could not determine Ghidra policy: {e}")
        results['ghidra'] = None
    
    # Summary
    print("\n" + "="*70)
    print("VALIDATION SUMMARY")
    print("="*70)
    
    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)
    total = len(results)
    
    for name, status in results.items():
        if status is True:
            icon = "✅"
            msg = "PASSED"
        elif status is False:
            icon = "❌"
            msg = "FAILED"
        else:
            icon = "⏭️ "
            msg = "SKIPPED"
        print(f"{icon} {name.replace('_', ' ').title()}: {msg}")
    
    print("\n" + "="*70)
    print(f"Results: {passed}/{total-skipped} passed")
    if failed > 0:
        print(f"⚠️  {failed} test(s) failed")
    if skipped > 0:
        print(f"ℹ️  {skipped} test(s) skipped")
    print("="*70)
    
    if failed == 0:
        print("\n🎉 ALL CHECKS PASSED!")
        print("\nThe static detection pipeline is ready for use.")
        print("\nNext steps:")
        print("  1. Run: python src/app.py")
        print("  2. See: docs/static-detection-quickstart.md")
        return 0
    else:
        print("\n❌ SOME CHECKS FAILED")
        print("\nPlease review the errors above and:")
        print("  1. Run: python -m src.auditor.detectors.static_detection.setup check")
        print("  2. See: docs/static-detection-quickstart.md#troubleshooting")
        return 1

if __name__ == "__main__":
    sys.exit(main())
