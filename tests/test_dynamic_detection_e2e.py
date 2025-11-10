"""
End-to-end test for dynamic detection.

Tests the full pipeline from runner to results generation.
Can be run without Frida for smoke testing.
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

# Fix encoding for Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from auditor.detectors.dynamic_detection import (
    DynamicRunner,
    DynamicContext,
    DynamicResult,
    Config
)


def create_test_environment(base_dir: str) -> dict:
    """
    Create test environment with mock data.

    Creates:
    - preproc/test_hash/input.bin (mock binary)
    - preproc/test_hash/metadata.json
    - analysis/static/test_hash/hints.json (mock hints)

    Returns:
        Dictionary with paths
    """
    file_hash = "test_abc123def456"

    # Create directory structure
    preproc_dir = os.path.join(base_dir, 'preproc', file_hash)
    os.makedirs(preproc_dir, exist_ok=True)

    static_dir = os.path.join(base_dir, 'analysis', 'static', file_hash)
    os.makedirs(static_dir, exist_ok=True)

    # Create mock binary (empty file for now)
    binary_path = os.path.join(preproc_dir, 'input.bin')
    with open(binary_path, 'wb') as f:
        # Write some mock binary data
        f.write(b'MZ\x90\x00')  # PE header start
        f.write(b'\x00' * 100)  # Padding

    # Create metadata.json
    metadata = {
        'file_hash': file_hash,
        'filename': 'test_binary.exe',
        'size': 104,
        'file_type': 'pe',
        'arch': 'x86_64'
    }

    metadata_path = os.path.join(preproc_dir, 'metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    # Create mock hints.json
    hints = {
        'file_hash': file_hash,
        'schema_version': '1.0',
        'hints': [
            {
                'id': 'hint_1',
                'type': 'crypto_function',
                'name': 'BCryptEncrypt',
                'module': 'bcrypt.dll',
                'confidence': 0.95,
                'reason_tags': ['signature_match', 'bcrypt_api']
            },
            {
                'id': 'hint_2',
                'type': 'crypto_function',
                'name': 'CryptEncrypt',
                'module': 'crypt32.dll',
                'confidence': 0.85,
                'reason_tags': ['signature_match', 'crypt32_api']
            },
            {
                'id': 'hint_3',
                'type': 'instruction_pattern',
                'address_or_range': '0x401000-0x401050',
                'confidence': 0.75,
                'reason_tags': ['aes_pattern', 'sbox_access']
            }
        ]
    }

    hints_path = os.path.join(static_dir, 'hints.json')
    with open(hints_path, 'w') as f:
        json.dump(hints, f, indent=2)

    return {
        'base_dir': base_dir,
        'file_hash': file_hash,
        'preproc_dir': preproc_dir,
        'binary_path': binary_path,
        'metadata_path': metadata_path,
        'hints_path': hints_path,
        'static_dir': static_dir
    }


def test_context_creation():
    """Test creating DynamicContext."""
    print("\n" + "="*60)
    print("TEST 1: Context Creation")
    print("="*60)

    try:
        ctx = DynamicContext(
            file_hash="test123",
            preproc_dir="/tmp/preproc/test123",
            hints_path="/tmp/hints.json",
            analysis_base="/tmp",
            mode="spawn",
            timeout=500
        )

        assert ctx.file_hash == "test123"
        assert ctx.mode == "spawn"
        assert ctx.timeout == 500

        print("✓ Context created successfully")
        print(f"  - File hash: {ctx.file_hash}")
        print(f"  - Mode: {ctx.mode}")
        print(f"  - Timeout: {ctx.timeout}s")
        print(f"  - Instrumenters: {ctx.instrumenters}")

        return True

    except Exception as e:
        print(f"✗ Context creation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_config_loading():
    """Test configuration loading."""
    print("\n" + "="*60)
    print("TEST 2: Configuration Loading")
    print("="*60)

    try:
        # Load default config
        config = Config.load()

        print("✓ Configuration loaded successfully")
        print(f"  - Timeout: {config.get('timeout')}s")
        print(f"  - Max trace events: {config.get('max_trace_events')}")
        print(f"  - Max crypto calls: {config.get('max_crypto_calls')}")
        print(f"  - BCrypt APIs: {len(config.get('crypto_apis', 'bcrypt', default=[]))}")
        print(f"  - Crypt32 APIs: {len(config.get('crypto_apis', 'crypt32', default=[]))}")

        return True

    except Exception as e:
        print(f"✗ Configuration loading failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_hints_loading(env: dict):
    """Test hints loading."""
    print("\n" + "="*60)
    print("TEST 3: Hints Loading")
    print("="*60)

    try:
        from auditor.detectors.dynamic_detection import hints_adapter

        hints_data = hints_adapter.load_hints(env['hints_path'])

        print("✓ Hints loaded successfully")
        print(f"  - File hash: {hints_data.get('file_hash')}")
        print(f"  - Total hints: {len(hints_data.get('hints', []))}")

        # Test hint filtering
        crypto_hints = hints_adapter.get_crypto_function_hints(hints_data)
        print(f"  - Crypto function hints: {len(crypto_hints)}")

        address_hints = hints_adapter.get_address_hints(hints_data)
        print(f"  - Address-based hints: {len(address_hints)}")

        summary = hints_adapter.summarize_hints(hints_data)
        print(f"  - Summary: {summary}")

        return True

    except Exception as e:
        print(f"✗ Hints loading failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_hook_generation(env: dict):
    """Test Frida hook generation."""
    print("\n" + "="*60)
    print("TEST 4: Frida Hook Generation")
    print("="*60)

    try:
        from auditor.detectors.dynamic_detection import hints_adapter, frida_scripter, Config

        hints_data = hints_adapter.load_hints(env['hints_path'])
        config = Config.load()

        hooks = frida_scripter.generate_hooks(hints_data, config)

        print("✓ Frida hooks generated successfully")
        print(f"  - Total scripts: {len(hooks)}")

        for i, hook in enumerate(hooks, 1):
            lines = hook.count('\n')
            print(f"  - Script {i}: {lines} lines")

            # Check for expected content
            if 'Helpers' in hook:
                print(f"    → Contains helper functions")
            if 'BCryptEncrypt' in hook or 'CryptEncrypt' in hook:
                print(f"    → Contains crypto API hooks")
            if 'Memory' in hook and 'Scan' in hook:
                print(f"    → Contains memory scanner")
            if 'CallGraph' in hook:
                print(f"    → Contains call graph tracker")

        return True

    except Exception as e:
        print(f"✗ Hook generation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_trace_management():
    """Test trace manager."""
    print("\n" + "="*60)
    print("TEST 5: Trace Management")
    print("="*60)

    try:
        from auditor.detectors.dynamic_detection import trace_manager

        mgr = trace_manager.TraceManager(
            max_events=100,
            max_size_mb=1,
            max_crypto_calls=10
        )

        print("✓ Trace manager created")
        print(f"  - Max events: {mgr.max_events}")
        print(f"  - Max crypto calls: {mgr.max_crypto_calls}")

        # Add some test events
        for i in range(15):
            event = {
                'type': 'crypto_call' if i < 10 else 'crypto_return',
                'function': 'BCryptEncrypt',
                'timestamp': 1000 + i
            }
            added = mgr.add_event(event)

            if not added:
                print(f"  - Event {i+1} rejected (limit reached)")
                break

        summary = mgr.get_summary()
        print(f"  - Total events collected: {summary.total_events}")
        print(f"  - Crypto calls: {summary.crypto_calls}")
        print(f"  - Limits reached: {summary.limits_reached}")

        # Test NDJSON writing
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ndjson') as f:
            temp_path = f.name

        try:
            mgr.write_ndjson(temp_path)
            print(f"  - NDJSON written to temp file")

            # Verify
            with open(temp_path, 'r') as f:
                lines = f.readlines()
                print(f"  - Verified {len(lines)} events in file")

        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        return True

    except Exception as e:
        print(f"✗ Trace management failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_trace_sanitization():
    """Test trace sanitization."""
    print("\n" + "="*60)
    print("TEST 6: Trace Sanitization")
    print("="*60)

    try:
        from auditor.detectors.dynamic_detection import traces_sanitizer

        # Create test events with potentially sensitive data
        events = [
            {
                'type': 'crypto_call',
                'function': 'BCryptEncrypt',
                'buffer': 'some_raw_data_here',  # Should be sanitized
                'args_hashes': {
                    'arg0': 'hash_abc123'  # Already a hash, keep
                },
                'timestamp': 1000
            },
            {
                'type': 'crypto_return',
                'retval': 0,
                'raw_data': 'secret_key_12345',  # Should be redacted
                'timestamp': 1001
            }
        ]

        sanitized, violations = traces_sanitizer.sanitize_traces(events, strict=True)

        print("✓ Trace sanitization completed")
        print(f"  - Original events: {len(events)}")
        print(f"  - Sanitized events: {len(sanitized)}")
        print(f"  - Violations detected: {len(violations)}")

        if violations:
            for v in violations[:3]:
                print(f"    → {v}")

        # Check sanitization worked
        for event in sanitized:
            if 'raw_data' in event:
                assert event['raw_data'] == 'REDACTED', "Raw data should be redacted"
                print("  - ✓ Raw data redacted")

        return True

    except Exception as e:
        print(f"✗ Trace sanitization failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_runner_without_frida(env: dict):
    """Test runner without Frida (checks pre-flight)."""
    print("\n" + "="*60)
    print("TEST 7: Runner Pre-flight (No Frida)")
    print("="*60)

    try:
        ctx = DynamicContext(
            file_hash=env['file_hash'],
            preproc_dir=env['preproc_dir'],
            hints_path=env['hints_path'],
            analysis_base=env['base_dir'],
            mode='spawn',
            timeout=10  # Short timeout for testing
        )

        runner = DynamicRunner()

        print(f"  - Frida available: {runner._frida_available}")

        # Test pre-flight checks
        result = DynamicResult(file_hash=ctx.file_hash)
        result = runner._preflight_checks(ctx, result)

        if runner._frida_available:
            print("✓ Pre-flight checks passed (Frida available)")
        else:
            print("✓ Pre-flight checks completed (Frida not available)")
            print(f"  - Errors: {result.errors}")

        # Test setup
        result = DynamicResult(file_hash=ctx.file_hash)
        config, hints_data, analysis_dir = runner._setup(ctx, result)

        if hints_data:
            print("✓ Setup stage completed")
            print(f"  - Config loaded: Yes")
            print(f"  - Hints loaded: {len(hints_data.get('hints', []))} hints")
            print(f"  - Analysis dir: {analysis_dir}")

        return True

    except Exception as e:
        print(f"✗ Runner test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_full_pipeline_mock(env: dict):
    """Test full pipeline with mocking (no actual Frida execution)."""
    print("\n" + "="*60)
    print("TEST 8: Full Pipeline (Mock)")
    print("="*60)

    try:
        # Import all components
        from auditor.detectors.dynamic_detection import (
            sandbox,
            input_feeder,
            frida_scripter,
            trace_manager,
            traces_sanitizer,
            results_packager,
            hints_adapter,
            Config
        )

        print("Step 1: Load hints...")
        hints_data = hints_adapter.load_hints(env['hints_path'])
        print(f"  ✓ Loaded {len(hints_data['hints'])} hints")

        print("Step 2: Load config...")
        config = Config.load()
        print(f"  ✓ Config loaded")

        print("Step 3: Setup sandbox...")
        sand = sandbox.Sandbox(timeout=10, memory_limit=512)
        sand.setup()
        print(f"  ✓ Sandbox created: {sand.temp_dir}")

        try:
            print("Step 4: Prepare input...")
            input_config = input_feeder.prepare_input(env['preproc_dir'], config, sand.temp_dir)
            print(f"  ✓ Input prepared: {input_feeder.get_input_summary(input_config)}")

            print("Step 5: Generate hooks...")
            hooks = frida_scripter.generate_hooks(hints_data, config)
            print(f"  ✓ Generated {len(hooks)} scripts")

            print("Step 6: Create trace manager...")
            trace_mgr = trace_manager.TraceManager(
                max_events=100,
                max_size_mb=1,
                max_crypto_calls=10
            )
            print(f"  ✓ Trace manager ready")

            # Simulate some trace events (since we can't run Frida without a real binary)
            print("Step 7: Simulating trace collection...")
            mock_events = [
                {
                    'type': 'crypto_call',
                    'hint_id': 'hint_1',
                    'function': 'BCryptEncrypt',
                    'module': 'bcrypt.dll',
                    'timestamp': 1000,
                    'args_hashes': {'arg0': 'hash_abc', 'arg1': 'hash_def'}
                },
                {
                    'type': 'crypto_return',
                    'function': 'BCryptEncrypt',
                    'retval': 0,
                    'timestamp': 1001
                }
            ]

            for event in mock_events:
                trace_mgr.add_event(event)

            print(f"  ✓ Collected {trace_mgr.get_event_count()} events")

            print("Step 8: Sanitize traces...")
            sanitized, violations = traces_sanitizer.sanitize_traces(trace_mgr.get_events(), strict=True)
            trace_mgr.events = sanitized
            print(f"  ✓ Sanitized {len(sanitized)} events, {len(violations)} violations")

            print("Step 9: Package results...")
            ctx = DynamicContext(
                file_hash=env['file_hash'],
                preproc_dir=env['preproc_dir'],
                hints_path=env['hints_path'],
                analysis_base=env['base_dir'],
                mode='spawn'
            )

            analysis_dir = os.path.join(env['base_dir'], 'analysis', 'dynamic', env['file_hash'])

            result = results_packager.package_results(
                ctx,
                trace_mgr,
                hints_data,
                analysis_dir,
                execution_time_seconds=1.5,
                incomplete=False,
                incomplete_reason=None
            )

            print(f"  ✓ Results packaged")
            print(f"    - Results file: {result.dynamic_results_path}")
            print(f"    - Trace file: {result.trace_path}")

            # Verify files were created
            if os.path.exists(result.dynamic_results_path):
                with open(result.dynamic_results_path, 'r') as f:
                    results_data = json.load(f)
                    print(f"    - Findings: {len(results_data.get('findings', []))}")
                    print(f"    - Summary: {results_data.get('summary')}")

            if os.path.exists(result.trace_path):
                with open(result.trace_path, 'r') as f:
                    trace_lines = f.readlines()
                    print(f"    - Trace events: {len(trace_lines)}")

            print("\n✓ Full pipeline completed successfully!")
            return True

        finally:
            print("Step 10: Cleanup...")
            sand.cleanup()
            print("  ✓ Sandbox cleaned up")

    except Exception as e:
        print(f"✗ Full pipeline test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """Run all tests."""
    print("\n" + "="*60)
    print("DYNAMIC DETECTION END-TO-END TESTS")
    print("="*60)

    # Create test environment
    temp_dir = tempfile.mkdtemp(prefix="dynamic_test_")
    print(f"\nTest environment: {temp_dir}")

    try:
        env = create_test_environment(temp_dir)
        print(f"✓ Test environment created")
        print(f"  - File hash: {env['file_hash']}")
        print(f"  - Binary: {env['binary_path']}")
        print(f"  - Hints: {env['hints_path']}")

        # Run tests
        tests = [
            ("Context Creation", test_context_creation, None),
            ("Configuration Loading", test_config_loading, None),
            ("Hints Loading", test_hints_loading, env),
            ("Hook Generation", test_hook_generation, env),
            ("Trace Management", test_trace_management, None),
            ("Trace Sanitization", test_trace_sanitization, None),
            ("Runner Pre-flight", test_runner_without_frida, env),
            ("Full Pipeline Mock", test_full_pipeline_mock, env),
        ]

        results = []
        for name, test_func, test_env in tests:
            try:
                if test_env:
                    result = test_func(test_env)
                else:
                    result = test_func()
                results.append((name, result))
            except Exception as e:
                print(f"\n✗ Test '{name}' raised exception: {e}")
                import traceback
                traceback.print_exc()
                results.append((name, False))

        # Summary
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)

        passed = sum(1 for _, r in results if r)
        total = len(results)

        for name, result in results:
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"{status} - {name}")

        print(f"\nTotal: {passed}/{total} tests passed")

        if passed == total:
            print("\n🎉 All tests passed!")
            return 0
        else:
            print(f"\n⚠️  {total - passed} test(s) failed")
            return 1

    finally:
        # Cleanup test environment
        print(f"\nCleaning up test environment: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(run_all_tests())
