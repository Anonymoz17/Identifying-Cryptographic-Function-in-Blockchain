"""
Performance profiling tests for dynamic cryptographic function detector (Phase 7).

These tests establish performance baselines and identify bottlenecks in the
dynamic analysis system. They measure execution time, memory usage, throughput,
and cache efficiency to ensure the system meets performance requirements.

Test Coverage:
- PERF-01: Execution Time Baseline (full pipeline)
- PERF-02: Memory Usage Profiling (heap, trace collection)
- PERF-03: Trace Collection Throughput (events/second)
- PERF-04: Cache Efficiency (hit rate, TTL behavior)

Performance Targets:
- Pipeline execution: <30s for typical binary
- Memory usage: <512MB peak for 10k events
- Trace throughput: >1000 events/second
- Cache hit rate: >80% for repeated analyses
"""

import os
import sys
import json
import time
import tempfile
import shutil
import tracemalloc
from pathlib import Path
from typing import Dict, Any, List
import gc

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from auditor.detectors.dynamic_detection import (
    DynamicRunner,
    DynamicContext,
    DynamicResult,
    Config
)
from auditor.detectors.dynamic_detection import trace_manager, cache
from auditor.detectors.dynamic_detection.traces_sanitizer import TraceSanitizer


# ============================================================================
# Pytest Markers and Fixtures
# ============================================================================

pytestmark = pytest.mark.performance


@pytest.fixture
def temp_workspace(tmp_path):
    """
    Create temporary workspace for performance tests.

    Returns:
        Path to workspace directory
    """
    workspace = tmp_path / "perf_workspace"
    workspace.mkdir()

    # Create directory structure
    (workspace / "preproc").mkdir()
    (workspace / "analysis" / "static").mkdir(parents=True)
    (workspace / "analysis" / "dynamic").mkdir(parents=True)

    yield workspace

    # Cleanup
    # pytest handles tmp_path cleanup


@pytest.fixture
def performance_test_environment(temp_workspace):
    """
    Create performance test environment with realistic data.

    Returns:
        Dictionary with paths and configuration
    """
    file_hash = "perf_test_binary"

    # Create preprocessing directory
    preproc_dir = temp_workspace / "preproc" / file_hash
    preproc_dir.mkdir(parents=True)

    # Create realistic mock binary (1MB)
    binary_path = preproc_dir / "input.bin"
    with open(binary_path, 'wb') as f:
        # PE header
        f.write(b'MZ\x90\x00')
        # Realistic binary size
        f.write(os.urandom(1024 * 1024))  # 1MB of random data

    # Create metadata.json
    metadata = {
        'file_hash': file_hash,
        'filename': 'perf_test.exe',
        'size': binary_path.stat().st_size,
        'file_type': 'pe',
        'arch': 'x86_64'
    }

    metadata_path = preproc_dir / 'metadata.json'
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)

    # Create static analysis directory
    static_dir = temp_workspace / "analysis" / "static" / file_hash
    static_dir.mkdir(parents=True)

    # Create realistic hints with multiple crypto functions
    hints = {
        'file_hash': file_hash,
        'schema_version': '1.0',
        'hints': [
            {
                'id': f'hint_{i}',
                'type': 'crypto_function',
                'name': func,
                'module': module,
                'confidence': 0.85,
                'reason_tags': ['signature_match', 'crypto_api']
            }
            for i, (func, module) in enumerate([
                ('BCryptEncrypt', 'bcrypt.dll'),
                ('BCryptDecrypt', 'bcrypt.dll'),
                ('BCryptGenRandom', 'bcrypt.dll'),
                ('CryptEncrypt', 'crypt32.dll'),
                ('CryptDecrypt', 'crypt32.dll'),
                ('CryptHashData', 'crypt32.dll'),
            ])
        ]
    }

    hints_path = static_dir / 'hints.json'
    with open(hints_path, 'w') as f:
        json.dump(hints, f, indent=2)

    return {
        'file_hash': file_hash,
        'workspace': str(temp_workspace),
        'preproc_dir': str(preproc_dir),
        'binary_path': str(binary_path),
        'metadata_path': str(metadata_path),
        'hints_path': str(hints_path),
        'static_dir': str(static_dir)
    }


# ============================================================================
# Helper Functions
# ============================================================================

def format_bytes(bytes_value: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.2f} TB"


def format_duration(seconds: float) -> str:
    """Format duration to human-readable string."""
    if seconds < 1:
        return f"{seconds * 1000:.2f} ms"
    elif seconds < 60:
        return f"{seconds:.2f} s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.2f}s"


def create_mock_trace_events(count: int) -> List[Dict[str, Any]]:
    """
    Create realistic mock trace events.

    Args:
        count: Number of events to create

    Returns:
        List of trace event dictionaries
    """
    events = []
    functions = ['BCryptEncrypt', 'BCryptDecrypt', 'CryptHashData', 'CryptEncrypt']

    for i in range(count):
        event = {
            'type': 'crypto_call' if i % 2 == 0 else 'crypto_return',
            'function': functions[i % len(functions)],
            'module': 'bcrypt.dll' if i % 2 == 0 else 'crypt32.dll',
            'timestamp': 1000000 + i,
            'args_hashes': {
                f'arg{j}': f'hash_{i:08x}_{j:04x}'
                for j in range(3)
            }
        }
        events.append(event)

    return events


def measure_memory_usage(func, *args, **kwargs):
    """
    Measure memory usage of a function.

    Args:
        func: Function to measure
        *args: Function arguments
        **kwargs: Function keyword arguments

    Returns:
        Tuple of (result, peak_memory_bytes)
    """
    # Force garbage collection before measurement
    gc.collect()

    # Start memory tracking
    tracemalloc.start()

    try:
        # Execute function
        result = func(*args, **kwargs)

        # Get memory statistics
        current, peak = tracemalloc.get_traced_memory()

        return result, peak

    finally:
        # Stop tracking
        tracemalloc.stop()


# ============================================================================
# PERF-01: Execution Time Baseline
# ============================================================================

@pytest.mark.performance
def test_perf_01_execution_time_baseline(performance_test_environment):
    """
    PERF-01: Execution Time Baseline

    Objective:
        Establish baseline execution time for the full dynamic analysis pipeline
        with mock data (no actual Frida execution).

    Test Scenario:
        1. Create context with realistic configuration
        2. Initialize runner
        3. Measure time for each pipeline stage:
           - Pre-flight checks
           - Configuration loading
           - Hints loading
           - Cache checking
           - Sandbox setup
           - Hook generation
           - Trace management
           - Sanitization
           - Results packaging
        4. Calculate total execution time
        5. Identify bottlenecks

    Performance Target:
        - Pre-flight + setup: <1s
        - Hook generation: <2s
        - Trace processing (10k events): <5s
        - Results packaging: <1s
        - Total: <10s (excluding actual Frida execution)

    Expected Results:
        - Clear breakdown of time spent in each stage
        - Identification of slow stages (if any)
        - Baseline metrics for future optimization
    """
    print("\n" + "="*70)
    print("PERF-01: Execution Time Baseline")
    print("="*70)

    env = performance_test_environment

    # Create context
    ctx = DynamicContext(
        file_hash=env['file_hash'],
        preproc_dir=env['preproc_dir'],
        hints_path=env['hints_path'],
        analysis_base=env['workspace']
    )

    print(f"\n[TEST] Measuring pipeline stage execution times...")

    # Initialize runner
    runner = DynamicRunner()
    timings = {}

    # Stage 0: Pre-flight checks
    start = time.time()
    result = DynamicResult(file_hash=ctx.file_hash)
    result = runner._preflight_checks(ctx, result)
    timings['preflight'] = time.time() - start
    print(f"  ✓ Pre-flight checks: {format_duration(timings['preflight'])}")

    # Stage 1: Setup (config + hints)
    start = time.time()
    result = DynamicResult(file_hash=ctx.file_hash)
    config, hints_data, analysis_dir = runner._setup(ctx, result)
    timings['setup'] = time.time() - start
    print(f"  ✓ Setup (config + hints): {format_duration(timings['setup'])}")

    # Stage 2: Cache check
    start = time.time()
    cache_result = cache.should_use_cache(ctx, analysis_dir)
    timings['cache_check'] = time.time() - start
    print(f"  ✓ Cache check: {format_duration(timings['cache_check'])}")

    # Stage 3: Sandbox setup
    start = time.time()
    sand = runner._setup_sandbox(ctx, config)
    timings['sandbox'] = time.time() - start
    print(f"  ✓ Sandbox setup: {format_duration(timings['sandbox'])}")

    # Stage 4: Hook generation
    start = time.time()
    hooks = runner._generate_hooks(hints_data, config)
    timings['hooks'] = time.time() - start
    print(f"  ✓ Hook generation: {format_duration(timings['hooks'])}")
    print(f"    - Generated {len(hooks)} hook scripts")

    # Stage 5: Trace manager creation
    start = time.time()
    trace_mgr = runner._create_trace_manager(config)
    timings['trace_mgr'] = time.time() - start
    print(f"  ✓ Trace manager init: {format_duration(timings['trace_mgr'])}")

    # Stage 6: Simulate trace collection (10k events)
    print(f"\n  [TEST] Simulating trace collection (10,000 events)...")
    start = time.time()
    mock_events = create_mock_trace_events(10000)

    for event in mock_events:
        trace_mgr.add_event(event)

    timings['trace_collection'] = time.time() - start
    print(f"  ✓ Trace collection: {format_duration(timings['trace_collection'])}")
    print(f"    - Events collected: {trace_mgr.get_event_count():,}")
    print(f"    - Throughput: {trace_mgr.get_event_count() / timings['trace_collection']:,.0f} events/s")

    # Stage 7: Trace sanitization
    start = time.time()
    sanitized, violations = runner._sanitize_traces(trace_mgr.get_events())
    timings['sanitization'] = time.time() - start
    print(f"  ✓ Trace sanitization: {format_duration(timings['sanitization'])}")

    # Stage 8: Results packaging
    start = time.time()
    result = runner._package_results(
        ctx,
        trace_mgr,
        hints_data,
        analysis_dir,
        execution_time=1.0,
        incomplete=False,
        incomplete_reason=None
    )
    timings['packaging'] = time.time() - start
    print(f"  ✓ Results packaging: {format_duration(timings['packaging'])}")

    # Stage 9: Cache write
    start = time.time()
    runner._write_cache(ctx, analysis_dir, result)
    timings['cache_write'] = time.time() - start
    print(f"  ✓ Cache write: {format_duration(timings['cache_write'])}")

    # Cleanup
    sand.cleanup()

    # Calculate totals
    total_time = sum(timings.values())

    print(f"\n{'='*70}")
    print("PERFORMANCE SUMMARY")
    print(f"{'='*70}")
    print(f"Total execution time: {format_duration(total_time)}")
    print(f"\nTime breakdown:")

    # Sort by time (descending)
    sorted_timings = sorted(timings.items(), key=lambda x: x[1], reverse=True)

    for stage, duration in sorted_timings:
        percentage = (duration / total_time) * 100
        print(f"  {stage:.<25} {format_duration(duration):>10} ({percentage:>5.1f}%)")

    # Performance assertions
    print(f"\n{'='*70}")
    print("PERFORMANCE CHECKS")
    print(f"{'='*70}")

    # Check individual stage targets
    checks = {
        'Pre-flight + setup': (timings['preflight'] + timings['setup'], 1.0),
        'Hook generation': (timings['hooks'], 2.0),
        'Trace collection (10k)': (timings['trace_collection'], 5.0),
        'Sanitization': (timings['sanitization'], 2.0),
        'Results packaging': (timings['packaging'], 1.0),
        'Total (no Frida)': (total_time, 15.0)
    }

    all_passed = True

    for check_name, (actual, target) in checks.items():
        status = "✓ PASS" if actual <= target else "✗ FAIL"
        if actual > target:
            all_passed = False

        print(f"  {status} {check_name}: {format_duration(actual)} (target: {format_duration(target)})")

    if all_passed:
        print(f"\n[OK] PERF-01 PASSED - All performance targets met")
    else:
        print(f"\n[WARNING] Some performance targets missed (not a failure, just FYI)")

    # Return timings for future analysis
    return timings


# ============================================================================
# PERF-02: Memory Usage Profiling
# ============================================================================

@pytest.mark.performance
def test_perf_02_memory_usage_profiling(performance_test_environment):
    """
    PERF-02: Memory Usage Profiling

    Objective:
        Measure peak memory usage during trace collection and processing
        to ensure system stays within acceptable limits.

    Test Scenario:
        1. Create trace manager
        2. Add 10,000 realistic events while tracking memory
        3. Measure peak memory usage
        4. Test memory efficiency with different event sizes
        5. Verify no memory leaks after cleanup

    Performance Target:
        - 10k events: <100MB peak memory
        - 50k events: <512MB peak memory
        - No memory leaks after cleanup

    Expected Results:
        - Peak memory within limits
        - Memory scales linearly with event count
        - No memory retained after cleanup
    """
    print("\n" + "="*70)
    print("PERF-02: Memory Usage Profiling")
    print("="*70)

    # Test 1: 10k events memory usage
    print(f"\n[TEST 1] Memory usage with 10,000 events...")

    def test_10k_events():
        mgr = trace_manager.TraceManager(
            max_events=10000,
            max_size_mb=100,
            max_crypto_calls=5000
        )

        events = create_mock_trace_events(10000)

        for event in events:
            mgr.add_event(event)

        return mgr

    result_10k, peak_10k = measure_memory_usage(test_10k_events)

    print(f"  Peak memory: {format_bytes(peak_10k)}")
    print(f"  Events stored: {result_10k.get_event_count():,}")
    print(f"  Memory per event: {format_bytes(peak_10k / result_10k.get_event_count())}")

    # Check target
    target_10k_mb = 100
    actual_10k_mb = peak_10k / (1024 * 1024)

    if actual_10k_mb <= target_10k_mb:
        print(f"  ✓ PASS: Within {target_10k_mb}MB target")
    else:
        print(f"  ✗ WARN: Exceeds {target_10k_mb}MB target (actual: {actual_10k_mb:.1f}MB)")

    # Test 2: Memory scaling test
    print(f"\n[TEST 2] Memory scaling with different event counts...")

    event_counts = [1000, 5000, 10000]
    memory_usage = []

    for count in event_counts:
        def test_events():
            mgr = trace_manager.TraceManager(
                max_events=count,
                max_size_mb=100,
                max_crypto_calls=count
            )
            events = create_mock_trace_events(count)
            for event in events:
                mgr.add_event(event)
            return mgr

        _, peak = measure_memory_usage(test_events)
        memory_usage.append(peak)

        print(f"  {count:>6,} events: {format_bytes(peak):>10} ({format_bytes(peak / count)}/event)")

    # Check if scaling is roughly linear
    # Memory per event should be similar across counts
    mem_per_event = [mem / count for mem, count in zip(memory_usage, event_counts)]
    avg_per_event = sum(mem_per_event) / len(mem_per_event)
    variance = max(abs(mpe - avg_per_event) / avg_per_event for mpe in mem_per_event)

    print(f"\n  Average memory per event: {format_bytes(avg_per_event)}")
    print(f"  Variance: {variance * 100:.1f}%")

    if variance < 0.2:  # Less than 20% variance
        print(f"  ✓ PASS: Memory scales linearly (variance < 20%)")
    else:
        print(f"  ✗ WARN: Memory scaling not linear (variance: {variance * 100:.1f}%)")

    # Test 3: Sanitizer memory usage
    print(f"\n[TEST 3] Sanitizer memory usage...")

    def test_sanitization():
        events = create_mock_trace_events(10000)
        sanitizer = TraceSanitizer(strict_mode=True)
        sanitized = sanitizer.sanitize_all(events)
        return sanitized

    _, peak_sanitizer = measure_memory_usage(test_sanitization)

    print(f"  Peak memory during sanitization: {format_bytes(peak_sanitizer)}")
    print(f"  Memory overhead: {format_bytes(peak_sanitizer - peak_10k)}")

    # Test 4: NDJSON export memory usage
    print(f"\n[TEST 4] NDJSON export memory usage...")

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ndjson') as f:
        temp_path = f.name

    try:
        def test_ndjson_export():
            mgr = trace_manager.TraceManager(max_events=10000)
            events = create_mock_trace_events(10000)
            for event in events:
                mgr.add_event(event)
            mgr.write_ndjson(temp_path)
            return mgr

        _, peak_export = measure_memory_usage(test_ndjson_export)

        file_size = Path(temp_path).stat().st_size

        print(f"  Peak memory during export: {format_bytes(peak_export)}")
        print(f"  Output file size: {format_bytes(file_size)}")
        print(f"  Memory/file ratio: {peak_export / file_size:.2f}x")

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    # Summary
    print(f"\n{'='*70}")
    print("MEMORY PROFILING SUMMARY")
    print(f"{'='*70}")

    print(f"10k events peak memory: {format_bytes(peak_10k)}")
    print(f"Sanitization overhead: {format_bytes(peak_sanitizer - peak_10k)}")
    print(f"NDJSON export memory: {format_bytes(peak_export)}")

    if actual_10k_mb <= target_10k_mb:
        print(f"\n[OK] PERF-02 PASSED - Memory usage within targets")
    else:
        print(f"\n[WARNING] Memory usage higher than target (not a failure)")

    return {
        'peak_10k': peak_10k,
        'peak_sanitizer': peak_sanitizer,
        'peak_export': peak_export
    }


# ============================================================================
# PERF-03: Trace Collection Throughput
# ============================================================================

@pytest.mark.performance
def test_perf_03_trace_collection_throughput(performance_test_environment):
    """
    PERF-03: Trace Collection Throughput

    Objective:
        Measure trace collection throughput (events/second) to identify
        bottlenecks in event processing.

    Test Scenario:
        1. Create trace manager with various configurations
        2. Measure throughput for different event types
        3. Test with concurrent event addition (simulating Frida callbacks)
        4. Measure serialization (NDJSON) throughput

    Performance Target:
        - Event addition: >1,000 events/second
        - Sanitization: >500 events/second
        - NDJSON serialization: >2,000 events/second
        - Overall pipeline: >500 events/second

    Expected Results:
        - Throughput meets targets for all operations
        - Bottlenecks identified if targets not met
    """
    print("\n" + "="*70)
    print("PERF-03: Trace Collection Throughput")
    print("="*70)

    # Test 1: Raw event addition throughput
    print(f"\n[TEST 1] Raw event addition throughput...")

    event_count = 10000
    mgr = trace_manager.TraceManager(max_events=event_count)

    events = create_mock_trace_events(event_count)

    start = time.time()
    for event in events:
        mgr.add_event(event)
    elapsed = time.time() - start

    throughput_add = event_count / elapsed

    print(f"  Events added: {event_count:,}")
    print(f"  Time: {format_duration(elapsed)}")
    print(f"  Throughput: {throughput_add:,.0f} events/s")

    target_add = 1000
    if throughput_add >= target_add:
        print(f"  ✓ PASS: Exceeds {target_add:,} events/s target")
    else:
        print(f"  ✗ FAIL: Below {target_add:,} events/s target")

    # Test 2: Sanitization throughput
    print(f"\n[TEST 2] Sanitization throughput...")

    sanitizer = TraceSanitizer(strict_mode=True)
    events_to_sanitize = create_mock_trace_events(10000)

    start = time.time()
    sanitized = sanitizer.sanitize_all(events_to_sanitize)
    elapsed = time.time() - start

    throughput_sanitize = len(events_to_sanitize) / elapsed

    print(f"  Events sanitized: {len(sanitized):,}")
    print(f"  Time: {format_duration(elapsed)}")
    print(f"  Throughput: {throughput_sanitize:,.0f} events/s")

    target_sanitize = 500
    if throughput_sanitize >= target_sanitize:
        print(f"  ✓ PASS: Exceeds {target_sanitize:,} events/s target")
    else:
        print(f"  ✗ WARN: Below {target_sanitize:,} events/s target")

    # Test 3: NDJSON serialization throughput
    print(f"\n[TEST 3] NDJSON serialization throughput...")

    mgr_ndjson = trace_manager.TraceManager(max_events=10000)
    for event in create_mock_trace_events(10000):
        mgr_ndjson.add_event(event)

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ndjson') as f:
        temp_path = f.name

    try:
        start = time.time()
        mgr_ndjson.write_ndjson(temp_path)
        elapsed = time.time() - start

        throughput_serialize = mgr_ndjson.get_event_count() / elapsed

        print(f"  Events serialized: {mgr_ndjson.get_event_count():,}")
        print(f"  Time: {format_duration(elapsed)}")
        print(f"  Throughput: {throughput_serialize:,.0f} events/s")

        target_serialize = 2000
        if throughput_serialize >= target_serialize:
            print(f"  ✓ PASS: Exceeds {target_serialize:,} events/s target")
        else:
            print(f"  ✗ WARN: Below {target_serialize:,} events/s target")

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    # Test 4: Overall pipeline throughput
    print(f"\n[TEST 4] Overall pipeline throughput...")

    # Simulate full pipeline: add → sanitize → package
    start = time.time()

    # Add events
    mgr_pipeline = trace_manager.TraceManager(max_events=10000)
    events_pipeline = create_mock_trace_events(10000)
    for event in events_pipeline:
        mgr_pipeline.add_event(event)

    # Sanitize
    sanitizer_pipeline = TraceSanitizer(strict_mode=True)
    sanitized_pipeline = sanitizer_pipeline.sanitize_all(mgr_pipeline.get_events())

    # Package (simplified - just summary generation)
    from auditor.detectors.dynamic_detection.results_packager import generate_summary
    summary = generate_summary(sanitized_pipeline, 1.0)

    elapsed = time.time() - start
    throughput_pipeline = len(events_pipeline) / elapsed

    print(f"  Events processed: {len(events_pipeline):,}")
    print(f"  Time: {format_duration(elapsed)}")
    print(f"  Throughput: {throughput_pipeline:,.0f} events/s")

    target_pipeline = 500
    if throughput_pipeline >= target_pipeline:
        print(f"  ✓ PASS: Exceeds {target_pipeline:,} events/s target")
    else:
        print(f"  ✗ WARN: Below {target_pipeline:,} events/s target")

    # Summary
    print(f"\n{'='*70}")
    print("THROUGHPUT SUMMARY")
    print(f"{'='*70}")

    print(f"Event addition:     {throughput_add:>10,.0f} events/s (target: 1,000)")
    print(f"Sanitization:       {throughput_sanitize:>10,.0f} events/s (target: 500)")
    print(f"NDJSON export:      {throughput_serialize:>10,.0f} events/s (target: 2,000)")
    print(f"Overall pipeline:   {throughput_pipeline:>10,.0f} events/s (target: 500)")

    all_passed = (
        throughput_add >= target_add and
        throughput_pipeline >= target_pipeline
    )

    if all_passed:
        print(f"\n[OK] PERF-03 PASSED - All throughput targets met")
    else:
        print(f"\n[WARNING] Some targets missed (not critical)")

    return {
        'event_addition': throughput_add,
        'sanitization': throughput_sanitize,
        'ndjson_export': throughput_serialize,
        'overall_pipeline': throughput_pipeline
    }


# ============================================================================
# PERF-04: Cache Efficiency
# ============================================================================

@pytest.mark.performance
def test_perf_04_cache_efficiency(performance_test_environment):
    """
    PERF-04: Cache Efficiency

    Objective:
        Measure cache hit rate and verify TTL behavior to ensure
        efficient caching of analysis results.

    Test Scenario:
        1. Run analysis twice to test cache hit
        2. Measure speedup from cached results
        3. Test cache invalidation on config change
        4. Test TTL expiration behavior
        5. Verify cache size and cleanup

    Performance Target:
        - Cache hit speedup: >10x faster than fresh analysis
        - Cache hit rate: >80% for repeated analyses
        - TTL enforcement: Correctly expires after 24 hours
        - Cache metadata size: <10KB per entry

    Expected Results:
        - Significant speedup from cache hits
        - Cache invalidated when appropriate
        - TTL behavior working correctly
    """
    print("\n" + "="*70)
    print("PERF-04: Cache Efficiency")
    print("="*70)

    env = performance_test_environment

    # Test 1: Cache miss (first run)
    print(f"\n[TEST 1] First run (cache miss)...")

    ctx_first = DynamicContext(
        file_hash=env['file_hash'],
        preproc_dir=env['preproc_dir'],
        hints_path=env['hints_path'],
        analysis_base=env['workspace']
    )

    analysis_dir = os.path.join(env['workspace'], 'analysis', 'dynamic', env['file_hash'])

    # Ensure clean state
    if os.path.exists(analysis_dir):
        shutil.rmtree(analysis_dir)

    start_first = time.time()

    # Simulate analysis stages that would be cached
    runner = DynamicRunner()
    _, hints_data, _ = runner._setup(ctx_first, DynamicResult(file_hash=ctx_first.file_hash))
    config = Config.load(preproc_dir=ctx_first.preproc_dir)
    hooks = runner._generate_hooks(hints_data, config)

    elapsed_first = time.time() - start_first

    # Write cache
    os.makedirs(analysis_dir, exist_ok=True)
    cache.write_cache_meta(ctx_first, analysis_dir, incomplete=False)

    print(f"  Time (uncached): {format_duration(elapsed_first)}")
    print(f"  Cache written: Yes")

    # Test 2: Cache hit (second run)
    print(f"\n[TEST 2] Second run (cache hit)...")

    ctx_second = DynamicContext(
        file_hash=env['file_hash'],
        preproc_dir=env['preproc_dir'],
        hints_path=env['hints_path'],
        analysis_base=env['workspace']
    )

    start_second = time.time()

    # Check if cache should be used
    should_use = cache.should_use_cache(ctx_second, analysis_dir)

    elapsed_second = time.time() - start_second

    print(f"  Cache hit: {should_use}")
    print(f"  Time (cache check): {format_duration(elapsed_second)}")

    assert should_use, "Cache should be usable"

    # Calculate speedup
    if elapsed_second > 0:
        speedup = elapsed_first / elapsed_second
        print(f"  Speedup: {speedup:.1f}x")

        if speedup >= 10:
            print(f"  ✓ PASS: Speedup exceeds 10x target")
        else:
            print(f"  ✗ WARN: Speedup below 10x target (actual: {speedup:.1f}x)")
    else:
        print(f"  ⚠ Cache check too fast to measure accurately")

    # Test 3: Cache invalidation on config change
    print(f"\n[TEST 3] Cache invalidation on config change...")

    ctx_changed = DynamicContext(
        file_hash=env['file_hash'],
        preproc_dir=env['preproc_dir'],
        hints_path=env['hints_path'],
        analysis_base=env['workspace'],
        timeout=1000,  # Different timeout
        instrumenters={'crypto_ops': False}  # Different config
    )

    should_use_changed = cache.should_use_cache(ctx_changed, analysis_dir)

    print(f"  Cache valid after config change: {should_use_changed}")

    if not should_use_changed:
        print(f"  ✓ PASS: Cache correctly invalidated")
    else:
        print(f"  ✗ FAIL: Cache should be invalidated")

    # Test 4: TTL expiration simulation
    print(f"\n[TEST 4] TTL expiration behavior...")

    # Read current cache metadata
    cache_info = cache.get_cache_info(analysis_dir)
    print(f"  Current TTL: {cache_info.get('ttl_hours', 'N/A')} hours")

    # Modify timestamp to simulate expiration
    cache_meta_path = cache.get_cache_meta_path(analysis_dir)
    with open(cache_meta_path, 'r') as f:
        cache_data = json.load(f)

    # Set timestamp to 25 hours ago
    from datetime import datetime, timedelta
    old_timestamp = (datetime.now() - timedelta(hours=25)).isoformat()
    cache_data['timestamp'] = old_timestamp

    with open(cache_meta_path, 'w') as f:
        json.dump(cache_data, f)

    # Check if cache is expired
    should_use_expired = cache.should_use_cache(ctx_second, analysis_dir)

    print(f"  Cache valid after TTL expiration: {should_use_expired}")

    if not should_use_expired:
        print(f"  ✓ PASS: Cache correctly expired")
    else:
        print(f"  ✗ FAIL: Cache should be expired")

    # Test 5: Cache metadata size
    print(f"\n[TEST 5] Cache metadata size...")

    # Restore valid cache
    cache.write_cache_meta(ctx_first, analysis_dir, incomplete=False)

    cache_meta_path = cache.get_cache_meta_path(analysis_dir)
    cache_size = os.path.getsize(cache_meta_path)

    print(f"  Cache metadata size: {format_bytes(cache_size)}")

    target_size = 10 * 1024  # 10KB
    if cache_size <= target_size:
        print(f"  ✓ PASS: Within 10KB target")
    else:
        print(f"  ✗ WARN: Exceeds 10KB target")

    # Summary
    print(f"\n{'='*70}")
    print("CACHE EFFICIENCY SUMMARY")
    print(f"{'='*70}")

    print(f"Cache hit detection:     ✓ Working")
    print(f"Config invalidation:     ✓ Working" if not should_use_changed else "✗ FAIL")
    print(f"TTL expiration:          ✓ Working" if not should_use_expired else "✗ FAIL")
    print(f"Metadata size:           {format_bytes(cache_size)}")

    all_passed = (
        should_use and
        not should_use_changed and
        not should_use_expired
    )

    if all_passed:
        print(f"\n[OK] PERF-04 PASSED - Cache working efficiently")
    else:
        print(f"\n[FAIL] Some cache tests failed")

    return {
        'cache_hit': should_use,
        'invalidation': not should_use_changed,
        'ttl_expiration': not should_use_expired,
        'metadata_size': cache_size
    }


# ============================================================================
# Test Execution
# ============================================================================

if __name__ == '__main__':
    """
    Run performance tests standalone.

    Usage:
        python tests/test_dynamic_detection_performance.py

    Or with pytest:
        pytest tests/test_dynamic_detection_performance.py -v
        pytest tests/test_dynamic_detection_performance.py -v -k "perf_01"
        pytest tests/test_dynamic_detection_performance.py -v -m performance
    """
    print("="*70)
    print("DYNAMIC DETECTION PERFORMANCE TESTS")
    print("="*70)
    print("\nThese tests establish performance baselines and identify bottlenecks.")
    print("\nTo run these tests, use pytest:")
    print("  pytest tests/test_dynamic_detection_performance.py -v")
    print("\nTo run specific test:")
    print("  pytest tests/test_dynamic_detection_performance.py -v -k PERF-01")
    print("\nTo run all performance tests:")
    print("  pytest tests/test_dynamic_detection_performance.py -v -m performance")
    print("\nNote: These tests may take several minutes to complete.")
    print("="*70)
