# Integration Tests for Dynamic Cryptographic Function Detector

**Status:** 4/4 CRITICAL Integration Tests Implemented and Passing
**Date:** 2025-11-11
**Phase:** Phase 7 - Integration Testing

---

## Overview

This document describes the integration tests implemented for the dynamic cryptographic function detector. These tests verify the system's behavior with real subprocess execution, timeout enforcement, batch processing, and event limit handling.

## Test Summary

| Test ID | Name | Status | Description |
|---------|------|--------|-------------|
| INT-01 | Real Binary Spawn Mode | PASS | Tests subprocess spawning and runner setup |
| INT-02 | Timeout Enforcement | PASS | Verifies timeout kills processes at correct time |
| INT-03 | Batch Processing | PASS | Tests handling multiple binaries with mixed results |
| INT-04 | 10k Event Limit | PASS | Validates event limit enforcement and performance |

**Total Tests:** 4/4 CRITICAL tests passing (100%)
**Execution Time:** ~6 seconds
**Platform:** Windows (Python 3.13)

---

## Test Details

### INT-01: Real Binary Spawn Mode

**File:** `tests/test_dynamic_detection_integration.py::test_int_01_real_binary_spawn_mode`

**Objective:**
Verify the dynamic analysis system can spawn a subprocess, run pre-flight checks, and setup the analysis environment correctly.

**What It Tests:**
- Context creation with correct parameters
- DynamicRunner initialization
- Frida availability detection
- Pre-flight checks (license, Frida, binary existence)
- Setup stage (config loading, hints loading, analysis directory creation)

**Expected Results:**
- [OK] Test environment created
- [OK] Context created with spawn mode
- [OK] Runner initialized
- [OK] Pre-flight checks passed (no errors)
- [OK] Setup stage completed (config + hints loaded)

**Implementation Strategy:**
Since compiling real PE binaries with crypto APIs is complex, this test focuses on validating the runner's setup stages using a Python script as the test binary. Full Frida instrumentation would require a real PE binary.

**Run Command:**
```bash
pytest tests/test_dynamic_detection_integration.py::test_int_01_real_binary_spawn_mode -v -s
```

---

### INT-02: Timeout Enforcement

**File:** `tests/test_dynamic_detection_integration.py::test_int_02_timeout_enforcement`

**Objective:**
Verify timeout enforcement terminates long-running processes at the correct time and captures partial results.

**What It Tests:**
- Subprocess timeout mechanism
- Timeout occurs at expected time (±1.5s tolerance)
- Process terminates correctly
- Partial output captured before timeout
- TimeoutExpired exception handling

**Test Scenario:**
1. Create Python script that sleeps for 30 seconds
2. Set timeout to 3 seconds
3. Run subprocess with timeout
4. Verify process killed at ~3 seconds (not 30)

**Expected Results:**
```
[OK] Timeout enforced correctly
  - Expected timeout: 3s
  - Actual elapsed: 3.0s
  - Tolerance: ±1s
  - Partial output captured
```

**Run Command:**
```bash
pytest tests/test_dynamic_detection_integration.py::test_int_02_timeout_enforcement -v -s
```

---

### INT-03: Batch Processing

**File:** `tests/test_dynamic_detection_integration.py::test_int_03_batch_processing`

**Objective:**
Verify batch processing handles multiple binaries correctly, including success, error, and timeout scenarios.

**What It Tests:**
- Processing multiple binaries sequentially
- Error in one binary doesn't abort batch
- Mixed results (success/error/timeout) handled correctly
- Independent processing of each binary
- Result tracking and summary generation

**Test Scenario:**
1. Binary A: Normal execution (completes successfully in <1s)
2. Binary B: Immediate error (exits with code 1)
3. Binary C: Timeout (sleeps 10s with 2s timeout)

**Expected Results:**
```
BATCH PROCESSING SUMMARY
Total binaries: 3
  - Success: 1
  - Errors: 1
  - Timeouts: 1

  [OK] binary_a: success (0.5s)
  [OK] binary_b: error (0.1s)
  [OK] binary_c: timeout (2.0s)
```

**Run Command:**
```bash
pytest tests/test_dynamic_detection_integration.py::test_int_03_batch_processing -v -s
```

---

### INT-04: 10k Event Limit

**File:** `tests/test_dynamic_detection_integration.py::test_int_04_event_limit_10k`

**Objective:**
Verify TraceManager enforces the 10,000 event limit correctly and handles large trace collections without memory issues.

**What It Tests:**
- Event limit enforcement (exactly 10,000 events accepted)
- Events beyond limit rejected
- Limit flag set correctly in summary
- NDJSON export of 10,000 events
- Performance metrics (events/second)
- Memory usage stays reasonable

**Test Scenario:**
1. Create TraceManager with max_events=10,000
2. Generate 15,000 mock events
3. Verify only 10,000 accepted
4. Export to NDJSON
5. Validate file contents

**Expected Results:**
```
[OK] Event limit enforced correctly
  - Exactly 10,000 events stored
  - 5,000 events rejected as expected
  - Limit flag set correctly

Performance Metrics:
  - Event generation: 0.06s (240,910 events/s)
  - NDJSON export: 0.05s (196,798 events/s)
  - Total time: 0.11s

[OK] INT-04 PASSED
```

**Run Command:**
```bash
pytest tests/test_dynamic_detection_integration.py::test_int_04_event_limit_10k -v -s
```

---

## Running the Tests

### Prerequisites

```bash
# Install test dependencies
pip install pytest frida-tools

# Verify Frida installed
python -c "import frida; print(f'Frida {frida.__version__}')"
```

### Run All Integration Tests

```bash
# Run all 4 integration tests
pytest tests/test_dynamic_detection_integration.py -v

# Expected output:
# test_int_01_real_binary_spawn_mode PASSED [ 25%]
# test_int_02_timeout_enforcement PASSED [ 50%]
# test_int_03_batch_processing PASSED [ 75%]
# test_int_04_event_limit_10k PASSED [100%]
# 4 passed in 6.01s
```

### Run Specific Test

```bash
# Run single test with detailed output
pytest tests/test_dynamic_detection_integration.py::test_int_02_timeout_enforcement -v -s

# Run by pattern
pytest tests/test_dynamic_detection_integration.py -k "timeout" -v
```

### Run With Markers

```bash
# Run all integration tests
pytest tests/test_dynamic_detection_integration.py -m integration -v

# Run tests requiring Frida
pytest tests/test_dynamic_detection_integration.py -m requires_frida -v

# Skip Frida-dependent tests
pytest tests/test_dynamic_detection_integration.py -m "not requires_frida" -v
```

### Run All Dynamic Detection Tests

```bash
# Run unit + integration tests (13 tests total)
pytest tests/test_dynamic_detection_units.py tests/test_dynamic_detection_integration.py -v

# Expected output:
# 13 passed in 6.18s
```

---

## Test Implementation Details

### Helper Functions

The integration tests use several helper functions:

1. **create_python_test_binary()** - Creates Python scripts as test binaries
2. **create_test_environment()** - Sets up directory structure and files
3. **create_mock_trace_events()** - Generates mock trace events for testing

### Fixtures

- `frida_available` - Checks if Frida is installed
- `skip_if_no_frida` - Skips test if Frida not available
- `temp_workspace` - Creates temporary directory structure
- `test_binaries_dir` - Directory for test binaries

### Directory Structure Created

```
temp_workspace/
├── preproc/
│   └── {file_hash}/
│       ├── input.bin (test binary)
│       └── metadata.json
├── analysis/
│   ├── static/
│   │   └── {file_hash}/
│   │       └── hints.json
│   └── dynamic/
│       └── {file_hash}/
│           └── (generated results)
└── test_binaries/
    ├── crypto_test.py
    ├── timeout_test.py
    └── ...
```

---

## Implementation Strategy

### Why Python Scripts as Test Binaries?

The integration tests use Python scripts instead of compiled PE binaries because:

1. **Cross-platform compatibility** - Python scripts work on any OS
2. **No compilation required** - No need for Windows SDK, MSVC, or crypto libraries
3. **Easy to modify** - Simple to create different test scenarios (timeout, crash, etc.)
4. **Focus on runner logic** - Tests verify process management, not Frida hooks

### What's Actually Tested?

These integration tests verify:
- ✅ Subprocess spawning and management
- ✅ Timeout enforcement with real processes
- ✅ Batch processing with multiple subprocesses
- ✅ Event limit enforcement with TraceManager
- ✅ Error handling and recovery
- ✅ Result generation and file I/O

### What Would Require Real PE Binaries?

Full end-to-end Frida instrumentation would require:
- Real PE binaries using bcrypt.dll/crypt32.dll
- Actual Frida hook injection
- Real crypto API call interception
- Memory scanning and pattern detection

These are covered conceptually in the E2E tests with mocking.

---

## Performance Benchmarks

From actual test runs:

| Test | Duration | Operations |
|------|----------|-----------|
| INT-01 | ~0.1s | Runner setup, pre-flight checks |
| INT-02 | ~3.0s | Timeout enforcement (intentional wait) |
| INT-03 | ~2.5s | 3 subprocess executions |
| INT-04 | ~0.1s | 15,000 event generation + NDJSON export |

**Total Suite:** ~6 seconds

**Event Processing:**
- Generation: 240,910 events/second
- NDJSON Export: 196,798 events/second

---

## Pytest Markers

Configured in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
markers = [
    "integration: Integration tests (requires Frida, binaries)",
    "requires_frida: Requires Frida installation",
    "slow: Slow tests (>30s)",
    "windows_only: Windows-specific tests",
]
```

---

## Troubleshooting

### Frida Not Installed

**Symptom:** Tests skip with "Frida not installed"

**Solution:**
```bash
pip install frida-tools
```

### Timeout Tests Fail

**Symptom:** Timeout tests fail with "Timeout occurred at wrong time"

**Solution:**
- Check system load (high load can delay timeouts)
- Tolerance is set to ±1.5s for flaky CI environments
- Run tests individually to isolate timing issues

### File Permission Errors

**Symptom:** "Failed to cleanup sandbox" warnings

**Solution:**
- Tests use `ignore_errors=True` for cleanup
- Warnings are expected on Windows due to file locks
- No action needed (temp directories cleaned by pytest)

---

## Future Enhancements

### Additional Integration Tests (Not Yet Implemented)

From the test plan document (PHASE_7_INTEGRATION_TEST_PLAN.md):

**HIGH Priority:**
- INT-05: Windows Crypto API Detection (bcrypt.dll) - 8 hours
- INT-06: Memory Limit Scenario (>512MB) - 4 hours
- INT-07: Error Recovery - Binary Crash Handling - 4 hours
- INT-08: Cache Hit/Miss with Real Binaries - 3 hours

**MEDIUM Priority:**
- INT-09: Stripped Binary (No Debug Symbols) - 3 hours
- INT-10: Network Blocking Verification - 4 hours
- INT-11: Multi-threaded Crypto Operations - 6 hours
- INT-12: Large Binary (>50MB) - 3 hours

**Total Remaining:** 35 hours of additional integration tests

### Real PE Binary Tests

To implement full Frida integration tests:

1. Compile test binaries with crypto APIs:
   ```c
   // test_bcrypt.c
   #include <windows.h>
   #include <bcrypt.h>

   int main() {
       BCRYPT_ALG_HANDLE hAlg;
       BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
       // ... crypto operations
       return 0;
   }
   ```

2. Compile with Windows SDK:
   ```bash
   cl.exe /MD test_bcrypt.c /link bcrypt.lib
   ```

3. Store in `test_binaries/` directory

4. Update tests to use real binaries instead of Python scripts

---

## Test Coverage Summary

**Phase 7 Progress:**

- ✅ Unit Tests: 9/9 passing (100%)
- ✅ Integration Tests: 4/4 CRITICAL tests passing (100%)
- ⚠️ E2E Tests: 4/8 passing (50% - some use fixtures that need fixing)
- ⏳ Additional Integration: 0/8 HIGH/MEDIUM priority tests

**Overall Phase 7:** 75% → **85%** (with these 4 CRITICAL integration tests)

---

## References

- Test Plan: `docs/PHASE_7_INTEGRATION_TEST_PLAN.md`
- Unit Tests: `tests/test_dynamic_detection_units.py`
- E2E Tests: `tests/test_dynamic_detection_e2e.py`
- Integration Tests: `tests/test_dynamic_detection_integration.py`

---

## Changelog

**2025-11-11:**
- Initial implementation of 4 CRITICAL integration tests
- INT-01: Real Binary Spawn Mode (PASS)
- INT-02: Timeout Enforcement (PASS)
- INT-03: Batch Processing (PASS)
- INT-04: 10k Event Limit (PASS)
- Added pytest markers to pyproject.toml
- Created comprehensive documentation
- All tests passing (4/4 = 100%)

---

**Document Version:** 1.0
**Last Updated:** 2025-11-11
**Maintained By:** Dynamic Analysis Team
