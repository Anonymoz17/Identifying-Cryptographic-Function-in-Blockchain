# Dynamic Analysis Troubleshooting Guide

**Document Version:** 1.0  
**Last Updated:** January 2025  
**Status:** Complete ✅

This guide provides comprehensive troubleshooting information for the dynamic cryptographic function detector. It covers common issues, diagnostic procedures, solutions, and best practices for debugging problems.

---

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Common Issues](#common-issues)
3. [Frida-Specific Problems](#frida-specific-problems)
4. [Performance Issues](#performance-issues)
5. [Cache Problems](#cache-problems)
6. [Sandboxing Issues](#sandboxing-issues)
7. [Trace Collection Problems](#trace-collection-problems)
8. [Integration Issues](#integration-issues)
9. [Debugging Tools](#debugging-tools)
10. [Error Reference](#error-reference)
11. [Advanced Troubleshooting](#advanced-troubleshooting)
12. [Support and Reporting](#support-and-reporting)

---

## Quick Diagnostics

### Health Check Script

Run this script to quickly diagnose common issues:

```python
# debug_dynamic_analysis.py
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from auditor.detectors.dynamic_detection import health_check

# Run health check
results = health_check.run_all_checks()

# Print results
for check_name, result in results.items():
    status = "✓" if result['passed'] else "✗"
    print(f"{status} {check_name}: {result['message']}")
```

### Quick Check Commands

```powershell
# Check Frida installation
python -c "import frida; print(f'Frida {frida.__version__}')"

# Check Python version
python --version

# Check workspace structure
Test-Path ".\analysis\dynamic"

# Check test status
pytest tests/test_dynamic_detection_e2e.py -v --tb=short
```

---

## Common Issues

### Issue 1: "Frida not installed" Error

**Symptoms:**

- Error: `ModuleNotFoundError: No module named 'frida'`
- Dynamic detection disabled in UI

**Causes:**

- Frida package not installed
- Wrong Python environment
- Version mismatch

**Solutions:**

1. **Install Frida:**

   ```powershell
   pip install frida==16.0.19 frida-tools==12.2.1
   ```

2. **Verify installation:**

   ```powershell
   python -c "import frida; print(frida.__version__)"
   ```

3. **Check Python environment:**

   ```powershell
   # Show active environment
   python -c "import sys; print(sys.prefix)"

   # List installed packages
   pip list | Select-String "frida"
   ```

4. **Reinstall if needed:**
   ```powershell
   pip uninstall frida frida-tools
   pip install frida==16.0.19 frida-tools==12.2.1
   ```

**Prevention:**

- Use `requirements.txt` for consistent environments
- Activate virtual environment before running
- Document environment setup in README

---

### Issue 2: "Binary not found" Error

**Symptoms:**

- Error: `FileNotFoundError: Binary not found at path`
- Analysis fails immediately

**Causes:**

- Incorrect preprocessing directory
- Missing input file
- Wrong file hash

**Solutions:**

1. **Verify preprocessing structure:**

   ```powershell
   # Expected structure:
   # workspace/preproc/{file_hash}/input.bin
   # workspace/preproc/{file_hash}/metadata.json

   Get-ChildItem -Path ".\workspace\preproc" -Recurse
   ```

2. **Check metadata:**

   ```python
   import json

   with open('workspace/preproc/{hash}/metadata.json') as f:
       meta = json.load(f)

   print(f"Hash: {meta['file_hash']}")
   print(f"Type: {meta['file_type']}")
   ```

3. **Regenerate preprocessing:**

   ```python
   from auditor.preproc import preprocess_file

   result = preprocess_file(
       file_path='path/to/binary.exe',
       workspace='workspace'
   )
   ```

**Prevention:**

- Always validate preprocessing before dynamic analysis
- Use consistent file hashing (SHA-256)
- Keep preprocessing and analysis directories synchronized

---

### Issue 3: "No hints available" Warning

**Symptoms:**

- Warning: `No static analysis hints found`
- Analysis runs but finds nothing

**Causes:**

- Static analysis not run
- No crypto functions detected
- Wrong hints path

**Solutions:**

1. **Run static analysis first:**

   ```python
   from auditor.detectors import StaticDetector

   detector = StaticDetector()
   hints = detector.analyze(
       file_hash='abcd1234',
       workspace='workspace'
   )
   ```

2. **Check hints file:**

   ```python
   import json

   hints_path = 'workspace/analysis/static/{hash}/hints.json'

   with open(hints_path) as f:
       hints = json.load(f)

   print(f"Found {len(hints.get('hints', []))} hints")
   ```

3. **Generate dummy hints for testing:**
   ```python
   hints = {
       'file_hash': 'test_hash',
       'schema_version': '1.0',
       'hints': [
           {
               'id': 'hint_001',
               'type': 'crypto_function',
               'name': 'BCryptEncrypt',
               'module': 'bcrypt.dll',
               'confidence': 0.85,
               'reason_tags': ['test']
           }
       ]
   }
   ```

**Prevention:**

- Always run static analysis before dynamic
- Validate hints schema
- Use pipeline mode to ensure proper ordering

---

### Issue 4: Timeout During Execution

**Symptoms:**

- Analysis times out after configured duration
- Result marked as incomplete
- No error message

**Causes:**

- Binary hangs or waits for input
- Infinite loop in target
- Timeout too short

**Solutions:**

1. **Increase timeout:**

   ```python
   ctx = DynamicContext(
       file_hash='hash',
       preproc_dir='path',
       hints_path='path',
       analysis_base='path',
       timeout=30  # Increase from default 10s
   )
   ```

2. **Use headless mode:**

   ```python
   # Ensure process doesn't wait for user input
   ctx = DynamicContext(
       # ...
       instrumenters={'crypto_ops': True}
   )
   ```

3. **Check for blocking calls:**

   - Look for `MessageBox`, `scanf`, `getchar` in binary
   - Use static analysis to identify interactive functions
   - Consider patching binary to skip input

4. **Monitor execution:**

   ```python
   # Enable detailed logging
   import logging
   logging.basicConfig(level=logging.DEBUG)

   runner = DynamicRunner()
   result = runner.run_analysis(ctx)
   ```

**Prevention:**

- Set appropriate timeouts for binary complexity
- Test with known-good samples first
- Document timeout requirements

---

## Frida-Specific Problems

### Issue: Frida Server Version Mismatch

**Symptoms:**

- Error: `Unable to inject library: version mismatch`
- Analysis fails during spawn

**Causes:**

- Frida Python package and server versions differ
- Old server cached

**Solutions:**

1. **Check versions:**

   ```powershell
   # Python package
   python -c "import frida; print(frida.__version__)"

   # Server (if using remote)
   frida-ps --version
   ```

2. **Update both:**

   ```powershell
   pip install frida==16.0.19 frida-tools==12.2.1 --upgrade
   ```

3. **Clear Frida cache:**
   ```powershell
   Remove-Item -Path "$env:TEMP\frida-*" -Recurse -Force
   ```

---

### Issue: Process Spawn Fails

**Symptoms:**

- Error: `Failed to spawn: access denied`
- Error: `Unable to spawn: file not found`

**Causes:**

- Insufficient permissions
- Antivirus blocking
- Wrong architecture (x86 vs x64)

**Solutions:**

1. **Run as administrator:**

   ```powershell
   # Right-click PowerShell → Run as Administrator
   python app.py
   ```

2. **Check antivirus:**

   - Add workspace to exclusions
   - Temporarily disable real-time protection
   - Whitelist Frida components

3. **Verify architecture:**

   ```python
   import pefile

   pe = pefile.PE('binary.exe')
   print(f"Arch: {pe.FILE_HEADER.Machine}")
   # IMAGE_FILE_MACHINE_I386 = x86
   # IMAGE_FILE_MACHINE_AMD64 = x64
   ```

4. **Use attach mode instead:**
   ```python
   # Start process manually, then attach
   ctx = DynamicContext(
       # ...
       spawn_mode=False
   )
   ```

---

### Issue: Script Injection Fails

**Symptoms:**

- Error: `Failed to load script: syntax error`
- No hooks installed

**Causes:**

- Invalid JavaScript syntax
- Missing Frida API calls
- Wrong API version

**Solutions:**

1. **Validate script syntax:**

   ```javascript
   // Test script manually
   console.log("Script loaded");
   ```

2. **Check Frida API compatibility:**

   ```python
   from auditor.detectors.dynamic_detection import frida_script_generator

   # Generate and validate script
   script = frida_script_generator.generate_crypto_hooks(['BCryptEncrypt'])
   print(script)
   ```

3. **Enable script debugging:**
   ```python
   # Add to script
   console.log = function(msg) {
       send({type: 'log', payload: msg});
   };
   ```

---

## Performance Issues

### Issue: Slow Trace Collection

**Symptoms:**

- Analysis takes minutes to complete
- Thousands of events collected
- System becomes unresponsive

**Causes:**

- Too many hook points
- No event limits
- Large data collection

**Solutions:**

1. **Set event limits:**

   ```python
   ctx = DynamicContext(
       # ...
       max_events=10000,  # Limit total events
       max_crypto_calls=5000  # Limit crypto calls
   )
   ```

2. **Reduce hook coverage:**

   ```python
   # Only instrument high-confidence hints
   hints_filtered = [
       h for h in hints['hints']
       if h['confidence'] > 0.8
   ]
   ```

3. **Use targeted instrumentation:**

   ```python
   ctx = DynamicContext(
       # ...
       instrumenters={
           'crypto_ops': True,
           'crypto_api': False,  # Disable if not needed
           'crypto_imports': False
       }
   )
   ```

4. **Monitor event rate:**
   ```python
   # Check trace manager stats
   mgr = trace_manager.TraceManager()
   print(f"Events: {mgr.get_event_count()}")
   print(f"Rate: {mgr.get_event_count() / elapsed:.0f} events/s")
   ```

**Prevention:**

- Always set event limits
- Start with conservative limits
- Profile before full analysis

---

### Issue: High Memory Usage

**Symptoms:**

- Python process uses >2GB RAM
- System slows down
- Out of memory errors

**Causes:**

- Too many events stored
- Large trace payloads
- Memory leaks

**Solutions:**

1. **Reduce event count:**

   ```python
   ctx = DynamicContext(
       # ...
       max_events=5000,  # Lower limit
       max_size_mb=100  # Memory cap
   )
   ```

2. **Enable streaming mode:**

   ```python
   # Write events to disk immediately
   mgr = trace_manager.TraceManager(
       stream_to_disk=True,
       stream_path='temp_traces.ndjson'
   )
   ```

3. **Limit payload sizes:**

   ```python
   # Truncate large arguments
   ctx = DynamicContext(
       # ...
       max_arg_size=1024  # 1KB per argument
   )
   ```

4. **Monitor memory:**

   ```python
   import tracemalloc

   tracemalloc.start()
   # Run analysis
   current, peak = tracemalloc.get_traced_memory()
   print(f"Peak memory: {peak / 1024 / 1024:.1f} MB")
   ```

**Prevention:**

- Set memory limits before analysis
- Monitor during long runs
- Use performance tests to establish baselines

---

## Cache Problems

### Issue: Cache Not Working

**Symptoms:**

- Analysis runs every time
- No speedup from cache
- Cache metadata missing

**Causes:**

- Cache disabled
- Config changes invalidate cache
- TTL expired

**Solutions:**

1. **Verify cache is enabled:**

   ```python
   from auditor.detectors.dynamic_detection import Config

   config = Config.load(preproc_dir='path')
   print(f"Cache enabled: {config.cache_enabled}")
   print(f"TTL: {config.cache_ttl_hours} hours")
   ```

2. **Check cache metadata:**

   ```python
   from auditor.detectors.dynamic_detection import cache

   cache_info = cache.get_cache_info(analysis_dir)
   print(f"Cached: {cache_info.get('cached', False)}")
   print(f"Timestamp: {cache_info.get('timestamp', 'N/A')}")
   ```

3. **Force cache refresh:**

   ```python
   # Delete cache metadata
   import os
   cache_path = os.path.join(analysis_dir, '.cache_meta.json')
   if os.path.exists(cache_path):
       os.remove(cache_path)
   ```

4. **Check TTL:**

   ```python
   from datetime import datetime

   # Check if cache is expired
   cached_time = datetime.fromisoformat(cache_info['timestamp'])
   age_hours = (datetime.now() - cached_time).total_seconds() / 3600

   print(f"Cache age: {age_hours:.1f} hours")
   print(f"TTL: {cache_info.get('ttl_hours', 24)} hours")
   ```

**Prevention:**

- Use consistent configurations
- Document config changes that invalidate cache
- Monitor cache hit rate

---

### Issue: Cache Corruption

**Symptoms:**

- Error: `Invalid cache metadata`
- JSON decode errors
- Inconsistent results

**Causes:**

- Interrupted write
- Disk full
- Concurrent access

**Solutions:**

1. **Validate cache file:**

   ```python
   import json

   try:
       with open('.cache_meta.json') as f:
           data = json.load(f)
       print("✓ Cache valid")
   except json.JSONDecodeError as e:
       print(f"✗ Cache corrupted: {e}")
   ```

2. **Rebuild cache:**

   ```python
   # Remove corrupted cache
   import shutil
   shutil.rmtree(analysis_dir, ignore_errors=True)

   # Re-run analysis
   runner = DynamicRunner()
   result = runner.run_analysis(ctx)
   ```

3. **Use atomic writes:**

   ```python
   # Write to temp file, then rename
   import tempfile, shutil

   with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
       json.dump(data, tmp)
       tmp_path = tmp.name

   shutil.move(tmp_path, cache_path)
   ```

**Prevention:**

- Avoid concurrent writes to same cache
- Ensure adequate disk space
- Use file locking for multi-process scenarios

---

## Sandboxing Issues

### Issue: Sandbox Creation Fails

**Symptoms:**

- Error: `Failed to create sandbox directory`
- Permission denied errors

**Causes:**

- Insufficient permissions
- Disk full
- Path too long (Windows)

**Solutions:**

1. **Check permissions:**

   ```powershell
   # Test write access
   New-Item -Path ".\workspace\sandbox\test" -ItemType Directory
   Remove-Item -Path ".\workspace\sandbox\test"
   ```

2. **Free disk space:**

   ```powershell
   # Check available space
   Get-PSDrive C | Select-Object Used,Free
   ```

3. **Shorten paths:**

   ```python
   # Use shorter base path
   analysis_base = 'C:\\work'  # Instead of long path
   ```

4. **Manual cleanup:**
   ```powershell
   # Remove old sandboxes
   Get-ChildItem -Path ".\workspace\sandbox" |
       Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-7)} |
       Remove-Item -Recurse -Force
   ```

**Prevention:**

- Regular cleanup of old sandboxes
- Monitor disk usage
- Use short workspace paths

---

### Issue: Binary Copy Fails

**Symptoms:**

- Error: `Failed to copy binary to sandbox`
- Analysis incomplete

**Causes:**

- Large binary size
- Disk full
- File in use

**Solutions:**

1. **Check binary size:**

   ```python
   import os
   size_mb = os.path.getsize('input.bin') / 1024 / 1024
   print(f"Binary size: {size_mb:.1f} MB")
   ```

2. **Use hard links instead:**

   ```python
   # Modify sandbox setup to use links
   import os
   os.link(source, destination)  # Instead of shutil.copy2
   ```

3. **Close open handles:**
   ```powershell
   # Check if file is in use
   Get-Process | Where-Object {$_.MainWindowTitle -like "*binary.exe*"}
   ```

**Prevention:**

- Avoid unnecessary copies
- Use symbolic links when possible
- Implement cleanup after analysis

---

## Trace Collection Problems

### Issue: No Events Collected

**Symptoms:**

- Analysis completes but no traces
- Event count is 0
- Empty NDJSON file

**Causes:**

- No hooks installed
- Functions not called
- Script errors

**Solutions:**

1. **Verify hooks were generated:**

   ```python
   from auditor.detectors.dynamic_detection import frida_script_generator

   hooks = frida_script_generator.generate_crypto_hooks(['BCryptEncrypt'])
   print(f"Generated {len(hooks)} hooks")
   print(hooks)
   ```

2. **Check if functions are called:**

   ```python
   # Add entry point hook to verify execution
   script = """
   console.log("Script loaded");

   Interceptor.attach(Module.getExportByName(null, 'main'), {
       onEnter: function(args) {
           console.log("main() called");
       }
   });
   """
   ```

3. **Enable verbose logging:**

   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)

   # Run analysis with debug output
   runner = DynamicRunner()
   result = runner.run_analysis(ctx)
   ```

4. **Test with known sample:**
   ```python
   # Use test binary with known crypto calls
   ctx = DynamicContext(
       file_hash='test_crypto_hash',
       # ...
   )
   ```

**Prevention:**

- Validate hooks before execution
- Test with samples known to use crypto
- Use static analysis to confirm function presence

---

### Issue: Malformed Events

**Symptoms:**

- Error: `Invalid event format`
- Sanitization failures
- Missing required fields

**Causes:**

- Script generates bad data
- Type conversion errors
- Incomplete events

**Solutions:**

1. **Validate event schema:**

   ```python
   from auditor.detectors.dynamic_detection import trace_schemas

   # Check event against schema
   is_valid, errors = trace_schemas.validate_event(event)
   if not is_valid:
       print(f"Validation errors: {errors}")
   ```

2. **Add schema validation to script:**

   ```javascript
   // In Frida script
   function sendEvent(event) {
     // Validate required fields
     if (!event.type || !event.function || !event.module) {
       console.error("Invalid event:", JSON.stringify(event));
       return;
     }
     send(event);
   }
   ```

3. **Check type conversions:**
   ```javascript
   // Ensure proper types
   const event = {
     type: String(eventType),
     function: String(funcName),
     module: String(moduleName),
     timestamp: Number(Date.now()),
   };
   ```

**Prevention:**

- Use schema validation in development
- Add type checks to script generation
- Test with various event types

---

## Integration Issues

### Issue: UI Not Showing Results

**Symptoms:**

- Analysis completes but UI shows nothing
- "No results" message
- Missing trace data

**Causes:**

- Results not in expected format
- File paths incorrect
- UI cache outdated

**Solutions:**

1. **Verify result file:**

   ```python
   import json

   result_path = 'workspace/analysis/dynamic/{hash}/results.json'
   with open(result_path) as f:
       results = json.load(f)

   print(f"Schema version: {results.get('schema_version')}")
   print(f"Trace count: {len(results.get('traces', []))}")
   ```

2. **Check UI integration:**

   ```python
   from src.pages.detectors import load_dynamic_results

   results = load_dynamic_results(file_hash='hash', workspace='workspace')
   print(f"Loaded: {results is not None}")
   ```

3. **Refresh UI cache:**

   ```python
   # In Streamlit app
   import streamlit as st
   st.cache_data.clear()
   ```

4. **Check file paths:**

   ```python
   # Verify paths used by UI
   from src.auditor.detectors.dynamic_detection import results_packager

   paths = results_packager.get_result_paths(file_hash, workspace)
   for path in paths.values():
       print(f"{path}: {os.path.exists(path)}")
   ```

**Prevention:**

- Use schema validation for all results
- Test UI integration after changes
- Document expected file structure

---

### Issue: Pipeline Ordering Problems

**Symptoms:**

- Dynamic analysis runs before static
- Missing dependencies
- Cache issues

**Causes:**

- Manual execution out of order
- Pipeline configuration wrong
- State not tracked

**Solutions:**

1. **Use pipeline orchestration:**

   ```python
   from auditor.pipeline import AnalysisPipeline

   pipeline = AnalysisPipeline(workspace='workspace')
   results = pipeline.run_full_analysis(file_hash='hash')
   ```

2. **Check prerequisites:**

   ```python
   from auditor.detectors.dynamic_detection import preflight

   checks = preflight.check_prerequisites(ctx)
   for check, passed in checks.items():
       status = "✓" if passed else "✗"
       print(f"{status} {check}")
   ```

3. **Force correct order:**

   ```python
   # Run static first
   static_result = static_detector.analyze(file_hash)

   # Then dynamic (uses static hints)
   dynamic_result = dynamic_runner.run_analysis(ctx)
   ```

**Prevention:**

- Always use pipeline for full analysis
- Document execution order
- Add dependency checks to stages

---

## Debugging Tools

### Tool 1: Trace Viewer

View and analyze collected traces:

```python
# view_traces.py
import json
import sys
from pathlib import Path

def view_traces(ndjson_path):
    """View traces from NDJSON file."""
    with open(ndjson_path) as f:
        events = [json.loads(line) for line in f]

    print(f"Total events: {len(events)}")

    # Group by type
    by_type = {}
    for event in events:
        event_type = event.get('type', 'unknown')
        by_type[event_type] = by_type.get(event_type, 0) + 1

    print("\nEvents by type:")
    for event_type, count in sorted(by_type.items()):
        print(f"  {event_type}: {count}")

    # Group by function
    by_func = {}
    for event in events:
        func = event.get('function', 'unknown')
        by_func[func] = by_func.get(func, 0) + 1

    print("\nEvents by function:")
    for func, count in sorted(by_func.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {func}: {count}")

    # Show first few events
    print("\nFirst 3 events:")
    for i, event in enumerate(events[:3], 1):
        print(f"\n  Event {i}:")
        print(f"    Type: {event.get('type')}")
        print(f"    Function: {event.get('function')}")
        print(f"    Module: {event.get('module')}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python view_traces.py <traces.ndjson>")
        sys.exit(1)

    view_traces(sys.argv[1])
```

---

### Tool 2: Config Validator

Validate configuration files:

```python
# validate_config.py
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'src'))

from auditor.detectors.dynamic_detection import Config

def validate_config(preproc_dir):
    """Validate dynamic analysis config."""
    try:
        config = Config.load(preproc_dir=preproc_dir)

        print("✓ Config loaded successfully")
        print(f"\nSettings:")
        print(f"  Timeout: {config.timeout}s")
        print(f"  Max events: {config.max_events:,}")
        print(f"  Max crypto calls: {config.max_crypto_calls:,}")
        print(f"  Cache enabled: {config.cache_enabled}")
        print(f"  Cache TTL: {config.cache_ttl_hours}h")

        print(f"\nInstrumenters:")
        for name, enabled in config.instrumenters.items():
            status = "✓" if enabled else "✗"
            print(f"  {status} {name}")

        return True

    except Exception as e:
        print(f"✗ Config validation failed: {e}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python validate_config.py <preproc_dir>")
        sys.exit(1)

    validate_config(sys.argv[1])
```

---

### Tool 3: Cache Inspector

Inspect cache status:

```python
# inspect_cache.py
import json
import sys
from pathlib import Path
from datetime import datetime

def inspect_cache(analysis_dir):
    """Inspect cache metadata."""
    cache_path = Path(analysis_dir) / '.cache_meta.json'

    if not cache_path.exists():
        print("✗ No cache found")
        return

    with open(cache_path) as f:
        cache_data = json.load(f)

    print("✓ Cache found")
    print(f"\nMetadata:")
    print(f"  File hash: {cache_data.get('file_hash')}")
    print(f"  Timestamp: {cache_data.get('timestamp')}")
    print(f"  TTL: {cache_data.get('ttl_hours')}h")
    print(f"  Incomplete: {cache_data.get('incomplete', False)}")

    # Calculate age
    cached_time = datetime.fromisoformat(cache_data['timestamp'])
    age = datetime.now() - cached_time
    age_hours = age.total_seconds() / 3600

    print(f"\nCache age: {age_hours:.1f} hours")

    # Check if expired
    ttl = cache_data.get('ttl_hours', 24)
    if age_hours > ttl:
        print(f"✗ Cache EXPIRED (TTL: {ttl}h)")
    else:
        print(f"✓ Cache VALID ({ttl - age_hours:.1f}h remaining)")

    # Show config hash
    if 'config_hash' in cache_data:
        print(f"\nConfig hash: {cache_data['config_hash']}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python inspect_cache.py <analysis_dir>")
        sys.exit(1)

    inspect_cache(sys.argv[1])
```

---

### Tool 4: Performance Profiler

Profile analysis performance:

```python
# profile_analysis.py
import time
import tracemalloc
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'src'))

from auditor.detectors.dynamic_detection import DynamicRunner, DynamicContext

def profile_analysis(file_hash, workspace):
    """Profile analysis performance."""
    print("Starting performance profiling...")

    ctx = DynamicContext(
        file_hash=file_hash,
        preproc_dir=f'{workspace}/preproc/{file_hash}',
        hints_path=f'{workspace}/analysis/static/{file_hash}/hints.json',
        analysis_base=workspace
    )

    runner = DynamicRunner()

    # Start profiling
    tracemalloc.start()
    start_time = time.time()

    try:
        result = runner.run_analysis(ctx)

        # Get stats
        elapsed = time.time() - start_time
        current, peak = tracemalloc.get_traced_memory()

        print(f"\n{'='*60}")
        print("PERFORMANCE PROFILE")
        print(f"{'='*60}")
        print(f"Execution time: {elapsed:.2f}s")
        print(f"Peak memory: {peak / 1024 / 1024:.1f} MB")
        print(f"Events collected: {result.metadata.get('total_events', 0):,}")

        if elapsed > 0:
            throughput = result.metadata.get('total_events', 0) / elapsed
            print(f"Throughput: {throughput:.0f} events/s")

        print(f"\nResult status: {result.status}")
        print(f"Incomplete: {result.incomplete}")

        return result

    finally:
        tracemalloc.stop()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python profile_analysis.py <file_hash> <workspace>")
        sys.exit(1)

    profile_analysis(sys.argv[1], sys.argv[2])
```

---

## Error Reference

### Error Codes

| Code   | Error                    | Cause                    | Solution                              |
| ------ | ------------------------ | ------------------------ | ------------------------------------- |
| DD-001 | `FridaNotInstalled`      | Frida package missing    | Install: `pip install frida==16.0.19` |
| DD-002 | `BinaryNotFound`         | Input file missing       | Check preprocessing structure         |
| DD-003 | `InvalidConfig`          | Config validation failed | Validate config.json schema           |
| DD-004 | `HintsNotFound`          | Static analysis not run  | Run static detector first             |
| DD-005 | `TimeoutExceeded`        | Analysis timed out       | Increase timeout or check binary      |
| DD-006 | `SpawnFailed`            | Cannot spawn process     | Check permissions, antivirus          |
| DD-007 | `ScriptInjectionFailed`  | Frida script error       | Validate script syntax                |
| DD-008 | `TraceCollectionFailed`  | Event collection error   | Check event limits, memory            |
| DD-009 | `SanitizationFailed`     | Invalid event format     | Validate event schema                 |
| DD-010 | `CacheCorrupted`         | Invalid cache metadata   | Delete and regenerate cache           |
| DD-011 | `SandboxCreationFailed`  | Cannot create sandbox    | Check permissions, disk space         |
| DD-012 | `ResultsPackagingFailed` | Cannot write results     | Check disk space, permissions         |

---

### Common Error Messages

**"Frida is not installed or unavailable"**

- Install Frida: `pip install frida==16.0.19`
- Verify: `python -c "import frida; print(frida.__version__)"`

**"Binary file not found at path"**

- Check preprocessing: `ls workspace/preproc/{hash}/input.bin`
- Verify file hash matches

**"No static analysis hints available"**

- Run static analysis first
- Check hints.json exists and is valid

**"Analysis timed out after X seconds"**

- Increase timeout: `ctx = DynamicContext(..., timeout=30)`
- Check if binary hangs or waits for input

**"Failed to spawn process: access denied"**

- Run as administrator
- Check antivirus settings
- Add workspace to exclusions

**"Event limit reached (X events)"**

- Increase limit: `ctx = DynamicContext(..., max_events=20000)`
- Or reduce hook coverage

**"Cache metadata is invalid or corrupted"**

- Delete cache: `rm analysis/dynamic/{hash}/.cache_meta.json`
- Re-run analysis

---

## Advanced Troubleshooting

### Debugging Frida Scripts

Enable verbose Frida logging:

```python
import frida
import sys

# Enable Frida debug output
frida.set_log_level('debug')

# Create session with debug
session = device.attach(pid)
session.on('detached', lambda reason: print(f"Detached: {reason}"))

# Load script with error handling
script = session.create_script(script_source)

def on_message(message, data):
    if message['type'] == 'error':
        print(f"Error: {message}")
        print(f"Stack: {message.get('stack')}")
    elif message['type'] == 'send':
        print(f"Message: {message['payload']}")
    else:
        print(f"Unknown: {message}")

script.on('message', on_message)
script.load()
```

---

### Analyzing Failed Traces

When trace collection fails, analyze partial data:

```python
import json

# Load partial NDJSON
events = []
with open('traces.ndjson') as f:
    for line_no, line in enumerate(f, 1):
        try:
            event = json.loads(line)
            events.append(event)
        except json.JSONDecodeError as e:
            print(f"Line {line_no} failed: {e}")
            print(f"Content: {line[:100]}")

print(f"Recovered {len(events)} events from partial file")
```

---

### Monitoring Live Analysis

Monitor analysis in real-time:

```python
import threading
import time

def monitor_progress(trace_mgr, interval=1):
    """Monitor trace collection progress."""
    last_count = 0

    while not trace_mgr.is_complete():
        current_count = trace_mgr.get_event_count()
        rate = (current_count - last_count) / interval

        print(f"\rEvents: {current_count:,} | Rate: {rate:.0f}/s", end='')

        last_count = current_count
        time.sleep(interval)

    print(f"\nComplete! Total: {trace_mgr.get_event_count():,}")

# Start monitoring in background
monitor_thread = threading.Thread(target=monitor_progress, args=(mgr,))
monitor_thread.daemon = True
monitor_thread.start()

# Run analysis
result = runner.run_analysis(ctx)
```

---

### Memory Leak Detection

Detect memory leaks:

```python
import gc
import tracemalloc

# Take snapshot before
tracemalloc.start()
snapshot1 = tracemalloc.take_snapshot()

# Run analysis
result = runner.run_analysis(ctx)

# Force garbage collection
gc.collect()

# Take snapshot after
snapshot2 = tracemalloc.take_snapshot()

# Compare snapshots
top_stats = snapshot2.compare_to(snapshot1, 'lineno')

print("Top 10 memory differences:")
for stat in top_stats[:10]:
    print(f"{stat}")
```

---

## Support and Reporting

### Before Reporting Issues

1. **Run diagnostics:**

   ```powershell
   python debug_dynamic_analysis.py
   ```

2. **Check logs:**

   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG, filename='debug.log')
   ```

3. **Reproduce with minimal example:**
   - Use test binaries
   - Simplify configuration
   - Document steps

---

### Information to Include

When reporting issues, include:

1. **Environment:**

   - OS version
   - Python version
   - Frida version
   - Package versions (`pip list`)

2. **Configuration:**

   - config.json contents
   - Context parameters
   - Timeout and limits

3. **Error details:**

   - Full error message
   - Stack trace
   - Debug logs

4. **Reproduction:**
   - Steps to reproduce
   - Sample binary (if possible)
   - Expected vs actual behavior

---

### Contact

- **GitHub Issues:** [Project Issues Page]
- **Email:** [Support Email]
- **Documentation:** [Online Docs]

---

## Appendix

### A. Test Commands

```powershell
# Run all tests
pytest tests/test_dynamic_detection_*.py -v

# Run specific test suite
pytest tests/test_dynamic_detection_e2e.py -v
pytest tests/test_dynamic_detection_units.py -v
pytest tests/test_dynamic_detection_integration.py -v
pytest tests/test_dynamic_detection_edge_cases.py -v
pytest tests/test_dynamic_detection_performance.py -v

# Run with coverage
pytest tests/test_dynamic_detection_*.py --cov=src/auditor/detectors/dynamic_detection

# Run specific test
pytest tests/test_dynamic_detection_e2e.py::test_e2e_01_basic_workflow -v
```

---

### B. Useful PowerShell Commands

```powershell
# Check Frida installation
python -c "import frida; print(frida.__version__)"

# List installed packages
pip list | Select-String "frida"

# Check workspace structure
Get-ChildItem -Path ".\workspace" -Recurse -Depth 3

# Find large files
Get-ChildItem -Path ".\workspace" -Recurse |
    Where-Object {$_.Length -gt 10MB} |
    Select-Object FullName, @{Name="SizeMB";Expression={$_.Length/1MB}}

# Clean old sandboxes
Get-ChildItem -Path ".\workspace\sandbox" |
    Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-7)} |
    Remove-Item -Recurse -Force

# Monitor process
Get-Process python | Select-Object CPU, WS, PM
```

---

### C. Configuration Templates

**Minimal config.json:**

```json
{
  "timeout": 10,
  "max_events": 10000,
  "max_crypto_calls": 5000,
  "cache_enabled": true,
  "cache_ttl_hours": 24,
  "instrumenters": {
    "crypto_ops": true,
    "crypto_api": true,
    "crypto_imports": false
  }
}
```

**Performance config.json:**

```json
{
  "timeout": 30,
  "max_events": 50000,
  "max_crypto_calls": 25000,
  "cache_enabled": true,
  "cache_ttl_hours": 72,
  "instrumenters": {
    "crypto_ops": true,
    "crypto_api": true,
    "crypto_imports": true
  },
  "max_arg_size": 2048,
  "stream_to_disk": false
}
```

**Debugging config.json:**

```json
{
  "timeout": 60,
  "max_events": 1000,
  "max_crypto_calls": 500,
  "cache_enabled": false,
  "instrumenters": {
    "crypto_ops": true,
    "crypto_api": false,
    "crypto_imports": false
  },
  "verbose": true,
  "debug_mode": true
}
```

---

### D. Schema References

**Event Schema:**

```json
{
  "type": "crypto_call",
  "function": "BCryptEncrypt",
  "module": "bcrypt.dll",
  "timestamp": 1234567890,
  "args_hashes": {
    "arg0": "hash_value",
    "arg1": "hash_value"
  },
  "return_hash": "hash_value"
}
```

**Result Schema:**

```json
{
  "file_hash": "abc123...",
  "schema_version": "1.0",
  "status": "success",
  "incomplete": false,
  "timestamp": "2025-01-15T10:30:00",
  "metadata": {
    "execution_time": 5.23,
    "total_events": 1234,
    "crypto_calls": 567
  },
  "summary": {...},
  "traces": [...]
}
```

---

**End of Troubleshooting Guide**
