# Ghidra Execution Policy

## Overview

The Ghidra execution policy intelligently determines when to run Ghidra binary analysis based on file type, size, and user configuration. This dramatically improves performance for source-code-heavy projects while maintaining comprehensive analysis for actual binaries.

## Problem Statement

Ghidra is a powerful binary analysis tool, but:

- **Cannot analyze source code** (Python, JavaScript, JSON, etc.)
- **Time-consuming** (10-minute default timeout per file)
- **Wasteful** when run on non-binary files

In blockchain projects, 99% of files are source code. Running Ghidra on all files causes:

- 50-100x slowdown
- Wasted computational resources
- Poor user experience

## Solution: Intelligent Filtering

The `ghidra_policy.py` module implements smart filtering based on:

1. **File metadata** (`is_binary` flag)
2. **MIME types** (source code vs binary)
3. **File size** (skip files > 5MB)
4. **User configuration** (override policy)

---

## Policy Modes

### `auto` (Default - Recommended)

Intelligent filtering based on file characteristics:

- ✅ **Run on:** Binary executables (ELF, PE, Mach-O, etc.)
- ❌ **Skip:** Source code (Python, JS, JSON, Solidity, etc.)
- ❌ **Skip:** Files > 5MB
- ✅ **Run on:** Unknown files marked as `is_binary=True` (conservative)

**Use when:** You want optimal performance with smart defaults

### `always`

Force Ghidra to run on **all files** regardless of type:

- ✅ **Run on:** Everything (source, binaries, all sizes)
- ⚠️ **Warning:** Very slow, most runs will fail on source files

**Use when:** You suspect binaries are misclassified and want comprehensive analysis

### `never`

Disable Ghidra entirely:

- ❌ **Skip:** All files
- ⚡ **Fast:** Instant analysis
- ⚠️ **Warning:** May miss binary-only patterns

**Use when:** You only have source code or want maximum speed

---

## Configuration

### Check Current Policy

```python
from src.auditor.detectors.static_detection import config

policy = config.get_ghidra_run_policy()
print(f"Current policy: {policy}")  # Output: 'auto', 'always', or 'never'
```

### Change Policy

```python
from src.auditor.detectors.static_detection import config

# Set to auto (smart filtering)
config.set_ghidra_run_policy('auto')

# Set to always (force on all files)
config.set_ghidra_run_policy('always')

# Set to never (disable Ghidra)
config.set_ghidra_run_policy('never')
```

Policy is persisted in: `%APPDATA%\cryptoscope\config.json` (Windows) or `~/.config/cryptoscope/config.json` (Linux/Mac)

---

## Decision Logic (Auto Mode)

```
┌─────────────────────────┐
│  File Preprocessed      │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│  Check Policy Mode      │
└────────┬────────────────┘
         │
         ├─ 'never' ──────► SKIP (user override)
         │
         ├─ 'always' ─────► RUN (user override)
         │
         ▼ 'auto'
┌─────────────────────────┐
│  Check is_binary Flag   │
└────────┬────────────────┘
         │
         ├─ False ─────────► SKIP (explicit source code)
         │
         ▼ True
┌─────────────────────────┐
│  Check MIME Type        │
└────────┬────────────────┘
         │
         ├─ Source Code ───► SKIP (Python, JS, JSON, etc.)
         │   - text/x-python
         │   - application/javascript
         │   - application/json
         │   - text/x-solidity
         │   - etc.
         │
         ├─ Known Binary ──► RUN (ELF, PE, Mach-O)
         │   - application/x-executable
         │   - application/x-elf
         │   - application/x-dosexec
         │   - application/x-mach-binary
         │   - etc.
         │
         ▼ Unknown MIME
┌─────────────────────────┐
│  Check File Size        │
└────────┬────────────────┘
         │
         ├─ > 5MB ─────────► SKIP (too large)
         │
         ▼ ≤ 5MB
┌─────────────────────────┐
│  RUN (conservative)     │
│  Unknown but binary     │
└─────────────────────────┘
```

---

## MIME Type Lists

### Source Code MIME Types (Always Skip)

```python
SOURCE_CODE_MIMES = {
    "text/x-python",          # Python
    "text/x-script.python",
    "application/javascript", # JavaScript
    "text/javascript",
    "application/json",       # JSON
    "text/json",
    "text/x-solidity",        # Solidity (smart contracts)
    "text/plain",             # Plain text
    "text/html",              # HTML
    "text/css",               # CSS
    "application/xml",        # XML
    "text/xml",
    "text/x-yaml",            # YAML
    "application/x-yaml",
    "text/markdown",          # Markdown
}
```

### Binary MIME Types (Always Run)

```python
BINARY_MIMES = {
    "application/x-executable",    # Generic executable
    "application/x-elf",           # Linux ELF
    "application/x-sharedlib",     # Shared library
    "application/x-object",        # Object file
    "application/x-dosexec",       # Windows PE
    "application/x-msdownload",    # Windows executable
    "application/x-mach-binary",   # macOS Mach-O
    "application/octet-stream",    # Generic binary
}
```

---

## Skip Markers

When Ghidra is skipped, the pipeline creates a `SKIPPED.txt` marker file explaining why:

**File:** `<analysis_dir>/ghidra-export/SKIPPED.txt`

**Example content:**

```
Ghidra analysis skipped
Reason: is_binary=False (source code, mime=text/x-python)
```

This provides transparency and helps debugging.

---

## Logging

The policy logs every decision for visibility:

```python
# Log format
2025-01-15 14:32:45 [INFO] Ghidra decision for abc123...def: should_run=False, reason=is_binary=False (source code, mime=text/x-python)
```

This helps you:

- Verify correct filtering behavior
- Debug unexpected skips/runs
- Understand pipeline performance

---

## Performance Impact

### Before (No Filtering)

- **Timeout:** 600 seconds per file
- **Source Files:** 99% of files (all timeout or fail)
- **Analysis Time:** 10 minutes × 1000 files = **~166 hours**

### After (Auto Policy)

- **Source Files:** Instant skip (0.01s per file)
- **Binary Files:** 1% of files (full Ghidra analysis)
- **Analysis Time:** 0.01s × 990 files + 600s × 10 files = **~10 seconds + 100 minutes = ~100 minutes**

**Speedup:** 166 hours → 1.7 hours = **~100x faster**

---

## Testing

### Unit Tests

```bash
python test_policy.py
```

Tests individual policy decisions for:

- Python files → SKIP
- JavaScript files → SKIP
- ELF binaries → RUN
- Windows PE → RUN
- Large files → SKIP
- Unknown binaries → RUN (conservative)

### Integration Test

```bash
python test_policy_integration.py
```

Verifies policy integration with full pipeline.

### End-to-End Test

```bash
python test_ghidra_pipeline.py
```

Confirms Ghidra still works correctly on binaries.

---

## Heuristics Compatibility

All heuristics safely handle empty `ghidra_export`:

**instruction_patterns.py:**

```python
if isinstance(ghidra_export, list) and ghidra_export:
    # Analyze disassembly
```

**signature.py:**

```python
if isinstance(ghidra_export, list) and ghidra_export:
    # Scan prototypes
```

**constants.py:**

```python
# Uses static_artifacts, not ghidra_export
```

No heuristic will crash with empty Ghidra data.

---

## Troubleshooting

### Problem: Binaries are being skipped

**Solution:** Check the file's MIME type and `is_binary` flag in `metadata.json`. If misclassified, you can:

1. Set policy to `'always'` to force analysis
2. Add the MIME type to `BINARY_MIMES` in `ghidra_policy.py`

### Problem: Too many files running Ghidra

**Solution:** Check logs to see why files are being analyzed. Common causes:

- Files marked as `is_binary=True` with unknown MIME
- MIME type not in `SOURCE_CODE_MIMES` list
- Solution: Add MIME types to skip list or use `'never'` policy

### Problem: Analysis is still slow

**Solution:**

1. Check how many binaries you actually have: `ls -lh case/preproc/*/metadata.json | grep '"is_binary": true'`
2. Consider reducing `MAX_BINARY_SIZE_BYTES` in `ghidra_policy.py`
3. Use `'never'` policy if you only have source code

---

## Future Enhancements

Potential improvements:

1. **Per-case policy:** Different policies for different cases
2. **Dynamic timeout:** Shorter timeout for smaller binaries
3. **Parallel Ghidra:** Run multiple Ghidra instances simultaneously
4. **Caching:** Reuse previous Ghidra results for unchanged files
5. **Machine learning:** Learn optimal policy from user feedback

---

## Related Files

- **Policy Logic:** `src/auditor/detectors/static_detection/ghidra_policy.py`
- **Integration:** `src/auditor/detectors/static_detection/runner.py`
- **Configuration:** `src/auditor/detectors/static_detection/config.py`
- **Tests:** `test_policy.py`, `test_policy_integration.py`
- **Ghidra Adapter:** `src/auditor/detectors/static_detection/ghidra_adapter.py`

---

## Summary

The Ghidra execution policy provides:

- ✅ **Smart filtering** based on file type
- ✅ **50-100x performance improvement** for source-heavy projects
- ✅ **User control** via configurable policies
- ✅ **Transparency** through logging and skip markers
- ✅ **Safety** - all heuristics handle empty Ghidra data
- ✅ **Flexibility** - override behavior as needed

**Default behavior:** Run Ghidra only on actual binaries, skip source code.

**Performance impact:** Near-instant analysis for 99% of blockchain projects.
