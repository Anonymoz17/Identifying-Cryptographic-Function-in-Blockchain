# Static Detection Quick Start Guide

Complete setup and usage guide for the static detection pipeline.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Setup & Validation](#setup--validation)
- [Basic Usage](#basic-usage)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required

- **Python 3.10-3.12** (3.11 recommended)
- **Operating System**: Windows, macOS, or Linux
- **jsonschema** package (installed via requirements)

### Optional (for full features)

- **Ghidra 10.x+** (for binary analysis)
- **tree-sitter** (for AST analysis)
- **capstone** (for disassembly)
- **yara-python** (for YARA rules)

---

## Installation

### 1. Install Python Dependencies

```powershell
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1  # Windows
# source .venv/bin/activate  # Linux/Mac

# Install requirements
pip install -r requirements.txt

# For development with optional features
pip install -r requirements-dev.txt
```

### 2. Verify Installation

```powershell
python -m src.auditor.detectors.static_detection.setup check
```

This will show:

- ✅ Python version
- ✅ Required packages
- ✅ Workspace structure
- ✅ Config file status
- ✅ Ghidra setup (if applicable)
- ✅ Ghidra policy

---

## Setup & Validation

### Run Setup Wizard

For interactive Ghidra configuration:

```powershell
python -m src.auditor.detectors.static_detection.setup wizard
```

The wizard will guide you through:

1. Checking current configuration
2. Choosing setup method (env var, installer, manual, or skip)
3. Verifying Ghidra executable
4. Setting execution policy

### Setup Options

#### Option 1: Environment Variable (Recommended)

```powershell
# Set environment variable
[System.Environment]::SetEnvironmentVariable('GHIDRA_INSTALL_DIR', 'C:\ghidra_10.1.5', 'User')

# Restart terminal, then verify
python -m src.auditor.detectors.static_detection.setup check
```

#### Option 2: Automatic Installer

```powershell
# Use PowerShell installer
powershell -File .\installation\install-ghidra.ps1 -ArchivePath "path\to\ghidra_10.1.5.zip" -Version 10.1.5 -Sha256 <checksum>

# Verify installation
python -m src.auditor.detectors.static_detection.setup check
```

See `installation/README.md` for detailed installer documentation.

#### Option 3: Manual Configuration

```python
from src.auditor.detectors.static_detection import config

# Set Ghidra install directory
config.set_ghidra_install_dir("C:\\ghidra_10.1.5")
```

#### Option 4: Source-Only Mode (No Ghidra)

```python
from src.auditor.detectors.static_detection import config

# Disable Ghidra entirely (fastest)
config.set_ghidra_run_policy('never')
```

---

## Basic Usage

### Python API

```python
from src.auditor.detectors.static_detection import StaticRunner
from src.auditor.detectors.static_detection.context import RunContext, ToolVersions

# Create runner
runner = StaticRunner()

# Setup context
ctx = RunContext(
    file_hash="abc123...",              # SHA256 hash of file
    preproc_dir="/path/to/case/preproc",  # Preprocessed data location
    analysis_base="/path/to/case",       # Output directory
    profile="quick",                     # 'quick' or 'full'
    force=False,                         # Skip cache?
    tool_versions=ToolVersions()
)

# Run analysis
result = runner.run(ctx)

# Check results
if result.errors:
    print(f"Errors: {result.errors}")
else:
    print(f"Results: {result.static_results_path}")
    print(f"Hints: {result.hints_path}")
    print(f"Cached: {result.cached}")
```

### Directory Structure

Expected input structure:

```
case/
├── preproc/
│   └── <file_hash>/
│       ├── input.bin          # Preprocessed binary/source
│       └── metadata.json      # File metadata
└── analysis/
    └── static/
        └── <file_hash>/
            ├── static_results.json   # Main results
            ├── hints.json           # Detection hints
            ├── hints-public.json    # Redacted hints
            ├── ghidra-export/       # Ghidra functions (if run)
            └── preproc/             # Static artifacts
```

---

## Configuration

### Ghidra Execution Policy

The pipeline supports three execution policies:

#### `auto` (Default - Recommended)

Smart filtering based on file type:

- ✅ Run on binary executables (ELF, PE, Mach-O)
- ❌ Skip source code (Python, JavaScript, JSON, Solidity)
- ❌ Skip files > 5MB

```python
from src.auditor.detectors.static_detection import config
config.set_ghidra_run_policy('auto')
```

**Best for:** Mixed projects with both source and binaries

#### `always`

Force Ghidra on all files (slow):

- ✅ Run on everything
- ⚠️ Warning: Will timeout on source files

```python
config.set_ghidra_run_policy('always')
```

**Best for:** Binary-only projects, debugging misclassifications

#### `never`

Skip Ghidra entirely (fastest):

- ❌ Skip all Ghidra analysis
- ⚡ Near-instant processing

```python
config.set_ghidra_run_policy('never')
```

**Best for:** Source-code-only projects (blockchain smart contracts, Python/JS tools)

### Check Current Policy

```powershell
python -m src.auditor.detectors.static_detection.setup policy
```

Or in Python:

```python
from src.auditor.detectors.static_detection import config
print(config.get_ghidra_run_policy())
```

### Advanced Options

#### Custom Ghidra Timeout

```python
ctx = RunContext(
    # ... other params ...
    ghidra_options={
        'timeout': 1200,  # 20 minutes instead of default 10
    }
)
```

#### Force Re-analysis (Skip Cache)

```python
ctx = RunContext(
    # ... other params ...
    force=True,  # Ignore cached results
)
```

#### Analysis Profiles

- **`quick`**: Fast analysis with basic heuristics
- **`full`**: Comprehensive analysis (slower)

```python
ctx = RunContext(
    # ... other params ...
    profile='full',  # or 'quick'
)
```

---

## Troubleshooting

### Common Issues

#### 1. "Ghidra not configured"

**Error:**

```
❌ Ghidra Setup: Ghidra not configured (run setup or set GHIDRA_INSTALL_DIR)
```

**Solutions:**

```powershell
# Option A: Run setup wizard
python -m src.auditor.detectors.static_detection.setup wizard

# Option B: Set environment variable
$env:GHIDRA_INSTALL_DIR = "C:\ghidra_10.1.5"

# Option C: Skip Ghidra (source-only mode)
python -c "from src.auditor.detectors.static_detection import config; config.set_ghidra_run_policy('never')"
```

#### 2. "Ghidra analysis timed out"

**Error:**

```
TimeoutError: Ghidra analysis timed out after 600 seconds
```

**Solutions:**

1. **Use source-only mode** (if analyzing source code):

   ```python
   config.set_ghidra_run_policy('never')
   ```

2. **Increase timeout** (if analyzing large binaries):

   ```python
   ctx = RunContext(
       ghidra_options={'timeout': 1800},  # 30 minutes
       # ... other params ...
   )
   ```

3. **Check file size** (files > 5MB skipped by default):
   ```python
   # Adjust in ghidra_policy.py:
   MAX_BINARY_SIZE_BYTES = 10 * 1024 * 1024  # 10MB
   ```

#### 3. "Missing required packages"

**Error:**

```
❌ Required Packages: Missing required packages: jsonschema
```

**Solution:**

```powershell
pip install jsonschema
# or
pip install -r requirements.txt
```

#### 4. "File not found"

**Error:**

```
FileNotFoundError: preproc input not found: /path/to/file
```

**Causes:**

- File hasn't been preprocessed yet
- Wrong `preproc_dir` path
- File hash mismatch

**Solution:**

```python
# Verify preprocessing happened
import os
preproc_dir = "/path/to/case/preproc/<file_hash>"
assert os.path.exists(os.path.join(preproc_dir, "input.bin"))
assert os.path.exists(os.path.join(preproc_dir, "metadata.json"))
```

#### 5. "Permission denied"

**Error:**

```
PermissionError: Permission denied: /path/to/output
```

**Solutions:**

- Check write permissions on output directory
- Run without admin/elevated privileges (per-user install)
- Check disk space

#### 6. Slow Analysis on Source Code

**Symptoms:**

- Analysis takes 10+ minutes per file
- Lots of timeout messages
- Analyzing Python/JavaScript/JSON files

**Solution:**

```python
# Use auto policy (default) or never policy
from src.auditor.detectors.static_detection import config
config.set_ghidra_run_policy('auto')  # Smart filtering
# or
config.set_ghidra_run_policy('never')  # Skip all Ghidra
```

**Expected speedup:** 50-100x faster for source-heavy projects

### Validation Checklist

Run this to verify everything is working:

```powershell
# 1. Check setup status
python -m src.auditor.detectors.static_detection.setup check

# 2. Verify policy
python -m src.auditor.detectors.static_detection.setup policy

# 3. Run verification tests
python test_policy.py
python test_policy_integration.py
python verify_optimization.py

# 4. Test with sample binary (if Ghidra enabled)
python test_ghidra_pipeline.py
```

### Getting Help

If issues persist:

1. **Check logs**: Look for detailed error messages in console output
2. **Review documentation**:
   - `docs/ghidra-policy.md` - Ghidra filtering details
   - `installation/README.md` - Ghidra installation
   - `docs/analysis-storage.md` - Directory structure
3. **Run diagnostics**:
   ```powershell
   python -m src.auditor.detectors.static_detection.setup check
   ```

---

## Performance Tips

### For Source-Heavy Projects (Recommended)

```python
# Use auto policy (skips source files automatically)
config.set_ghidra_run_policy('auto')
```

**Result:** 50-100x faster than running Ghidra on all files

### For Binary-Only Projects

```python
# Keep auto policy but ensure binaries are properly classified
config.set_ghidra_run_policy('auto')
```

Check `metadata.json` has:

- `"is_binary": true`
- Correct MIME type (`application/x-elf`, `application/x-dosexec`, etc.)

### For Maximum Speed (Source Only)

```python
# Disable Ghidra entirely
config.set_ghidra_run_policy('never')
```

**Result:** Near-instant analysis (no Ghidra overhead)

### Caching

The pipeline automatically caches results. To force re-analysis:

```python
ctx = RunContext(force=True, ...)  # Skip cache
```

---

## Quick Reference

### Commands

```powershell
# Setup and validation
python -m src.auditor.detectors.static_detection.setup check
python -m src.auditor.detectors.static_detection.setup wizard
python -m src.auditor.detectors.static_detection.setup policy

# Testing
python test_policy.py                    # Unit tests
python test_policy_integration.py        # Integration test
python verify_optimization.py            # Full verification
python test_ghidra_pipeline.py          # Ghidra test (if enabled)

# Ghidra installation (Windows)
powershell -File .\installation\install-ghidra.ps1 -ArchivePath "..." -Sha256 "..."
```

### Configuration Locations

**Windows:**

- Config: `%APPDATA%\cryptoscope\config.json`
- Ghidra: `%LOCALAPPDATA%\Ghidra\ghidra_<version>\`

**Linux/Mac:**

- Config: `~/.config/cryptoscope/config.json`
- Ghidra: `~/ghidra_<version>/`

### Policy Quick Reference

| Policy   | Description        | Use Case                | Speed            |
| -------- | ------------------ | ----------------------- | ---------------- |
| `auto`   | Smart filtering    | Mixed source + binaries | ⚡⚡⚡ Fast      |
| `always` | Force on all files | Binary-only, debugging  | 🐌 Slow          |
| `never`  | Skip Ghidra        | Source-only projects    | ⚡⚡⚡⚡ Fastest |

---

## What's Next?

After setup:

1. **Test with your data:**

   ```python
   from src.auditor.detectors.static_detection import StaticRunner
   from src.auditor.detectors.static_detection.context import RunContext

   runner = StaticRunner()
   ctx = RunContext(
       file_hash="your_hash",
       preproc_dir="path/to/preproc",
       analysis_base="path/to/case"
   )
   result = runner.run(ctx)
   ```

2. **Review outputs:**

   - `static_results.json` - Full findings
   - `hints.json` - Detection hints
   - `ghidra-export/` - Binary analysis (if run)

3. **Optimize for your workflow:**

   - Adjust policy based on file types
   - Configure caching behavior
   - Tune timeout for large binaries

4. **Monitor performance:**
   - Check log messages for skip reasons
   - Verify expected files are analyzed
   - Measure analysis time improvements

---

## Summary

**Essential Steps:**

1. ✅ Install Python 3.10-3.12 and dependencies
2. ✅ Run `python -m src.auditor.detectors.static_detection.setup check`
3. ✅ Configure Ghidra (or use `policy='never'` for source-only)
4. ✅ Test with your data

**Key Takeaways:**

- Use `auto` policy for best performance (default)
- Source-heavy projects get 50-100x speedup
- Run setup check to verify everything is working
- Ghidra is optional (use `never` policy to skip)

**Ready to Go! 🚀**

For more details, see:

- `docs/ghidra-policy.md` - Policy details
- `installation/README.md` - Ghidra installation
- `GHIDRA_OPTIMIZATION_COMPLETE.md` - Performance optimization guide
