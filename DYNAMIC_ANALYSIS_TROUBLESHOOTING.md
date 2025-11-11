# Dynamic Analysis Troubleshooting Checklist

Use this checklist to diagnose dynamic analysis issues.

---

## Pre-Flight: Is Your Case Suitable?

### ✓ Check 1: Do You Have Frida Installed?

```bash
python -c "import frida; print(f'Frida {frida.__version__}')"
```

**Expected:** Shows version like "17.2.14"

**If failed:**

```bash
pip install frida==16.0.19 frida-tools==12.2.1
```

---

### ✓ Check 2: Do You Have Compiled Binaries?

```bash
python diagnose_dynamic_issue.py "C:\path\to\your\workspace"
```

**Look for:**

- "Binary Types" check result
- If it shows mostly "executable", "pe32", "dll" → ✓ Good
- If it shows mostly "python", "c", "java" → ✗ Source code (won't work)

**If source code:**

```
⚠️ WARNING: {count} source code files detected
Solution: Use Static Analysis instead, or compile to binaries first
```

---

### ✓ Check 3: Do You Have Static Analysis Results?

```bash
# Check if hints.json exists
ls "workspace/analysis/static/{file_hash}/hints.json"
```

**If not found:** Run static analysis first

```bash
# In the UI: Click "Analyze All Binaries" under Static Detection
# Or programmatically:
from auditor.detectors import StaticDetector
detector = StaticDetector()
result = detector.analyze(workspace='workspace')
```

---

## Analysis Issues

### Issue: "No cryptographic operations detected" (0 calls)

**Possible causes (in order):**

1. **Source code files** (most common)

   - Solution: Use static analysis, or compile to .exe/.dll first

2. **Binaries don't use crypto at runtime**

   - Solution: Check if your binary actually loads crypto DLLs
   - Check with: `depends.exe yourfile.exe` (shows DLL dependencies)

3. **Static hints not available**

   - Solution: Run static analysis first
   - Check: Does `hints.json` exist?

4. **Timeout too short**

   - Solution: Increase timeout (default 10s, try 30s)
   - In UI: Adjust "Timeout (seconds)" slider

5. **Frida can't hook the process**
   - Solution: Run as Administrator
   - Or disable antivirus temporarily

---

### Issue: All Files Show "incomplete"

**This is normal for source code!**

Dynamic analysis marks results as incomplete if:

- No function hooks were triggered
- No trace data collected
- Frida couldn't intercept calls

**For source code:** Completely expected → Use static analysis instead

**For binaries:** Check:

- Is the binary actually executable?
- Does it use crypto functions?
- Is it x86 or x64? (Must match your Python: run `python -c "import struct; print(struct.calcsize('P') * 8)"`)

---

### Issue: Files Show "error" Instead of "incomplete"

**This usually means:**

- Binary is not actually executable
- Frida couldn't spawn/attach
- File is corrupted or wrong format

**Check:**

```bash
# Verify it's actually a PE (Windows executable)
file workspace/preproc/{hash}/input.bin

# Try to run it manually
workspace/preproc/{hash}/input.bin

# Check if file is locked by antivirus
# (Temporarily disable antivirus and retry)
```

---

## Step-by-Step Diagnosis

### Step 1: Check Frida

```bash
python -c "import frida; print('✓ Frida OK')"
# Expected: ✓ Frida OK
```

### Step 2: Check Case Structure

```bash
ls -R workspace/preproc/ | head -20
# Should show: hash_dirs with input.bin and metadata.json
```

### Step 3: Check File Types

```bash
python diagnose_dynamic_issue.py "workspace"
# Look at "FILE TYPE ANALYSIS REPORT" section
```

### Step 4: Check Hints Available

```bash
ls workspace/analysis/static/*/hints.json | wc -l
# Should show count > 0
```

### Step 5: Check One Binary Manually

```python
from auditor.detectors.dynamic_detection import DynamicRunner, DynamicContext

# Pick one file hash
file_hash = "your_hash_here"

ctx = DynamicContext(
    file_hash=file_hash,
    preproc_dir=f"workspace/preproc/{file_hash}",
    hints_path=f"workspace/analysis/static/{file_hash}/hints.json",
    analysis_base="workspace",
    mode="spawn",
    timeout=30  # Longer timeout for debugging
)

runner = DynamicRunner()
result = runner.run(ctx)

print(f"Success: {result.is_success()}")
print(f"Incomplete: {result.incomplete}")
print(f"Errors: {result.errors}")
```

### Step 6: Check Results

```bash
# Find where results were written
find workspace/analysis/dynamic -name "dynamic_results.json" -type f

# Check one result
cat workspace/analysis/dynamic/{hash}/dynamic_results.json | jq .

# Check if traces were collected
wc -l workspace/analysis/dynamic/{hash}/trace.ndjson
# 0 lines = no traces collected
```

---

## Common Solutions

### Solution 1: Source Code Detected

**Symptoms:** All files show 0 crypto calls

**Fix:**

```bash
# Use static analysis instead (works on source code)
# In UI: Click "Analyze All Binaries" under "Static Detection"
```

**Or compile to binary:**

```bash
# Python
pyinstaller --onefile myfile.py
cp dist/myfile.exe workspace/preproc/{hash}/input.bin

# C/C++
gcc myfile.c -o myfile.exe
cp myfile.exe workspace/preproc/{hash}/input.bin
```

---

### Solution 2: Frida Not Installed

**Symptoms:** "Frida not available"

**Fix:**

```bash
pip install frida==16.0.19 frida-tools==12.2.1
python -c "import frida; print(frida.__version__)"
```

---

### Solution 3: Need Administrator Rights

**Symptoms:** "Failed to spawn process"

**Fix:**

```bash
# Run PowerShell as Administrator
# Right-click PowerShell → "Run as Administrator"
# Then run your analysis
```

---

### Solution 4: Antivirus Blocking

**Symptoms:** Intermittent failures, some files work, some don't

**Fix:**

```bash
# Temporarily disable real-time protection
# Or add workspace to antivirus exclusions
# Retry analysis
```

---

### Solution 5: Timeout Too Short

**Symptoms:** Analysis completes but no traces, especially on slow binaries

**Fix:**

- In UI: Increase "Timeout (seconds)" to 30 or 60
- Or programmatically: `timeout=60` in DynamicContext

---

## Quick Reference: What Should I See?

### ✓ Healthy Dynamic Analysis (Binaries)

```
Summary: 5 successful, 0 errors
Traces: AGGREGATED FINDINGS (247 crypto calls from 5 binaries)
Call Graph: [populated]
```

### ⚠️ Source Code (Expected, Use Static Instead)

```
Summary: 180 successful, 0 errors
Traces: AGGREGATED FINDINGS (0 crypto calls from 180 binaries)
Call Graph: [empty]
Reason: Source code files cannot execute dynamically
```

### ✗ Real Problem

```
Summary: 180 errors, 0 successful
Error: Failed to spawn process
Reason: Permission issue, or file is corrupted
```

---

## When to Use What

| Scenario                                 | Use                     | Why                                           |
| ---------------------------------------- | ----------------------- | --------------------------------------------- |
| Source code files (`.py`, `.c`, `.java`) | Static Analysis         | Can analyze without compilation               |
| Compiled binaries (`.exe`, `.dll`)       | Both (Static + Dynamic) | Static finds functions, Dynamic shows runtime |
| Unknown file type                        | Run Diagnostic          | Will tell you what's in it                    |
| Slow analysis                            | Check timeout           | May be too short                              |
| 0 findings                               | Check hints             | May not have run static first                 |
| Some files work, some don't              | Check file types        | Mixed source/binary                           |

---

## Need More Help?

1. **Read full documentation:**

   - `docs/DYNAMIC_ANALYSIS_SOURCE_CODE_ISSUE.md` (comprehensive)
   - `DYNAMIC_ANALYSIS_QUICK_FIX.md` (quick reference)

2. **Run diagnostic:**

   ```bash
   python diagnose_dynamic_issue.py "workspace_path"
   ```

3. **Check logs:**

   - Look in console output when running analysis
   - Check for warnings about file types
   - Look for errors from Frida

4. **Test with known-good binary:**
   - Use `C:\Windows\System32\notepad.exe` or similar
   - Add to your case
   - Run dynamic analysis
   - If it finds calls, your setup is OK

---

## Verification Checklist

Before starting analysis, verify:

- [ ] Frida is installed (`python -c "import frida"`)
- [ ] Case workdir exists and has preproc directory
- [ ] Files in preproc have input.bin and metadata.json
- [ ] Static analysis has been run (check for hints.json)
- [ ] You know what files you're analyzing (binaries or source code?)
- [ ] You have enough disk space
- [ ] You're running as Administrator (if having permission issues)
- [ ] Antivirus isn't blocking Frida

---

**Last Updated:** November 11, 2025
**For:** Identifying-Cryptographic-Function-in-Blockchain Project
