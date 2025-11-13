# Debugging Your Static Detection Hang

**Last Updated:** 2025-11-13

---

## What Changed

I've added **comprehensive detailed logging** to help identify exactly where your static detection is hanging. Two recent commits added improvements:

### Commit 1: Timeout Protection & Memory Safeguards
```
e9f2e884 - fix: Add timeout protection and memory safeguards to static detection
```
- Chunked file reading (32KB chunks instead of whole file)
- File size limits (100MB hard limit)
- Timeout checks in each stage
- Memory optimizations for large files

### Commit 2: Detailed Debug Logging
```
8fbef7ca - feat: Add comprehensive detailed logging for static detection debugging
```
- Per-file logging with timestamps
- Stage-by-stage tracking (STAGE 1, 2, 3)
- Real-time progress visible
- Debug log file output

---

## How to Use the Debug Logs

### Step 1: Run Static Detection

Use the UI as normal to start batch analysis. The system will now automatically create a debug log.

### Step 2: Watch the Log in Real-Time

**Linux/Mac:**
```bash
tail -f <case_workdir>/static_detection_debug.log
```

**Windows PowerShell:**
```powershell
Get-Content -Path "<case_workdir>/static_detection_debug.log" -Wait
```

You'll see output like:
```
================================================================================
STATIC DETECTION BATCH ANALYSIS START
================================================================================
[2025-11-13 12:00:00] Total files to process: 1951
[2025-11-13 12:00:00] Profile: quick, Force: False

[2025-11-13 12:00:05]
================================================================================
[150/1951] Starting analysis of abc123def456789abc123...
================================================================================
[2025-11-13 12:00:05] [STAGE 1] Starting static preprocessing...
[2025-11-13 12:00:05] [STAGE 1] timeout=12.5s, remaining=298.5s
[2025-11-13 12:00:10] [STAGE 1] Completed in 5.23s

[2025-11-13 12:00:10] [STAGE 2] Starting Ghidra analysis decision...
[2025-11-13 12:00:10] [STAGE 2] Ghidra policy: auto
[2025-11-13 12:00:10] [STAGE 2] Decision: should_run=True, reason=Binary file
[2025-11-13 12:00:15] [STAGE 2] ensure_ghidra_export completed in 5.12s
[2025-11-13 12:00:15] [STAGE 2] Read 1523 functions from Ghidra
[2025-11-13 12:00:15] [STAGE 2] Completed in 5.45s

[2025-11-13 12:00:15] [STAGE 3] Loading heuristics...
[2025-11-13 12:00:15] [STAGE 3] Loaded 3 heuristics: [...]
[2025-11-13 12:00:20] [STAGE 3] Completed in 5.00s, found 42 findings
✓ Analyzed [150/1951] abc123def456... (15.73s)
```

### Step 3: When It Hangs (or if it does)

Let it run until it hangs (or let it complete). Then check the log to find:

1. **The stuck file hash** - Last file logged
2. **The stuck stage** - Which [STAGE N] was processing
3. **How long it took to get stuck** - From start to last log entry

---

## Quick Diagnostic Commands

### Find Which File Is Stuck

```bash
# Show the last file that started (but may not have finished)
grep "Starting analysis of" <case>/static_detection_debug.log | tail -1
```

Output will show the file hash.

### Find Which Stage It's Stuck In

```bash
# Show the last STAGE entry
grep "\[STAGE" <case>/static_detection_debug.log | tail -1
```

Output:
- `[STAGE 1]` = Static preprocessing
- `[STAGE 2]` = Ghidra analysis
- `[STAGE 3]` = Heuristics

### Check How Many Files Completed

```bash
# Count completed files
grep "✓ Analyzed\|✓ Cached" <case>/static_detection_debug.log | wc -l

# Count failed files
grep "✗ Error\|✗ TIMEOUT" <case>/static_detection_debug.log | wc -l
```

---

## Solutions Based on Where It Hangs

### If Stuck in STAGE 1 (Static Preprocessing)

**Likely cause:** Very large binary or slow I/O

**Try:**
1. Check file size:
   ```bash
   ls -lh <case>/preproc/[stuck_file_hash]/input.bin
   ```

2. If >50MB, use **"quick" profile** (skips expensive constant analysis):
   - In UI, select "quick" instead of "full"
   - Re-run on the stuck file

3. Check disk space/speed:
   ```bash
   # Linux
   free -h
   df -h
   ```

### If Stuck in STAGE 2 (Ghidra Analysis)

**Likely cause:** Ghidra subprocess hanging on complex binary

**Try:**
1. **Skip Ghidra** to test:
   - Edit `src/auditor/detectors/static_detection/config.py`
   - Set Ghidra policy to `"never"`
   - Re-run to see if it completes without Ghidra

2. Check log for Ghidra details:
   ```bash
   grep "STAGE 2" <case>/static_detection_debug.log | grep "ensure_ghidra_export"
   ```

### If Stuck in STAGE 3 (Heuristics)

**Likely cause:** Heuristic infinite loop or expensive computation

**Try:**
1. Check which heuristics loaded:
   ```bash
   grep "Loaded.*heuristics" <case>/static_detection_debug.log
   ```

2. Try disabling heuristics to isolate the issue:
   - Edit `src/auditor/detectors/static_detection/runner.py`
   - Comment out heuristic loading (lines 282-302)
   - Re-run to test

---

## After Identifying the Problem

### 1. Note the Details

When you run and it hangs again, capture:
- File hash from log
- Stage where it gets stuck
- How long until it hangs
- System resources (RAM available, disk free)

### 2. Try the Suggested Solution

For example:
- Try quick profile instead of full
- Try with Ghidra disabled
- Try with heuristics disabled

### 3. Re-Run on Just That File

Once you've identified the stuck file, you can test fixes faster:
- Just analyze that one file
- Try different settings
- See if it completes

### 4. Share the Log

If the issue persists, provide:
- The debug log file: `<case>/static_detection_debug.log`
- The stuck file hash (from log)
- What you tried and results
- System specs (RAM, disk, CPU type)

---

## Performance Tips (If Just Slow, Not Hanging)

### For Analysis on Large Releases

Use **"quick" profile**:
- Skips Ghidra on source code files
- Skips expensive constant detection on large binaries
- Cuts analysis time 2-5x

### Disable Ghidra for Source Code

If analyzing source code (like Go Ethereum):
- Set Ghidra policy to `"never"` in config
- Source code analysis doesn't need Ghidra
- Heuristics work fine on disassembled functions

### Disable Expensive Heuristics

In `runner.py`, comment out heuristics you don't need:
```python
# Comment these out if not needed:
# heuristics.append(signature_heuristic)
# heuristics.append(instruction_patterns_heuristic)
# heuristics.append(constants_heuristic)
```

---

## Understanding the Log Levels

| Level | Color | Meaning |
|-------|-------|---------|
| DEBUG | Gray | Detailed diagnostic info |
| INFO | Green | High-level progress (what you want to see) |
| WARNING | Yellow | Something unexpected but continuing |
| ERROR | Red | Something failed, usually with traceback |

---

## Key Improvements Made

### Timeout Protection
- ✅ 5-minute overall timeout (configurable)
- ✅ Per-stage timeouts
- ✅ 100MB file size limit
- ✅ Sampling for large files

### Debug Visibility
- ✅ Per-file logging with timestamps
- ✅ Stage-by-stage tracking
- ✅ Real-time progress visible
- ✅ File output + console output
- ✅ Easy grep-able format

### Better Error Handling
- ✅ Timeout errors caught and reported
- ✅ Failed heuristics don't break pipeline
- ✅ Partial results on timeout
- ✅ Clear error messages with context

---

## Files Changed

Two commits with improvements:

1. **Timeout & Memory Safeguards:**
   - `src/auditor/detectors/static_detection/static_preproc.py`
   - `src/auditor/detectors/static_detection/heuristics_manager.py`
   - `src/auditor/detectors/static_detection/runner.py`
   - New doc: `docs/STATIC_DETECTION_HANG_FIXES.md`

2. **Debug Logging:**
   - `src/pages/detectors.py`
   - `src/auditor/detectors/static_detection/runner.py`
   - New doc: `docs/STATIC_DETECTION_DEBUG_GUIDE.md` (detailed logging reference)

---

## Next Steps

1. **Run your analysis** with the new logging
2. **Monitor the log** in real-time using `tail -f`
3. **If it hangs**, identify the file hash and stage from logs
4. **Try suggested solution** based on stuck stage
5. **Report back** with:
   - Stuck file hash
   - Stuck stage
   - Debug log (last 100 lines)
   - What you tried

The logging should tell us exactly where the bottleneck is! 🎯

---

## Quick Reference

| When | Action | Command |
|------|--------|---------|
| Start analysis | Monitor log live | `tail -f <case>/static_detection_debug.log` |
| If hangs | Find stuck file | `grep "Starting analysis" <case>/static_detection_debug.log \| tail -1` |
| If hangs | Find stuck stage | `grep "\[STAGE" <case>/static_detection_debug.log \| tail -1` |
| If slow | Use quick profile | Select "quick" in UI |
| If Ghidra slow | Disable Ghidra | Set policy to "never" in config.py |
| If still stuck | Check disk space | `df -h` |
| If still stuck | Check RAM | `free -h` |

Good luck! The logs should reveal exactly what's happening! 🔍
