# Batch Static Detection Architecture

## Overview

The static detection system processes **all preprocessed binaries** in a case with a single click, automatically iterating through each binary and aggregating results.

## Architecture

### UI Layer (detectors.py)
**Responsibility:** Orchestration, progress tracking, results aggregation

**Key Components:**
- `_scan_all_cases()`: Scans `preproc/` directory to find all file_hashes
- `_batch_analysis_thread()`: Loops through each file_hash sequentially
- `_update_batch_progress()`: Updates UI with current/total counts
- `_display_batch_results()`: Shows aggregated findings from all binaries

### Backend Layer (StaticRunner)
**Responsibility:** Single-binary analysis logic

**Key Design:**
- Processes ONE file_hash at a time
- Takes `RunContext(file_hash=...)` parameter
- No batch handling logic - stays focused on single-binary analysis
- Validates preproc structure before processing

## Case Structure

```
case_workdir/
  ├── preproc/
  │   ├── <file_hash_1>/
  │   │   ├── input.bin
  │   │   └── metadata.json
  │   ├── <file_hash_2>/
  │   │   ├── input.bin
  │   │   └── metadata.json
  │   └── <file_hash_3>/
  │       ├── input.bin
  │       └── metadata.json
  └── analysis/
      └── static/
          ├── <file_hash_1>/
          │   ├── preproc/
          │   ├── ghidra-export/
          │   ├── hints.json
          │   └── static_results.json
          ├── <file_hash_2>/
          │   └── ...
          └── <file_hash_3>/
              └── ...
```

## Batch Processing Flow

### 1. Initialization
```python
# UI scans preproc/ directory
_scan_all_cases()
  → Finds all directories with input.bin + metadata.json
  → Updates case summary with total count
  → Checks which binaries already have cached results
```

### 2. Analysis Loop
```python
# UI starts batch thread
_batch_analysis_thread()
  for each file_hash in all_hashes:
    1. Create RunContext(file_hash=hash)
    2. Call StaticRunner.run(ctx)
    3. Store result in batch_results dict
    4. Update progress (current/total)
    5. Log status (✓ Analyzed / ✓ Cached / ✗ Error)
```

### 3. Completion
```python
# After all binaries processed
_on_batch_complete()
  → Display summary (successes/errors/cached)
  → Aggregate all findings from static_results.json files
  → Show top findings sorted by confidence
  → Enable export button
```

## UI Features

### Case Summary Panel
Shows before starting analysis:
- Total preprocessed binaries found
- Previously analyzed (cached) count
- Ready for analysis count

### Progress Tracking
Updates during analysis:
- Progress bar (0-100%)
- Current/total counter (e.g., "Processing 50/200")
- Current file_hash being processed
- Per-binary status logs (✓/✗)

### Results Display

#### Summary Tab
- Total binaries analyzed
- Success/error/cached breakdown
- Per-binary status list with finding counts

#### Findings Tab
- Aggregated findings from all binaries
- Sorted by confidence score
- Shows source file_hash for each finding
- Limited to top 100 findings for performance

## Results Access

### Standard Output Locations (Pipeline-Compatible)

All results are automatically saved to **standard locations** defined by the pipeline architecture:

- `analysis/static/<file_hash>/static_results.json` - Complete analysis results per binary
- `analysis/static/<file_hash>/hints.json` - Cryptographic hints for dynamic analysis
- `analysis/static/<file_hash>/ghidra-export/` - Cached Ghidra function exports

**Why no manual export?**

1. **Pipeline Integration**: Downstream tools (dynamic detector, merger) expect results at standard locations
2. **Automation-First**: Results are already in the canonical format - no conversion needed
3. **Case-Based Workflow**: With 200+ binaries, exporting individual results doesn't scale
4. **Programmatic Access**: Tools should read directly from `analysis/` directory, not manually exported copies

### Accessing Results

**Via UI**: Click "📁 Open Results" button to open the `analysis/static/` folder in file explorer

**Programmatically**:
```python
from pathlib import Path
import json

case_workdir = Path("/path/to/case")
for file_hash_dir in (case_workdir / "analysis" / "static").iterdir():
    results_path = file_hash_dir / "static_results.json"
    with open(results_path) as f:
        results = json.load(f)
        # Process results...
```

**For Reporting**: Generate HTML/PDF reports by reading the JSON files (future feature)

**For Sharing**: Archive the entire case workspace (preserves all context and relationships)

## Error Handling

### Graceful Degradation
- If one binary fails, continue with next binary
- Store error in `batch_results[hash] = {"error": "..."}` 
- Show error count in final summary
- Don't block entire batch on single failure

### Cancellation Support
- User can cancel at any time
- Currently processing binary completes
- Remaining binaries are skipped
- Partial results displayed

## Separation of Concerns

### ✅ Correct
- UI handles **orchestration** (loop through hashes)
- UI handles **progress tracking** (X/Y updates)
- UI handles **aggregation** (combine all static_results.json)
- Backend handles **single-binary analysis** (one file_hash → one result)

### ❌ Incorrect
- Backend should NOT loop through multiple binaries
- Backend should NOT handle batch progress
- UI should NOT contain analysis logic
- UI should NOT directly call Ghidra/disassemblers

## Standalone Mode

Both Setup and Static Detection support **standalone mode**:

1. **Setup Standalone**: User loads archive → preprocesses all binaries → saves case
2. **Detection Standalone**: User loads existing case → batch-analyzes all preprocessed binaries

No need to run Setup before Detection if case already exists.

## Performance Considerations

### Caching
- Automatically detects existing `static_results.json` files
- Skips re-analysis if cached result exists
- User can force re-analysis with "Force Re-run" option

### Progress
- Updates UI every binary (not every second)
- Logs per-binary status for monitoring
- Shows percentage complete

### Results Storage
- All results saved to standard pipeline locations
- No intermediate copies or manual exports needed
- Downstream tools read directly from `analysis/` directory

## Testing with Large Cases

Example: Case with 200+ binaries
- Scan time: ~1 second
- Analysis time: Varies by binary complexity
- Progress updates: Every binary
- Memory: Results stored in dict, manageable
- UI responsiveness: Background thread keeps UI responsive
- Results access: Direct filesystem access to `analysis/static/<file_hash>/` per binary
