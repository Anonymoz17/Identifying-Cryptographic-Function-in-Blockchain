# Detectors Page Implementation

**Date**: November 7, 2025  
**Status**: ✅ Implemented and Ready  
**Location**: `src/pages/detectors.py`

## Overview

The Detectors page provides a comprehensive UI for running static and dynamic cryptographic analysis on preprocessed binaries. It features a toggle between two modes and integrates seamlessly with the static detection backend. **The page supports both workflow mode (coming from Setup) and standalone mode (direct launch with case loading).**

---

## Features

### 🔄 **Standalone Mode Support**

The Detectors page can work independently without requiring the Setup page:

**Workflow Mode (from Setup):**

- Automatic case loading from `master.current_scan_meta`
- Seamless transition from preprocessing to analysis
- Pre-configured workdir paths

**Standalone Mode (direct launch):**

- Shows "Load Case" UI when no active case detected
- Browse and select existing case workdir
- Lists all available preprocessed cases
- Load any case to begin analysis independently

This makes the Detectors page reusable for:

- Re-analyzing existing cases
- Testing detection on preprocessed binaries
- Batch analysis workflows
- Development and debugging

### 🎯 **Dual-Mode Toggle**

- **Static Analysis** (Free, Implemented)

  - Analyzes binaries using Ghidra disassembly
  - Runs heuristics (signatures, instruction patterns, constants)
  - Generates findings with confidence scores
  - Exports results in JSON format

- **Dynamic Analysis** (Premium, Stub)
  - Placeholder for future Frida instrumentation
  - Premium feature indicator with upgrade CTA
  - Will integrate with static analysis hints

### 🎛️ **Static Analysis Controls**

**Configuration:**

- **Profile Selection**: `quick` or `full`
  - Quick: Fast entropy & pattern analysis (256-byte windows)
  - Full: Deep Ghidra disassembly (64-byte windows)
- **Force Re-analysis**: Bypass cache, always regenerate

**Actions:**

- ▶ **Run Static Analysis**: Starts background analysis thread
- ⏹ **Cancel**: Gracefully cancels ongoing analysis
- 📄 **Export Results**: Saves JSON findings to user-selected location

**Progress Tracking:**

- Real-time progress bar
- Status messages with timestamps
- Console log with detailed operation trace

### 📊 **Results Display (Tabbed)**

1. **Summary Tab**

   - File hash
   - Cache status
   - Findings count
   - Artifact paths

2. **Findings Tab**

   - Top 50 findings sorted by confidence
   - Detailed breakdown per finding:
     - Type (signature, instruction_pattern, constant_table, etc.)
     - Confidence score
     - Reason tags
     - Evidence snippet
     - Address/range (if available)

3. **Console Tab**
   - Timestamped operation log
   - Progress updates
   - Error messages
   - Debug information

### 📁 **Load Case UI (Standalone Mode)**

When launched without an active case:

**Workdir Selection:**

- Manual entry or file browser
- Auto-populates with default workdir
- Validation before loading

**Available Cases List:**

- Scans `preproc/` directory for case folders
- Shows file hash, binary status, metadata status
- Refresh button to rescan directory
- Clear status indicators (📦 bin, 📋 meta)

**Load Action:**

- Validates case structure
- Transitions to analysis UI
- Maintains standalone mode flag

---

## Architecture

### Data Flow

**Workflow Mode:**

```
Setup Page (preprocessing)
    ↓
    stores scan metadata in master.current_scan_meta
    ↓
Detectors Page
    ↓
    reads workdir from scan metadata
    ↓
    creates RunContext(preproc_dir=workdir)
    ↓
    StaticRunner.run(ctx)
    ↓
    Returns RunResult with findings
    ↓
    Display in UI (Summary + Findings + Console)
```

**Standalone Mode:**

```
Detectors Page (direct launch)
    ↓
    detects no scan metadata
    ↓
    shows Load Case UI
    ↓
User browses/selects workdir
    ↓
    scans preproc/ for available cases
    ↓
User clicks Load Case
    ↓
    validates case structure
    ↓
    sets _loaded_case_workdir
    ↓
    hides Load Case UI, shows analysis UI
    ↓
    analysis proceeds same as workflow mode
```

### Integration Points

**From Setup Page (Workflow Mode):**

- `master.current_scan_meta`: Contains `workdir` and `case_id`
- Workdir structure: `<workdir>/preproc/<file_hash>/`

**Standalone Mode:**

- User provides workdir path via UI
- `_loaded_case_workdir`: Stores selected workdir
- Same directory structure expected

**To Static Detection:**

- Creates `RunContext` with:
  - `preproc_dir`: Case workdir (from setup OR standalone)
  - `analysis_base`: Same as preproc_dir
  - `profile`: User-selected (quick/full)
  - `force`: User-selected (bypass cache)
  - `file_hash`: Auto-detected by runner

**Output Locations:**

- `<workdir>/analysis/static/<file_hash>/static_results.json`
- `<workdir>/analysis/static/<file_hash>/hints.json`

---

## UI Components

### Header

- Page title: "Cryptographic Detection Analysis"
- Accounts menu integration (profile switching)

### Load Case Section (Standalone Mode Only)

- **Title**: "Load Existing Case"
- **Description**: Explains standalone mode
- **Workdir Input**: Text entry + browse button
- **Cases List**: Scrollable textbox showing available cases
- **Refresh Button**: Rescans directory for cases
- **Load Button**: Validates and loads selected case
- **Status Label**: Shows load operation feedback

### Mode Toggle (Segmented Button)

- Static Analysis ↔ Dynamic Analysis
- Visual feedback with mode descriptions
- Free (🆓) vs Premium (🔒) indicators

### Static Analysis Section

- **Config Frame**: Profile, force options
- **Action Frame**: Run, Cancel, Export buttons
- **Progress Frame**: Bar + status label
- **Results Frame**: Tabbed view (Summary, Findings, Console)

### Status Bar

- Bottom-aligned status messages
- Color-coded (green = success, red = error)

---

## Thread Safety

**Background Analysis Thread:**

- Runs `StaticRunner.run()` in daemon thread
- Uses `threading.Event` for cancellation
- All UI updates marshalled to main thread via `self.after()`

**Critical Sections:**

- `_analysis_running` flag prevents concurrent runs
- UI state changes always on main thread
- Console logging thread-safe via `self.after()`

---

## Error Handling

**Graceful Degradation:**

- Missing scan metadata → User-friendly error message
- Analysis errors → Display in console + status bar
- File I/O errors → Try-except with fallback messages

**User Feedback:**

- All errors shown in status bar and console
- Progress bar resets on error
- Buttons re-enabled appropriately

---

## Testing Checklist

### Manual Testing (Workflow Mode)

- [ ] Mode toggle switches UI correctly
- [ ] Static analysis runs with quick profile
- [ ] Static analysis runs with full profile
- [ ] Force re-analysis bypasses cache
- [ ] Cancel button stops analysis
- [ ] Progress bar updates during analysis
- [ ] Results display correctly in all tabs
- [ ] Export saves results to chosen location
- [ ] Console log shows timestamped messages
- [ ] Dynamic mode shows premium placeholder

### Manual Testing (Standalone Mode)

- [ ] Load Case UI appears when no scan metadata
- [ ] Browse button opens file dialog
- [ ] Workdir entry accepts manual path
- [ ] Refresh Cases scans preproc directory
- [ ] Available cases list shows all valid cases
- [ ] Case status indicators correct (bin, meta)
- [ ] Load Case validates workdir structure
- [ ] After loading, analysis UI appears
- [ ] Static analysis works same as workflow mode
- [ ] Console log shows standalone mode messages

### Integration Testing

- [ ] Setup → Detectors flow works (workflow mode)
- [ ] Direct launch → Load Case works (standalone mode)
- [ ] Scan metadata passed correctly
- [ ] Workdir resolution works with auto-detect
- [ ] Multiple file hashes handled gracefully
- [ ] Cache behavior correct (cached vs fresh)
- [ ] Mode detection on `on_enter()` correct

### Error Scenarios

- [ ] No scan metadata → Shows Load Case UI
- [ ] Invalid workdir → Error with guidance
- [ ] Empty preproc directory → Clear message
- [ ] Incomplete case structure → Warning shown
- [ ] Analysis exception → Error displayed
- [ ] Missing results file → Handled gracefully

---

## Code Structure

```python
DetectorsPage
├── __init__()                        # Setup UI components
├── _build_static_ui()                # Static analysis UI
├── _build_dynamic_ui()               # Dynamic placeholder UI
├── _build_load_case_ui()             # Standalone case loader UI
├── _on_mode_change()                 # Toggle handler
├── _browse_case_workdir()            # File browser for workdir
├── _refresh_case_list()              # Scan for available cases
├── _update_cases_list()              # Update UI with case list
├── _load_selected_case()             # Load case and transition to analysis
├── _set_load_case_status()           # Status updates for load UI
├── _run_static_analysis()            # Start analysis (main thread)
├── _static_analysis_thread()         # Background analysis worker
├── _cancel_analysis()                # Cancellation handler
├── _on_analysis_complete()           # Success handler
├── _on_analysis_cancelled()          # Cancellation handler
├── _on_analysis_error()              # Error handler
├── _display_results()                # Results rendering
├── _display_findings_from_file()     # Parse & display JSON
├── _export_results()                 # File export dialog
├── _clear_results()                  # UI cleanup
├── _log_console()                    # Console logging
├── _set_status()                     # Status bar updates
└── on_enter()                        # Page activation hook (mode detection)
```

---

## Mode Detection Logic

The page automatically detects which mode to use in `on_enter()`:

**Workflow Mode Trigger:**

- `master.current_scan_meta` exists
- Contains valid `workdir` key
- → Hide Load Case UI
- → Show analysis UI directly
- → Set `_standalone_mode = False`

**Standalone Mode Trigger:**

- No `current_scan_meta` OR missing `workdir`
- → Show Load Case UI
- → Hide analysis UI
- → Set `_standalone_mode = True`
- → User must load case manually

**Mode Persistence:**

- `_standalone_mode` flag maintained throughout session
- `_loaded_case_workdir` stores manually loaded path
- `_case_workdir` used by analysis (combines both sources)

---

## Future Enhancements

### Short-term

1. **Case Selection**: Click-to-select from cases list (not just load workdir)
2. **Live Filtering**: Search/filter findings by type/confidence
3. **Visualization**: Charts for finding distribution
4. **Comparison**: Side-by-side results from multiple runs
5. **Batch Analysis**: Queue multiple binaries
6. **Recent Cases**: Remember recently loaded cases for quick access

### Long-term (Dynamic Analysis)

1. **Frida Integration**: Runtime instrumentation
2. **Hints-Driven Hooking**: Use static hints to guide dynamic analysis
3. **Memory Dumps**: Capture crypto keys/buffers
4. **Call Graph Visualization**: Interactive flow diagrams
5. **Premium Gating**: Role-based access control

---

## Dependencies

**Required:**

- `customtkinter` - UI framework
- `tkinter` - Standard GUI toolkit
- Threading (stdlib)

**Static Detection:**

- `auditor.detectors.static_detection.runner.StaticRunner`
- `auditor.detectors.static_detection.context.RunContext`
- `auditor.detectors.static_detection.context.ToolVersions`

**Optional:**

- `pages.accounts.AccountsMenu` - Profile management

---

## Configuration

**Default Values:**

- Profile: `quick`
- Force: `False` (use cache)
- Max findings displayed: 50
- Console log retention: Scrolling (no limit)

**Customizable:**

- Analysis profiles (quick/full)
- Force re-analysis toggle
- Export file location

---

## Performance Considerations

**UI Responsiveness:**

- Analysis runs in background thread (non-blocking)
- Progress updates throttled to avoid UI floods
- Console log uses `self.after()` for thread-safe updates

**Memory:**

- Results limited to top 50 findings in UI
- Full results available via export
- Console log unbounded (consider adding cap)

**Disk I/O:**

- Read-only access to analysis artifacts
- Export creates copy (doesn't modify originals)
- Cached results reused when force=False

---

## Known Limitations

1. **Single Binary**: Currently analyzes one binary per run
2. **No Progress Detail**: Progress bar is binary (0% → 100%)
3. **Export Format**: JSON only (consider CSV/PDF in future)
4. **Dynamic Stub**: Not yet implemented (placeholder UI only)

---

## Troubleshooting

**"No scan data available"**
→ Run Setup page first to preprocess binaries

**Analysis hangs**
→ Use Cancel button, check console for errors

**No findings displayed**
→ Check console tab for errors, verify workdir contains analysis/static/

**Export fails**
→ Ensure write permissions to destination, check file not open

---

## Commit Message

```
feat(ui): implement Detectors page with static analysis integration

- Add toggleable static/dynamic mode selection
- Integrate StaticRunner for crypto detection
- Display findings in tabbed UI (Summary, Findings, Console)
- Support quick/full analysis profiles
- Add force re-analysis option
- Export results to JSON
- Thread-safe background analysis
- Dynamic analysis placeholder (premium)

The Detectors page follows the Setup page in the workflow and
consumes preprocessed artifacts to run static detection heuristics.
All 3 heuristics (signature, instruction_patterns, constants) are
now accessible through the UI with real-time progress tracking.
```

---

## Screenshots (Conceptual)

**Static Analysis Mode:**

```
┌────────────────────────────────────────────────────────────┐
│ Cryptographic Detection Analysis          [@User ▾]        │
├────────────────────────────────────────────────────────────┤
│ Analysis Mode: [Static Analysis] [Dynamic Analysis]        │
│ 🆓 Free • Analyzes binaries for crypto patterns           │
├────────────────────────────────────────────────────────────┤
│ Profile: [quick ▾]  Quick: Fast entropy & pattern analysis│
│ ☐ Force re-analysis (ignore cache)                        │
├────────────────────────────────────────────────────────────┤
│ [▶ Run Static Analysis] [⏹ Cancel] [📄 Export Results]   │
│ Progress: ████████████████████ 100%   ✅ Complete         │
├────────────────────────────────────────────────────────────┤
│ [Summary] [Findings] [Console]                            │
│ ┌────────────────────────────────────────────────────────┐│
│ │ FINDINGS (42 total)                                    ││
│ │ [1] KNOWN_CRYPTO_CONSTANT                              ││
│ │     Confidence: 0.95                                   ││
│ │     Name: SHA256_H0                                    ││
│ │     Tags: known_constant, sha-256                      ││
│ │ ...                                                    ││
│ └────────────────────────────────────────────────────────┘│
├────────────────────────────────────────────────────────────┤
│ Status: ✅ Analysis completed successfully                 │
└────────────────────────────────────────────────────────────┘
```

**Dynamic Analysis Mode (Stub):**

```
┌────────────────────────────────────────────────────────────┐
│                          🔒                                │
│                                                            │
│               Dynamic Analysis                             │
│                                                            │
│         Premium Feature • Coming Soon                      │
│                                                            │
│ Dynamic analysis uses Frida instrumentation to trace      │
│ crypto operations at runtime...                           │
│                                                            │
│         [Learn More About Premium]                         │
└────────────────────────────────────────────────────────────┘
```
