# Basic Test Cases - View Detection Progress and Status

## User Story
As a free user, I want to see detection progress and status so that I know what's running and what's done.

---
Test Case #1
---
View Real-Time Detection Progress | ID: PROGRESS-001
---
Pre-conditions:
User is logged in
User has loaded a case with preprocessed files
User has started static analysis/detection
Detection is running
Progress panel/indicator is visible
---
Steps to Follow:
1. Click "Run Static Analysis" button
2. Detection begins
3. Observe progress indicator during detection
4. Monitor status updates in real-time
---
Test Data:
Case ID: CRYPTO-2024-001
Files: 10 blockchain files to analyze
Expected Progress: 0% → 100%
User Tier: Free
---
Expected Results:
Progress bar/indicator is displayed
Progress updates in real-time (e.g., "10%", "25%", "50%")
Current file being analyzed is shown: "Analyzing: contract.sol"
File counter is displayed: "Processing file 3 of 10"
Status messages update continuously
Progress is visually clear (progress bar, percentage, spinner)
Console shows detailed progress logs
User can see what's currently running
User can estimate time remaining (optional)
Progress never goes backward
Progress bar fills from 0% to 100%
Status text updates match actual progress
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
View Detection Status Stages | ID: PROGRESS-002
---
Pre-conditions:
User is logged in
User has started detection
Detection process has multiple stages
Status panel is visible
---
Steps to Follow:
1. Start detection
2. Observe different status stages during analysis
3. Verify status messages for each stage
4. Confirm completion status
---
Test Data:
Expected Status Stages:
- "Initializing detection..."
- "Loading preprocessed data..."
- "Analyzing file 1 of 10..."
- "Pattern matching in progress..."
- "Detecting cryptographic algorithms..."
- "Analyzing complete. Generating results..."
- "Detection completed successfully"
---
Expected Results:
Status messages clearly indicate current stage
Each stage is displayed as it occurs
Status text is descriptive and informative
User understands what system is doing at each stage
Status shows:
  - What's currently running (e.g., "Pattern matching")
  - What file is being processed
  - Current detection phase
Completion status is clearly marked
Final status shows: "Detection completed successfully"
Status remains visible throughout entire process
User can distinguish between "running" and "done"
Color coding or icons indicate status (optional):
  - In progress: Blue/spinner icon
  - Completed: Green/check icon
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
View Completed Detection Summary | ID: PROGRESS-003
---
Pre-conditions:
User is logged in
User has run detection to completion
Detection has finished successfully
User is viewing results screen
---
Steps to Follow:
1. Complete a full detection run
2. Observe final status and summary
3. Verify completion indicators
4. Check summary statistics
---
Test Data:
Case ID: CRYPTO-2024-001
Detection Status: Completed
Files Analyzed: 10
Findings: 8 cryptographic detections
---
Expected Results:
Progress bar shows 100% complete
Status displays: "Detection completed successfully"
Completion timestamp is shown (e.g., "Completed at 14:35:22")
Summary statistics are displayed:
  - "10 files analyzed"
  - "8 cryptographic findings detected"
  - "2 weak/deprecated algorithms flagged"
  - "Total execution time: 2 minutes 15 seconds"
Visual indicator shows completion (green check, success icon)
User clearly knows detection is finished
No ambiguity about completion state
Results are ready for review
Console shows completion message
User can navigate to detailed results
Summary is saved in work directory
User can export or review findings
Success message is prominent and clear
---
Actual Results:
---
Test Results:
---
