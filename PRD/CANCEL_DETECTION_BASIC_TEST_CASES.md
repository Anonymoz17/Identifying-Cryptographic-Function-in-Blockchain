# Basic Test Cases - Cancel Detection

## User Story
As a free user, I want to cancel detection so that I can stop a long or mistaken run.

---
Test Case #1
---
Cancel Detection in Progress | ID: CANCELDET-001
---
Pre-conditions:
User is logged in
User has loaded a case with preprocessed files
User has started static analysis/detection
Detection is currently running (e.g., 50% complete)
Cancel button is visible and enabled
---
Steps to Follow:
1. Click "Run Static Analysis" or "Start Detection" button
2. Detection process begins and runs for some time
3. Observe progress (e.g., analyzing file 5 of 10)
4. Click "Cancel Detection" or "Stop" button
5. Observe system response
---
Test Data:
Case ID: CRYPTO-2024-001
Detection Progress: 50% complete (5 of 10 files analyzed)
Expected Behavior: Detection stops immediately
---
Expected Results:
Detection stops successfully
Cancellation confirmation message: "Detection cancelled"
Console shows: "Detection stopped by user"
Current file analysis is terminated gracefully
Progress indicator stops updating
Partial results are saved (if applicable)
No system crashes or errors occur
User is returned to detector screen
User can restart detection or load different case
Results screen shows partial findings (optional)
Work directory contains logs up to cancellation point
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Cancel Long-Running Detection Early | ID: CANCELDET-002
---
Pre-conditions:
User is logged in
User has started detection on a large dataset
User realizes they selected wrong case or settings
Detection has just started (0-10% complete)
---
Steps to Follow:
1. Start detection on large case with many files
2. Realize mistake (wrong case or wrong settings)
3. Immediately click "Cancel Detection" button
4. System stops detection quickly
---
Test Data:
Case ID: CRYPTO-2024-005 (large dataset, 100+ files)
Detection Progress: Just started (1-3% complete)
Expected Behavior: Quick cancellation
---
Expected Results:
Detection stops immediately
Minimal processing has occurred
Cancellation message is displayed promptly
Console shows: "Detection cancelled at 2%"
No or minimal results are saved
User can select correct case/settings
User can restart detection with correct inputs
Early cancellation completes quickly (within seconds)
System resources are freed immediately
No background processes continue running
User interface returns to ready state
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Restart Detection After Cancellation | ID: CANCELDET-003
---
Pre-conditions:
User is logged in
User cancelled a previous detection run
User has corrected the mistake (loaded correct case or fixed settings)
User is ready to run detection again
---
Steps to Follow:
1. Cancel ongoing detection (wrong case selected)
2. Load the correct case
3. Verify correct case is loaded
4. Click "Run Static Analysis" again
5. Observe new detection run
---
Test Data:
First Run: Case CRYPTO-2024-006 (cancelled)
Second Run: Case CRYPTO-2024-001 (correct case)
Expected Behavior: Fresh detection run with correct inputs
---
Expected Results:
User can load different case after cancellation
Previous detection data is cleared or archived
New detection starts fresh from 0%
Console shows fresh detection logs
No interference from cancelled detection
Progress indicator starts from beginning
Detection runs on correct case/inputs
Detection completes successfully
Results reflect only the correct case
Cancelled run logs are preserved separately (optional)
Work directory shows both runs clearly separated
User successfully recovers from mistake
System handles multiple detection runs correctly
---
Actual Results:
---
Test Results:
---
