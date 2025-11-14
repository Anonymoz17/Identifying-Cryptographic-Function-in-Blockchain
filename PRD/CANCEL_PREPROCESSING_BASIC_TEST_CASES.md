# Basic Test Cases - Cancel Preprocessing

## User Story
As a free user, I want to cancel preprocessing so that I can stop if I picked the wrong input.

---
Test Case #1
---
Cancel Preprocessing in Progress | ID: CANCEL-001
---
Pre-conditions:
User is logged in
User has started preprocessing
Preprocessing is currently running (e.g., 40% complete)
Cancel button is visible and enabled
---
Steps to Follow:
1. Start preprocessing with selected folder
2. Wait until preprocessing is partially complete (e.g., processing file 4 of 10)
3. Click "Cancel" or "Stop Preprocessing" button
4. Observe system response
---
Test Data:
Preprocessing Progress: 40% complete (4 of 10 files processed)
Expected Behavior: Preprocessing stops immediately
---
Expected Results:
Preprocessing stops successfully
Cancellation confirmation message: "Preprocessing cancelled"
Console shows: "Preprocessing stopped by user"
Current file processing is terminated gracefully
Progress bar/indicator stops updating
Partial logs are saved to work directory
No file corruption occurs
User is returned to setup/preprocessing page
User can restart preprocessing with different inputs
System remains stable, no crashes
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Cancel Preprocessing at Start | ID: CANCEL-002
---
Pre-conditions:
User is logged in
User has just started preprocessing
Preprocessing has just begun (0-5% complete)
Cancel button is visible
---
Steps to Follow:
1. Click "Start Preprocessing" button
2. Immediately click "Cancel" button (within first few seconds)
3. Observe system response
---
Test Data:
Preprocessing Progress: Just started (0-5%)
Expected Behavior: Quick cancellation
---
Expected Results:
Preprocessing stops immediately
No files or minimal files are processed
Cancellation message is displayed
Console shows cancellation status
Work directory may be empty or contain minimal logs
No errors occur from early cancellation
User can modify inputs and restart
Cancel operation completes quickly
System handles early cancellation gracefully
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Restart Preprocessing After Cancellation | ID: CANCEL-003
---
Pre-conditions:
User is logged in
User cancelled a previous preprocessing operation
User realized wrong folder was selected
User has now selected the correct folder
---
Steps to Follow:
1. Cancel ongoing preprocessing (from wrong folder)
2. Change folder selection to correct folder
3. Click "Start Preprocessing" again
4. Verify preprocessing runs with new inputs
---
Test Data:
First Folder: /path/to/wrong/folder (cancelled)
Second Folder: /path/to/correct/folder (new attempt)
Expected Behavior: Fresh start with new inputs
---
Expected Results:
User can change folder after cancellation
Previous preprocessing data is cleared or marked as cancelled
New preprocessing starts with correct folder
Console shows fresh preprocessing logs
Progress starts from 0%
No interference from cancelled preprocessing
Cancelled preprocessing logs are preserved separately (optional)
New preprocessing completes successfully
Work directory contains logs from new preprocessing
User successfully recovers from wrong input selection
---
Actual Results:
---
Test Results:
---
