# Basic Test Cases - Start Preprocessing

## User Story
As a free user, I want to start preprocessing so that the system prepares my input for detection.

---
Test Case #1
---
Successful Preprocessing Start | ID: PREPROCESS-001
---
Pre-conditions:
User is logged in
User has selected a folder with files
User has set a work directory
User has entered a Case ID
User is on Setup/Preprocessing page
---
Steps to Follow:
1. Click "Start Preprocessing" button
2. System validates all required inputs are set
3. Preprocessing begins
4. Observe preprocessing progress
---
Test Data:
Folder: /path/to/blockchain/contracts (contains 10 .sol files)
Work Directory: /path/to/workspace
Case ID: CRYPTO-2024-001
User Tier: Free
---
Expected Results:
Preprocessing starts successfully
Progress indicator/bar is displayed
System reads files from selected folder
Files are prepared for detection analysis
Logs are saved to work directory
Status updates are shown to user (e.g., "Processing file 1 of 10")
Preprocessing completes without errors
User receives confirmation: "Preprocessing completed successfully"
User can proceed to detection step
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Start Preprocessing Without Required Setup | ID: PREPROCESS-002
---
Pre-conditions:
User is logged in
User has NOT completed all required setup steps
Missing: folder selection OR work directory OR Case ID
---
Steps to Follow:
1. Navigate to preprocessing page
2. Click "Start Preprocessing" button
3. System validates setup requirements
---
Test Data:
Folder: Not selected
Work Directory: Set
Case ID: Not entered
Expected Behavior: Validation error
---
Expected Results:
System detects missing required inputs
Error message is displayed: "Please complete all setup steps before preprocessing"
Specific missing items are highlighted or listed
Preprocessing does NOT start
User is guided to complete missing steps
"Start Preprocessing" button may be disabled
User must complete setup before proceeding
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Cancel Preprocessing in Progress | ID: PREPROCESS-003
---
Pre-conditions:
User is logged in
All setup steps are completed
Preprocessing has started
Preprocessing is currently in progress (not finished)
---
Steps to Follow:
1. Preprocessing is running (e.g., 30% complete)
2. Click "Cancel" or "Stop" button
3. System stops preprocessing
---
Test Data:
Preprocessing Progress: 30% complete (3 of 10 files processed)
Expected Behavior: Graceful cancellation
---
Expected Results:
Preprocessing stops immediately or after current file
Cancellation confirmation is displayed
Partial results are saved (if applicable)
Work directory contains logs up to cancellation point
No file corruption occurs
User is returned to setup/preprocessing page
User can restart preprocessing if desired
System state remains stable
No errors or crashes occur
---
Actual Results:
---
Test Results:
---
