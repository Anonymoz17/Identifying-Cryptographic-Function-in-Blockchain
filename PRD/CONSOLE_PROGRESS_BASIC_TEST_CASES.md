# Basic Test Cases - View Console/Progress During Preprocessing

## User Story
As a free user, I want to view console/progress during preprocessing so that I can see what the system is doing.

---
Test Case #1
---
Console Displays Preprocessing Progress | ID: CONSOLE-001
---
Pre-conditions:
User is logged in
User has completed all setup steps
User has started preprocessing
Console/progress panel is visible in UI
---
Steps to Follow:
1. Click "Start Preprocessing" button
2. Observe console/progress panel
3. Watch progress updates during preprocessing
4. Verify all processing steps are displayed
---
Test Data:
Folder: Contains 10 blockchain files
Expected Console Output: File processing status, progress percentage
User Tier: Free
---
Expected Results:
Console panel is visible during preprocessing
Progress updates are displayed in real-time
Console shows current file being processed
Progress percentage or progress bar is displayed (e.g., "30% complete")
Status messages appear: "Processing file 3 of 10"
Each file processed is logged in console
Console shows timestamps for each step (optional)
User can clearly see what the system is doing
Console is readable and well-formatted
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Console Shows Detailed Processing Steps | ID: CONSOLE-002
---
Pre-conditions:
User is logged in
Preprocessing is in progress
Console panel is visible
---
Steps to Follow:
1. Start preprocessing
2. Observe detailed console messages
3. Verify different processing stages are logged
---
Test Data:
Expected Console Messages:
- "Starting preprocessing..."
- "Reading files from folder..."
- "Processing file: contract.sol"
- "Analyzing code structure..."
- "Extracting functions..."
- "Preprocessing completed"
---
Expected Results:
Console displays detailed step-by-step messages
Each preprocessing stage is clearly logged
Messages are descriptive and informative
User understands what system is doing at each step
Console updates automatically as processing continues
No messages are missed or skipped
Console output helps user track progress
Technical details are shown (file names, operations)
Console provides transparency into system operations
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Console Displays Errors and Warnings | ID: CONSOLE-003
---
Pre-conditions:
User is logged in
User has started preprocessing
Selected folder contains problematic files (invalid format, corrupted, etc.)
Console panel is visible
---
Steps to Follow:
1. Start preprocessing with folder containing some invalid files
2. Observe console output when errors occur
3. Verify errors and warnings are clearly displayed
---
Test Data:
Folder Contents:
- 8 valid blockchain files
- 2 invalid/corrupted files
Expected Console Output: Error messages for invalid files
---
Expected Results:
Console displays normal processing for valid files
Console shows warnings/errors for problematic files
Error messages are clear and descriptive
Example: "Warning: Unable to process file 'corrupted.sol' - invalid format"
Errors are highlighted or color-coded (red text, warning icon)
Processing continues with remaining valid files
Final summary shows: "8 files processed successfully, 2 files skipped"
User understands which files had issues
User can identify and fix problematic files
Console helps with troubleshooting
System doesn't crash on errors
---
Actual Results:
---
Test Results:
---
