# Basic Test Cases - Load Case

## User Story
As a free user, I want to load a case so that the detector screen is populated with my previously prepared input.

---
Test Case #1
---
Load Existing Case Successfully | ID: LOADCASE-001
---
Pre-conditions:
User is logged in
User has previously created and preprocessed a case
Case ID exists: "CRYPTO-2024-001"
Case has completed preprocessing
User is on the detector or case management screen
---
Steps to Follow:
1. Navigate to "Load Case" or "Open Case" section
2. Enter Case ID: "CRYPTO-2024-001" or select from list
3. Click "Load" or "Open" button
4. System retrieves case data
5. Detector screen is populated with case data
---
Test Data:
Case ID: CRYPTO-2024-001
Case Status: Preprocessing completed
Work Directory: /path/to/workspace/CRYPTO-2024-001
---
Expected Results:
Case is loaded successfully
Detector screen is populated with preprocessed data
All previously prepared input files are loaded
Work directory is set to case workspace
Console shows: "Case CRYPTO-2024-001 loaded successfully"
Case metadata is displayed (Case ID, folder, work directory)
User can immediately start detection analysis
Preprocessing results are available
User doesn't need to re-preprocess
All previous case settings are restored
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Load Non-Existent Case | ID: LOADCASE-002
---
Pre-conditions:
User is logged in
User is on the load case screen
Case ID entered does NOT exist in the system
---
Steps to Follow:
1. Navigate to "Load Case" section
2. Enter non-existent Case ID: "INVALID-CASE-999"
3. Click "Load" button
4. System searches for the case
---
Test Data:
Case ID: INVALID-CASE-999 (does not exist)
Expected Behavior: Error message
---
Expected Results:
System detects case does not exist
Error message is displayed: "Case not found. Please check the Case ID and try again."
Detector screen is NOT populated
No data is loaded
User remains on load case screen
User can retry with a different Case ID
User can view list of available cases (if feature exists)
System remains stable, no crashes
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Load Case That Was Not Fully Preprocessed | ID: LOADCASE-003
---
Pre-conditions:
User is logged in
User previously started a case but cancelled preprocessing
Case ID exists: "CRYPTO-2024-002"
Case preprocessing was incomplete/cancelled
User attempts to load the incomplete case
---
Steps to Follow:
1. Navigate to "Load Case" section
2. Enter Case ID: "CRYPTO-2024-002"
3. Click "Load" button
4. System checks case preprocessing status
---
Test Data:
Case ID: CRYPTO-2024-002
Case Status: Preprocessing incomplete (cancelled at 40%)
Expected Behavior: Warning or error about incomplete preprocessing
---
Expected Results:
System detects preprocessing is incomplete
Warning message is displayed: "This case has incomplete preprocessing. Please complete preprocessing before detection."
User is given options:
  - Continue preprocessing from where it stopped (if supported)
  - Restart preprocessing
  - Cancel and choose different case
Detector screen is NOT populated with incomplete data
User cannot start detection with incomplete preprocessing
Case workspace is accessible but flagged as incomplete
User is guided to complete preprocessing first
System prevents analysis with incomplete data
---
Actual Results:
---
Test Results:
---
