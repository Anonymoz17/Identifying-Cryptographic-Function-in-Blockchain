# Basic Test Cases - Case ID Entry

## User Story
As a free user, I want to enter a Case ID so that I can identify and reopen this case later.

---
Test Case #1
---
Enter Valid Case ID for New Case | ID: CASEID-001
---
Pre-conditions:
User is logged in
User is on Setup page
User has set work directory
User is creating a new case
---
Steps to Follow:
1. Locate "Case ID" input field
2. Enter a unique Case ID (e.g., "CRYPTO-2024-001")
3. Click "Save" or "Continue" button
4. System validates and saves Case ID
---
Test Data:
Case ID: CRYPTO-2024-001
User Tier: Free
Expected Behavior: Case ID is saved and associated with workspace
---
Expected Results:
Case ID is accepted and saved
Confirmation message: "Case ID saved successfully"
Case ID is displayed in UI
Case can be identified by this ID
User can proceed with analysis
Case ID is stored for future reopening
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Enter Duplicate Case ID | ID: CASEID-002
---
Pre-conditions:
User is logged in
User has previously created a case with ID "CRYPTO-2024-001"
User is creating a new case
---
Steps to Follow:
1. Enter Case ID that already exists: "CRYPTO-2024-001"
2. Click "Save" or "Continue" button
3. System checks for duplicate Case ID
---
Test Data:
Case ID: CRYPTO-2024-001 (already exists)
Expected Behavior: Error message about duplicate ID
---
Expected Results:
System detects duplicate Case ID
Error message is displayed: "Case ID already exists. Please use a different ID."
Case ID is NOT saved
User is prompted to enter a different Case ID
User can retry with a unique ID
No data is overwritten or lost
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Reopen Existing Case Using Case ID | ID: CASEID-003
---
Pre-conditions:
User is logged in
User has previously created case with ID "CRYPTO-2024-001"
Case data and logs are saved in workspace
User wants to reopen the case
---
Steps to Follow:
1. Navigate to "Open Case" or "Load Case" section
2. Enter existing Case ID: "CRYPTO-2024-001"
3. Click "Open" or "Load" button
4. System retrieves case data
---
Test Data:
Case ID: CRYPTO-2024-001 (existing case)
Expected Behavior: Case is reopened with all previous data
---
Expected Results:
System finds the case by Case ID
Case is loaded successfully
All previous logs and outputs are accessible
Work directory is set to case workspace
User can view previous analysis results
User can continue working on the case
Case metadata is displayed correctly
No data is lost or corrupted
---
Actual Results:
---
Test Results:
---
