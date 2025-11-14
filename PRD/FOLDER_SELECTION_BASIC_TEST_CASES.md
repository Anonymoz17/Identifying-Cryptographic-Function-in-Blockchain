# Basic Test Cases - Folder Selection for Preprocessing

## User Story
As a free user, I want to select a folder so that I can preprocess it for analysis.

---
Test Case #1
---
Successful Folder Selection | ID: FOLDER-001
---
Pre-conditions:
User is logged in
User is on Setup or Detector page
User has access to file system
---
Steps to Follow:
1. Click "Select Folder" or "Browse" button
2. File picker/dialog opens
3. Navigate to desired folder location
4. Select folder containing files to analyze
5. Click "Open" or "Select" to confirm
---
Test Data:
Folder Path: /path/to/blockchain/contracts
Folder Contents: Multiple .sol or blockchain files
User Tier: Free
---
Expected Results:
File picker opens successfully
User can navigate file system
Selected folder path is displayed in UI
Folder is accepted for preprocessing
System shows confirmation of folder selection
User can proceed to next step (preprocessing/analysis)
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Select Empty Folder | ID: FOLDER-002
---
Pre-conditions:
User is logged in
User is on Setup or Detector page
---
Steps to Follow:
1. Click "Select Folder" button
2. Navigate to an empty folder (no files inside)
3. Select the empty folder
4. Attempt to proceed with preprocessing
---
Test Data:
Folder Path: /path/to/empty/folder
Folder Contents: 0 files
Expected Behavior: Error message or warning
---
Expected Results:
System detects folder is empty
Error message is displayed: "No files found in selected folder"
User cannot proceed with empty folder
User is prompted to select a different folder
No preprocessing is attempted
System remains stable
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Cancel Folder Selection | ID: FOLDER-003
---
Pre-conditions:
User is logged in
User is on Setup or Detector page
No folder has been selected yet
---
Steps to Follow:
1. Click "Select Folder" button
2. File picker dialog opens
3. User clicks "Cancel" or closes dialog without selecting
---
Test Data:
Expected Behavior: Return to previous state
---
Expected Results:
File picker closes without errors
User returns to Setup/Detector page
No folder is selected
Previous state is maintained
User can click "Select Folder" again to retry
System remains stable
No error messages are shown
---
Actual Results:
---
Test Results:
---
