# Basic Test Cases - Work Directory (Case Workspace) Setup

## User Story
As a free user, I want to set a work directory (case workspace) so that all logs and outputs are saved in one place.

---
Test Case #1
---
Successful Work Directory Setup | ID: WORKSPACE-001
---
Pre-conditions:
User is logged in
User is on Setup page
User has selected a folder for analysis
---
Steps to Follow:
1. Click "Set Work Directory" or "Choose Workspace" button
2. File picker/dialog opens
3. Navigate to desired location for workspace
4. Select or create a folder for the workspace
5. Click "Select" to confirm
---
Test Data:
Workspace Path: /path/to/my/workspace
User Tier: Free
Expected Behavior: All logs and outputs saved to this location
---
Expected Results:
Work directory is set successfully
Selected path is displayed in UI
System creates workspace folder if it doesn't exist
Confirmation message: "Workspace set to [path]"
All subsequent logs are saved to this directory
All analysis outputs are saved to this directory
User can proceed with analysis
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Set Work Directory to Read-Only Location | ID: WORKSPACE-002
---
Pre-conditions:
User is logged in
User is on Setup page
User attempts to set workspace to protected/read-only location
---
Steps to Follow:
1. Click "Set Work Directory" button
2. Navigate to a read-only or protected folder (e.g., system directory)
3. Select the read-only folder
4. Attempt to confirm selection
---
Test Data:
Workspace Path: /System/read-only/folder (or C:\Windows\System32)
Expected Behavior: Error message about permissions
---
Expected Results:
System detects insufficient write permissions
Error message is displayed: "Cannot write to this location. Please choose a different folder."
Work directory is NOT set
User is prompted to select a different location
User can retry with a valid location
No crashes or system errors occur
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Change Existing Work Directory | ID: WORKSPACE-003
---
Pre-conditions:
User is logged in
User has already set a work directory
Work directory contains previous logs and outputs
User wants to change to a new location
---
Steps to Follow:
1. Current workspace is displayed: /path/to/old/workspace
2. Click "Change Work Directory" or "Set Work Directory" button
3. Select a new folder location
4. Confirm new workspace selection
---
Test Data:
Old Workspace: /path/to/old/workspace
New Workspace: /path/to/new/workspace
Expected Behavior: Workspace location is updated
---
Expected Results:
New work directory is set successfully
UI updates to show new workspace path
Confirmation message: "Workspace changed to [new path]"
New logs and outputs are saved to new location
Previous workspace data remains intact (not deleted)
User can still access old workspace manually if needed
System doesn't lose or corrupt previous data
---
Actual Results:
---
Test Results:
---
