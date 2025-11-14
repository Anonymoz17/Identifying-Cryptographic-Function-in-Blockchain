# Basic Test Cases - Open Setup Page

## User Story
As a free user, I want to open the setup page so that I can prepare my input and workspace.

---
Test Case #1
---
Open Setup Page from Landing Page | ID: SETUP-001
---
Pre-conditions:
User is logged in
User is on the landing page
Setup navigation option is visible
User has not started any case yet
---
Steps to Follow:
1. User lands on landing page after login
2. Locate "Setup" button/link/option
3. Click on "Setup" navigation option
4. Observe navigation to Setup page
---
Test Data:
Current Page: Landing page
Destination: Setup page
User Tier: Free
---
Expected Results:
User is navigated to Setup page successfully
Setup page loads completely
URL changes to reflect Setup page (e.g., /setup)
Setup page displays all required sections:
  - Folder selection option
  - Work directory/workspace setup
  - Case ID input field
  - Preprocessing controls
Page layout is clear and organized
User can see all setup options available to free tier
Navigation maintains logged-in state
Back button returns to landing page
User can begin preparing input and workspace
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Open Setup Page for New Case | ID: SETUP-002
---
Pre-conditions:
User is logged in
User has previously worked on other cases
User wants to create a new case
User is on any page in the application
---
Steps to Follow:
1. Navigate to main menu or navigation bar
2. Click "Setup" or "New Case Setup" option
3. Setup page opens for new case creation
4. Verify all fields are empty/reset for new case
---
Test Data:
Previous Case: CRYPTO-2024-001 (already exists)
Expected State: Fresh setup for new case
User Tier: Free
---
Expected Results:
Setup page opens successfully
All input fields are empty/reset:
  - Folder selection: Not selected
  - Work directory: Not set
  - Case ID: Empty input field
  - No preprocessing in progress
Setup page is ready for new case configuration
User can enter new case details
Previous case data is not displayed
Page clearly indicates "New Case Setup" or similar
User can configure all required setup parameters
Setup page provides guidance for required fields
User can proceed step-by-step through setup process
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Open Setup Page to Modify Existing Case | ID: SETUP-003
---
Pre-conditions:
User is logged in
User has an existing case with incomplete setup
Case ID exists but preprocessing not started
User wants to complete or modify setup
---
Steps to Follow:
1. Navigate to "Setup" or "Edit Case Setup"
2. Select existing case or continue from where left off
3. Setup page opens with partially filled information
4. Verify existing data is preserved and editable
---
Test Data:
Existing Case: CRYPTO-2024-005
Previous Setup:
  - Folder: /path/to/contracts (already selected)
  - Work directory: Not set yet
  - Case ID: CRYPTO-2024-005
  - Preprocessing: Not started
---
Expected Results:
Setup page opens with existing case data
Previously entered information is displayed:
  - Folder selection shows: /path/to/contracts
  - Case ID shows: CRYPTO-2024-005
Empty/incomplete fields are ready for input:
  - Work directory: Empty, ready to be set
User can modify existing selections if needed
User can complete incomplete setup steps
Setup validation shows which fields are complete/incomplete
Progress indicator shows setup completion status (optional)
User can change folder selection if mistake was made
User can update Case ID if needed
User can set work directory to complete setup
After completing all fields, user can proceed to preprocessing
No data loss occurs when reopening setup page
---
Actual Results:
---
Test Results:
---
