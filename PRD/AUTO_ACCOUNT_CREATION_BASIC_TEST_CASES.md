# Basic Test Cases - Automatic Account Creation on First OAuth Login

## User Story
As a free user, I want to create an account on first OAuth login so that I can start immediately without extra forms.

---
Test Case #1
---
First Login via Google - Auto Account Creation | ID: AUTO-001
---
Pre-conditions:
User does NOT have an account in the system
Google OAuth is configured
User is on the login page
---
Steps to Follow:
1. Click "Continue with Google" button
2. Select Google account
3. Authorize the application
4. System creates account automatically
---
Test Data:
Google Email: newuser@gmail.com
Expected Account Tier: Free
Expected Behavior: No registration forms shown
---
Expected Results:
Account is created automatically
User role is set to "free"
User is immediately redirected to workspace
No additional forms or setup screens appear
User can start using the workspace immediately
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
First Login via GitHub - Auto Account Creation | ID: AUTO-002
---
Pre-conditions:
User does NOT have an account in the system
GitHub OAuth is configured
User is on the login page
---
Steps to Follow:
1. Click "Continue with GitHub" button
2. Authorize the application on GitHub
3. System creates account automatically
---
Test Data:
GitHub Username: newcoder123
GitHub Email: newcoder123@github.com
Expected Account Tier: Free
Expected Behavior: No registration forms shown
---
Expected Results:
Account is created automatically
User role is set to "free"
Profile populated with GitHub username
User is immediately redirected to workspace
No additional registration forms appear
User can access all free-tier features immediately
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Existing User Adds New OAuth Provider | ID: AUTO-003
---
Pre-conditions:
User already has account (created via email/password)
User has never used OAuth before
Google OAuth is configured
User is on the login page
---
Steps to Follow:
1. Click "Continue with Google" button
2. Select Google account with same email as existing account
3. Complete Google authorization
4. System links OAuth to existing account
---
Test Data:
Existing Email: existinguser@gmail.com
Existing Account Tier: Free
OAuth Provider: Google (newly linked)
---
Expected Results:
Google OAuth is linked to existing account
No new account is created (no duplication)
User is logged into existing account
User sees existing workspace data
User tier remains unchanged
No registration forms appear
User can now log in with either email/password or Google
---
Actual Results:
---
Test Results:
---
