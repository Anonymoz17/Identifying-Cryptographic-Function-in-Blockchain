# Basic Test Cases - Google OAuth Login

## User Story
As a free user, I want to log in with Google so that I can access my workspace quickly

---
Test Case #1
---
Successful Google Login (Existing User) | ID: GOOGLE-001
---
Pre-conditions:
User has an existing account
Google OAuth is configured
User is on the login page
---
Steps to Follow:
1. Click "Continue with Google" button
2. Select Google account
3. Complete Google authentication
---
Test Data:
Google Email: testuser@gmail.com
User Tier: Free
---
Expected Results:
User is logged in successfully
User is redirected to workspace/landing page
Session is established
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Google Login - User Cancels | ID: GOOGLE-002
---
Pre-conditions:
User has an existing account
Google OAuth is configured
User is on the login page
---
Steps to Follow:
1. Click "Continue with Google" button
2. Google consent screen appears
3. User clicks "Cancel" or closes window
---
Test Data:
Expected Error: User denied access
---
Expected Results:
User remains on login page
Error message is displayed
No session is created
User is not logged in
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
First-Time Google Login (Account Creation) | ID: GOOGLE-003
---
Pre-conditions:
User does NOT have an account
Google OAuth is configured
User is on the login page
---
Steps to Follow:
1. Click "Continue with Google" button
2. Select Google account
3. Authorize the application
---
Test Data:
Google Email: newuser@gmail.com
Expected Tier: Free
---
Expected Results:
New account is created automatically
User is logged in
User role is set to "free"
User is redirected to workspace
No additional forms are required
---
Actual Results:
---
Test Results:
---
