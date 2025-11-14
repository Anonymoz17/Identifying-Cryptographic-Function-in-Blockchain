# Test Cases - User Logout

## User Story
As a free user, I want to log out so that I can securely end my session.

---
Test Case #1
---
Successful Logout from Workspace | ID: LOGOUT-001
---
Pre-conditions:
User is logged in (authenticated)
User is on the workspace/landing page
Session token exists
User role is loaded
---
Steps to Follow:
1. Click on "Logout" button or menu option
2. System clears session token
3. System clears user data from app state
4. System redirects to login page
---
Test Data:
User Email: testuser@gmail.com
User Tier: Free
Session Token: Valid token exists
---
Expected Results:
Session token is cleared from app.auth_token
User data is cleared from app.current_user
User role is cleared from app.current_user_role
User is redirected to login page
User cannot access workspace without logging in again
Navigation shows logged-out state
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Logout Clears Local Session Data | ID: LOGOUT-002
---
Pre-conditions:
User is logged in via OAuth (Google or GitHub)
User has active session with stored token
User is on any page in the application
---
Steps to Follow:
1. Verify user is authenticated
2. Click "Logout" button
3. Check that session data is cleared
4. Attempt to access workspace page
---
Test Data:
Login Method: Google OAuth
Session Storage: Token stored in application
---
Expected Results:
All session data is cleared from application state
Auth token is removed
User data is removed
User role data is removed
Attempting to access workspace redirects to login
Browser back button does not restore session
User must re-authenticate to access workspace
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Logout from Multiple Pages | ID: LOGOUT-003
---
Pre-conditions:
User is logged in
User navigates to different pages in application
User is on a page other than landing page
---
Steps to Follow:
1. Navigate to various pages while logged in
2. From any page, click "Logout" button
3. Verify logout works from any location
---
Test Data:
Pages to test: Landing page, settings, analysis page
---
Expected Results:
Logout button is accessible from all pages
Logout works correctly regardless of current page
User is redirected to login page
Session is terminated completely
All user data is cleared
---
Actual Results:
---
Test Results:
---

---
Test Case #4
---
Logout After Session Timeout | ID: LOGOUT-004
---
Pre-conditions:
User was logged in
Session has expired or timed out
User attempts to logout
---
Steps to Follow:
1. User session expires (manually expire or wait)
2. User clicks "Logout" button
3. System handles logout gracefully
---
Test Data:
Session State: Expired
Expected Behavior: Graceful logout handling
---
Expected Results:
Logout completes without errors
User is redirected to login page
No error messages are shown
Session cleanup happens normally
User can log in again immediately
---
Actual Results:
---
Test Results:
---

---
Test Case #5
---
Logout and Re-login | ID: LOGOUT-005
---
Pre-conditions:
User is logged in
User has been working in workspace
---
Steps to Follow:
1. Click "Logout" button
2. Verify redirection to login page
3. Log in again using the same credentials
4. Verify workspace is accessible
---
Test Data:
Login Method: Google OAuth
User Email: testuser@gmail.com
---
Expected Results:
First logout is successful
User is redirected to login page
User can log in again immediately
New session is created with fresh token
User can access workspace again
Previous session data does not interfere
User's saved data is still available (not deleted)
---
Actual Results:
---
Test Results:
---

---
Test Case #6
---
Logout Prevents Unauthorized Access | ID: LOGOUT-006
---
Pre-conditions:
User is logged in
User is on workspace page
---
Steps to Follow:
1. Copy the current workspace URL
2. Click "Logout" button
3. User is redirected to login page
4. Paste the workspace URL and try to access it directly
---
Test Data:
Workspace URL: /landing or /workspace
Session State: Logged out
---
Expected Results:
Direct URL access is blocked after logout
User is redirected to login page
Error message may appear: "Please log in to continue"
No workspace data is displayed
User must authenticate to access the page
Session protection is working correctly
---
Actual Results:
---
Test Results:
---

---
Test Case #7
---
Logout in Web Application (Browser Session) | ID: LOGOUT-007
---
Pre-conditions:
User is logged in via web application
Browser has stored session data
Supabase session is active
---
Steps to Follow:
1. Click "Logout" button in web app
2. System calls Supabase signOut()
3. Verify session is cleared from browser storage
4. Check navigation updates to logged-out state
---
Test Data:
Platform: Web application (React/Vite)
Session Storage: localStorage/sessionStorage
Supabase Session: Active
---
Expected Results:
Supabase signOut() is called successfully
Session cleared from browser storage
Auth context is updated (user = null)
Navigation shows logged-out state
User is shown login/signup options
Protected routes redirect to login
No cached user data remains
---
Actual Results:
---
Test Results:
---

---
Test Case #8
---
Logout in Desktop Application | ID: LOGOUT-008
---
Pre-conditions:
User is logged in via desktop application
App state has auth_token, current_user, current_user_role
User is on landing page
---
Steps to Follow:
1. Click "Logout" button or menu option
2. System clears app.auth_token
3. System clears app.current_user
4. System clears app.current_user_role
5. User is switched to login page
---
Test Data:
Platform: Desktop application (Python/Flet)
Auth State: Fully authenticated
---
Expected Results:
app.auth_token is set to None
app.current_user is set to None
app.current_user_role is set to None
Page switches to "login" page
Login form is displayed
User must re-authenticate to access features
Previous session cannot be restored
---
Actual Results:
---
Test Results:
---

---
Test Case #9
---
Logout Confirmation (Optional Feature) | ID: LOGOUT-009
---
Pre-conditions:
User is logged in
User has unsaved work (if applicable)
Logout confirmation is enabled
---
Steps to Follow:
1. Click "Logout" button
2. Confirmation dialog appears (if implemented)
3. User confirms logout
4. Logout proceeds
---
Test Data:
Confirmation Dialog: "Are you sure you want to logout?"
Options: Confirm / Cancel
---
Expected Results:
If confirmation dialog exists:
- Dialog appears with clear message
- User can cancel and stay logged in
- User can confirm and logout completes
- Session is only cleared after confirmation

If no confirmation dialog:
- Logout happens immediately
- Session is cleared without prompt
---
Actual Results:
---
Test Results:
---

---
Test Case #10
---
Multiple Logout Clicks (Edge Case) | ID: LOGOUT-010
---
Pre-conditions:
User is logged in
User is on workspace page
---
Steps to Follow:
1. Click "Logout" button
2. Quickly click "Logout" button multiple times
3. Observe system behavior
---
Test Data:
Expected Behavior: Graceful handling of multiple clicks
---
Expected Results:
Logout process handles multiple clicks gracefully
No errors are thrown
Logout completes successfully
User is redirected to login page only once
Session cleanup happens correctly
No duplicate logout API calls cause issues
System remains stable
---
Actual Results:
---
Test Results:
---

## Summary

**Total Test Cases: 10**

**Coverage:**
- ✅ Basic logout functionality
- ✅ Session data cleanup
- ✅ Logout from different pages
- ✅ Edge cases (timeout, multiple clicks)
- ✅ Security (preventing unauthorized access)
- ✅ Platform-specific logout (web vs desktop)
- ✅ Re-login after logout
- ✅ Session storage cleanup
- ✅ Browser/app state management
- ✅ Error handling and graceful degradation

**Test Execution Notes:**
1. Test on both web and desktop applications
2. Verify all session data is cleared properly
3. Test with different login methods (OAuth, email/password)
4. Ensure logout works from all pages in the application
5. Verify security: logged-out users cannot access protected pages
6. Test edge cases: expired sessions, multiple clicks, network failures
7. Verify re-login works correctly after logout
8. Check that user data is preserved (not deleted) after logout
