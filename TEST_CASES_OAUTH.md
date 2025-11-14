# OAuth Login Test Cases

## User Story 1: Google OAuth Login for Existing Users
**As a free user, I want to log in with Google so that I can access my workspace quickly**

---
Test Case #1.1
---
User Login with Google (Existing Account) | ID: 1-1
---
Pre-conditions:
User account exists in Supabase auth.users table
User has previously linked Google OAuth account
Google OAuth is configured in Supabase dashboard
User is on the login page
User is not currently authenticated
---
Steps to Follow:
1. Click on "Continue with Google" button
2. Browser opens with Google OAuth consent screen
3. Select Google account previously used for this app
4. Google redirects to callback URL (http://127.0.0.1:8750/auth/callback)
5. Authorization code is exchanged for session token
6. System checks user_roles table for existing role
---
Test Data:
Google Account: testuser@gmail.com
Expected User ID: Valid UUID from auth.users
Expected Role Tier: "free"
Callback Port: 8750
---
Expected Results:
User is authenticated successfully
Session token is stored in app.auth_token
User data is stored in app.current_user
User role is stored in app.current_user_role
User is redirected to landing page
Callback server shuts down cleanly
Browser shows "Sign-in successful. You can close this window."
---
Actual Results:
---
Test Results:
---

---
Test Case #1.2
---
User Login with Google (Timeout) | ID: 1-2
---
Pre-conditions:
User account exists
Google OAuth is configured
User is on the login page
---
Steps to Follow:
1. Click on "Continue with Google" button
2. Browser opens with Google OAuth consent screen
3. User does not complete the OAuth flow within 180 seconds
4. System times out waiting for callback
---
Test Data:
Timeout Duration: 180 seconds
Callback Port: 8750
---
Expected Results:
System returns error: "Timed out waiting for Google sign-in."
Callback server shuts down cleanly
User remains on login page
Error message is displayed to user
Authentication state remains unauthenticated
---
Actual Results:
---
Test Results:
---

---
Test Case #1.3
---
User Login with Google (User Denies Permission) | ID: 1-3
---
Pre-conditions:
User account exists
Google OAuth is configured
User is on the login page
---
Steps to Follow:
1. Click on "Continue with Google" button
2. Browser opens with Google OAuth consent screen
3. User clicks "Cancel" or "Deny" on Google consent screen
4. Google redirects to callback with error parameter
---
Test Data:
Error Parameter: access_denied
Callback URL: http://127.0.0.1:8750/auth/callback?error=access_denied
---
Expected Results:
System captures error from callback URL
Error message is returned to application
User remains on login page
No session token is created
User sees appropriate error message
---
Actual Results:
---
Test Results:
---

---
Test Case #1.4
---
User Login with Google (Network Failure) | ID: 1-4
---
Pre-conditions:
User account exists
Google OAuth is configured
User is on the login page
Network connection is unstable
---
Steps to Follow:
1. Click on "Continue with Google" button
2. OAuth start request is sent to Supabase
3. Network connection fails during request
4. Exception is caught by error handler
---
Test Data:
Expected Error: OAuth start failed exception
---
Expected Results:
System returns error: "OAuth start failed: [exception details]"
User remains on login page
No callback server is started
Error message is displayed to user
---
Actual Results:
---
Test Results:
---

---
Test Case #1.5
---
User Login with Google (Port Already in Use) | ID: 1-5
---
Pre-conditions:
User account exists
Google OAuth is configured
Port 8750 is already occupied by another process
User is on the login page
---
Steps to Follow:
1. Click on "Continue with Google" button
2. System attempts to start callback server on port 8750
3. Port is already in use, server start fails
---
Test Data:
Callback Port: 8750 (occupied)
---
Expected Results:
System returns error about port being in use
User remains on login page
Error message is displayed to user
Alternative solution suggested (close other apps or retry)
---
Actual Results:
---
Test Results:
---

---
Test Case #1.6
---
User Login with Google (Invalid OAuth Configuration) | ID: 1-6
---
Pre-conditions:
Google OAuth is NOT properly configured in Supabase
User is on the login page
---
Steps to Follow:
1. Click on "Continue with Google" button
2. System calls sign_in_with_oauth() with provider "google"
3. Supabase returns no OAuth URL
---
Test Data:
Provider: "google"
Expected OAuth URL: None
---
Expected Results:
System returns error: "No OAuth URL returned by Supabase (Google)"
User remains on login page
Error message is displayed
No browser window is opened
---
Actual Results:
---
Test Results:
---

## User Story 2: GitHub OAuth Login and Account Creation
**As a free user, I want to log in with GitHub so that I can create a new account and access my workspace**

---
Test Case #2.1
---
User Login with GitHub (Existing Account) | ID: 2-1
---
Pre-conditions:
User account exists in Supabase auth.users table
User has previously linked GitHub OAuth account
GitHub OAuth is configured in Supabase dashboard
User is on the login page
---
Steps to Follow:
1. Click on "Continue with GitHub" button
2. Browser opens with GitHub OAuth authorization screen
3. User clicks "Authorize" on GitHub
4. GitHub redirects to callback URL with authorization code
5. Code is exchanged for session token
6. System verifies user_roles table entry exists
---
Test Data:
GitHub Username: testuser123
Expected User ID: Valid UUID from auth.users
Expected Role Tier: "free"
Callback Port: 8750
---
Expected Results:
User is authenticated successfully
Session token is stored in app.auth_token
User data is stored in app.current_user
User role tier is "free"
User is redirected to landing page
Browser shows success message
---
Actual Results:
---
Test Results:
---

---
Test Case #2.2
---
User Login with GitHub (New Account Creation) | ID: 2-2
---
Pre-conditions:
User does NOT have an account in the system
GitHub OAuth is configured in Supabase dashboard
User has a valid GitHub account
User is on the login page
---
Steps to Follow:
1. Click on "Continue with GitHub" button
2. Browser opens with GitHub OAuth authorization screen
3. User authorizes the application
4. GitHub redirects to callback with authorization code
5. Supabase Auth creates new user in auth.users table
6. System calls ensure_role_row() to create user role
7. New entry is created in user_roles table with tier "free"
---
Test Data:
GitHub Username: newuser456
GitHub Email: newuser456@github.com
Expected Role Tier: "free"
Expected Profile Data: { "id": UUID, "tier": "free" }
---
Expected Results:
New user account is created in auth.users
New entry is created in user_roles table
User tier is set to "free" by default
User is authenticated with session token
User is redirected to landing page
User can immediately access workspace features
No additional registration forms are required
---
Actual Results:
---
Test Results:
---

---
Test Case #2.3
---
User Login with GitHub (Revoked App Authorization) | ID: 2-3
---
Pre-conditions:
User has previously authorized the app
User has revoked app authorization in GitHub settings
GitHub OAuth is configured
User attempts to log in
---
Steps to Follow:
1. Click on "Continue with GitHub" button
2. Browser opens with GitHub OAuth screen
3. GitHub shows authorization request (app was revoked)
4. User must re-authorize the application
5. User clicks "Authorize"
6. OAuth flow completes normally
---
Test Data:
GitHub Username: testuser123
Authorization Status: Previously revoked, now re-authorized
---
Expected Results:
User is prompted to re-authorize application
After authorization, login succeeds
User is authenticated successfully
User is redirected to landing page
---
Actual Results:
---
Test Results:
---

---
Test Case #2.4
---
User Login with GitHub (User Cancels Authorization) | ID: 2-4
---
Pre-conditions:
GitHub OAuth is configured
User is on the login page
---
Steps to Follow:
1. Click on "Continue with GitHub" button
2. Browser opens with GitHub OAuth authorization screen
3. User clicks "Cancel" or closes the browser window
4. GitHub redirects to callback with error parameter
---
Test Data:
Error Parameter: access_denied
Callback URL: http://127.0.0.1:8750/auth/callback?error=access_denied
---
Expected Results:
System captures error from callback
Error is displayed to user
User remains on login page
No account is created
No session token is generated
---
Actual Results:
---
Test Results:
---

---
Test Case #2.5
---
User Login with GitHub (Code Exchange Failure) | ID: 2-5
---
Pre-conditions:
GitHub OAuth is configured
User is on the login page
---
Steps to Follow:
1. Click on "Continue with GitHub" button
2. Browser completes GitHub OAuth authorization
3. Callback receives authorization code
4. System attempts to exchange code for session token
5. Code exchange fails (expired code, invalid code, etc.)
---
Test Data:
Authorization Code: expired_or_invalid_code
Expected Error: Code exchange failed
---
Expected Results:
System returns error: "Code exchange failed: [exception]"
User is not authenticated
User remains on login page
Error message is displayed
No account is created if this was first login
---
Actual Results:
---
Test Results:
---

---
Test Case #2.6
---
User Login with GitHub (Timeout During Authorization) | ID: 2-6
---
Pre-conditions:
GitHub OAuth is configured
User is on the login page
Default timeout is 180 seconds
---
Steps to Follow:
1. Click on "Continue with GitHub" button
2. Browser opens with GitHub OAuth screen
3. User does not complete authorization within 180 seconds
4. System times out waiting for callback
---
Test Data:
Timeout Duration: 180 seconds
---
Expected Results:
System returns error: "Timed out waiting for GitHub sign-in."
Callback server shuts down cleanly
User remains on login page
Error message is displayed
No partial account creation occurs
---
Actual Results:
---
Test Results:
---

## User Story 3: Automatic Account Creation on First OAuth Login
**As a free user, I want to create an account on first OAuth login so that I can start immediately without extra forms**

---
Test Case #3.1
---
Automatic Account Creation via Google OAuth (First Time) | ID: 3-1
---
Pre-conditions:
User does NOT exist in auth.users table
Google OAuth is configured in Supabase
User has a valid Google account
User is on the login page
---
Steps to Follow:
1. Click on "Continue with Google" button
2. Browser opens with Google OAuth consent screen
3. User selects Google account and grants permissions
4. Google redirects to callback with authorization code
5. Code is exchanged for session token
6. Supabase Auth automatically creates user in auth.users
7. System calls ensure_role_row(token, user_id)
8. New entry is created in user_roles: {"id": user_id, "tier": "free"}
9. System does NOT show additional registration forms
10. User is immediately redirected to landing page
---
Test Data:
Google Email: firsttime@gmail.com
Expected User ID: Auto-generated UUID
Expected Role Tier: "free"
Expected Behavior: No additional forms required
---
Expected Results:
New user is created in auth.users table
User ID is auto-generated
Email is pulled from Google account
User role entry is created with tier "free"
Session token is generated and stored
User is redirected to landing page immediately
No registration form is displayed
User can access workspace immediately
Profiles table may be populated with basic info
---
Actual Results:
---
Test Results:
---

---
Test Case #3.2
---
Automatic Account Creation via GitHub OAuth (First Time) | ID: 3-2
---
Pre-conditions:
User does NOT exist in auth.users table
GitHub OAuth is configured in Supabase
User has a valid GitHub account
User is on the login page
---
Steps to Follow:
1. Click on "Continue with GitHub" button
2. Browser opens with GitHub OAuth authorization screen
3. User authorizes application
4. GitHub redirects with authorization code
5. Code is exchanged for session token
6. Supabase Auth creates user in auth.users
7. System calls ensure_role_row(token, user_id)
8. New role entry created: {"id": user_id, "tier": "free"}
9. No additional forms are shown
10. User is redirected to landing page
---
Test Data:
GitHub Username: newcoder789
GitHub Email: newcoder789@users.noreply.github.com
Expected Role Tier: "free"
Expected Behavior: Immediate access, no forms
---
Expected Results:
New user account is created automatically
Email is pulled from GitHub account
User role is set to "free" tier
Session is established immediately
User is redirected to landing page without forms
User can access all free-tier features immediately
Username may be populated from GitHub username
Profile may include GitHub metadata
---
Actual Results:
---
Test Results:
---

---
Test Case #3.3
---
Role Row Creation on First OAuth Login | ID: 3-3
---
Pre-conditions:
User does NOT exist in the system
OAuth provider (Google or GitHub) is configured
User is on the login page
---
Steps to Follow:
1. Complete OAuth login flow (Google or GitHub)
2. Supabase creates user in auth.users
3. System calls ensure_role_row(token, user_id)
4. Function checks if role exists in user_roles table
5. Role does NOT exist (first login)
6. Function creates new entry: {"id": user_id, "tier": "free"}
7. Function returns role data to application
---
Test Data:
User ID: Auto-generated UUID
Initial Tier: "free"
Table: user_roles
---
Expected Results:
ensure_role_row() successfully creates role entry
Role tier is set to "free" by default
Role data is returned to application
Application stores role in app.current_user_role
User has access to free-tier features
No errors occur during role creation
---
Actual Results:
---
Test Results:
---

---
Test Case #3.4
---
Existing User Logs in with New OAuth Provider | ID: 3-4
---
Pre-conditions:
User account exists (created with email/password)
User has never used OAuth before
OAuth provider (Google) is configured
User is on the login page
---
Steps to Follow:
1. Click on "Continue with Google" button
2. Complete Google OAuth flow
3. Google email matches existing user email in auth.users
4. Supabase links OAuth identity to existing user
5. System calls ensure_role_row(token, user_id)
6. Role already exists in user_roles table
7. Function returns existing role data
---
Test Data:
Existing Email: existinguser@gmail.com
Existing User ID: UUID from auth.users
Existing Tier: "free" or "premium"
OAuth Provider: Google (newly linked)
---
Expected Results:
OAuth identity is linked to existing account
User is authenticated successfully
Existing role data is returned (not recreated)
User tier remains unchanged
User is redirected to landing page
No duplicate entries are created
User sees their existing workspace data
---
Actual Results:
---
Test Results:
---

---
Test Case #3.5
---
Account Creation Failure with Fallback Handling | ID: 3-5
---
Pre-conditions:
User does NOT exist in the system
OAuth provider is configured
User is on the login page
Database has temporary connectivity issues
---
Steps to Follow:
1. Complete OAuth login flow (Google or GitHub)
2. Supabase successfully creates user in auth.users
3. Session token is generated
4. System calls ensure_role_row(token, user_id)
5. Database connection fails during role creation
6. Exception is caught by error handler
---
Test Data:
User ID: Valid UUID
Expected Error: Database connection error
Fallback Tier: "free"
---
Expected Results:
System logs error about role creation failure
User is still authenticated (token exists)
Application may use default "free" tier as fallback
User can still access landing page
System may retry role creation on next request
Error is logged for admin review
User experience is minimally impacted
---
Actual Results:
---
Test Results:
---

---
Test Case #3.6
---
Email Conflict Between OAuth Providers | ID: 3-6
---
Pre-conditions:
User has account linked to Google OAuth
User attempts to log in with GitHub OAuth
Both OAuth accounts use same email address
User is on the login page
---
Steps to Follow:
1. Click on "Continue with GitHub" button
2. Complete GitHub OAuth flow
3. GitHub email matches existing user email (from Google)
4. Supabase links GitHub identity to existing user
5. User now has both Google and GitHub OAuth linked
6. System retrieves existing role from user_roles
---
Test Data:
Email: sharedmail@example.com
Existing Provider: Google
New Provider: GitHub
Expected Behavior: Account linking, not duplication
---
Expected Results:
GitHub OAuth is linked to existing account
No duplicate user is created
User can now log in with either Google or GitHub
User role and tier remain unchanged
User sees existing workspace data
Both OAuth identities appear in auth.identities
User is redirected to landing page
---
Actual Results:
---
Test Results:
---

---
Test Case #3.7
---
Profile Data Population on First OAuth Login | ID: 3-7
---
Pre-conditions:
User does NOT exist in the system
OAuth provider returns user metadata (name, avatar, etc.)
OAuth is configured in Supabase
User is on the login page
---
Steps to Follow:
1. Complete OAuth login flow (Google or GitHub)
2. OAuth provider returns user metadata
3. Supabase creates user in auth.users
4. System attempts to populate profiles table
5. Profile entry is created or updated with metadata
6. Data includes: username, full_name, avatar_url (if available)
---
Test Data:
Google Name: "John Doe"
GitHub Username: "johndoe_dev"
GitHub Avatar: "https://avatars.githubusercontent.com/u/123456"
Expected Profile Fields: id, username, full_name
---
Expected Results:
Profile entry is created in profiles table
Username is populated from OAuth metadata
Full name is populated if available
Additional metadata may be stored
Profile is linked to user ID
User can see their name/avatar in UI
All data is populated automatically
No manual profile setup is required
---
Actual Results:
---
Test Results:
---

---
Test Case #3.8
---
Immediate Workspace Access After First OAuth Login | ID: 3-8
---
Pre-conditions:
User does NOT exist in the system
OAuth is configured
User is on the login page
Landing page requires authentication
---
Steps to Follow:
1. Complete OAuth login flow (Google or GitHub)
2. Account is created automatically
3. Role is set to "free" tier
4. Session token is generated
5. User is redirected to landing page
6. Landing page checks authentication state
7. User is authenticated and authorized
8. Free-tier features are accessible immediately
---
Test Data:
Expected Tier: "free"
Expected Features: File upload, single-file scan, basic analysis
Expected Page: Landing page (workspace)
---
Expected Results:
User lands on workspace/landing page
User is fully authenticated
Free-tier features are immediately available
No additional setup screens are shown
User can upload files and start analysis
Navigation shows user as logged in
User role badge shows "Free" tier
User sees logout option in navigation
User does NOT see premium-only features
---
Actual Results:
---
Test Results:
---

## Summary

**Total Test Cases: 24**
- User Story 1 (Google Login): 6 test cases
- User Story 2 (GitHub Login): 6 test cases
- User Story 3 (Auto Account Creation): 8 test cases

**Coverage:**
- ✅ Positive scenarios (successful login/registration)
- ✅ Negative scenarios (errors, timeouts, failures)
- ✅ Edge cases (port conflicts, email conflicts, revoked auth)
- ✅ Error handling (network failures, invalid configs)
- ✅ Account linking scenarios
- ✅ Role/tier management
- ✅ Profile data population
- ✅ Immediate workspace access

**Test Execution Notes:**
1. Ensure Supabase OAuth providers are configured before testing
2. Verify redirect URLs are set correctly in OAuth apps
3. Test with both existing and new accounts
4. Monitor database for correct role/profile creation
5. Verify session tokens are stored and validated correctly
6. Check error messages are user-friendly
7. Ensure callback server shuts down cleanly after each test
8. Test timeout behavior with actual 180-second waits or mock timers
