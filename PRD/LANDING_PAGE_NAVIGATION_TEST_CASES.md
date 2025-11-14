# Test Cases - Landing Page Navigation After Login

## User Story
As a free user, I want to land on the Landing page after login so that I can choose where to go (Setup, Detector, Results).

---
Test Case #1
---
Redirect to Landing Page After Successful Login | ID: NAV-001
---
Pre-conditions:
User has valid account credentials
User is on the login page
User is not authenticated
---
Steps to Follow:
1. Enter valid email and password (or use OAuth)
2. Click "Login" button
3. Authentication succeeds
4. Observe redirect destination
---
Test Data:
Login Method: Email/password or OAuth
User Tier: Free
Expected Destination: Landing page
---
Expected Results:
User is redirected to landing page
Landing page displays navigation options
User sees "Setup", "Detector", and "Results" options
User is fully authenticated
Navigation bar shows logged-in state
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Landing Page Shows All Navigation Options | ID: NAV-002
---
Pre-conditions:
User successfully logged in
User is on landing page
User has free tier access
---
Steps to Follow:
1. User lands on landing page after login
2. Observe all available navigation options
3. Verify Setup, Detector, Results are visible
---
Test Data:
User Tier: Free
Available Options: Setup, Detector, Results
---
Expected Results:
Landing page displays clearly
"Setup" navigation option is visible and clickable
"Detector" navigation option is visible and clickable
"Results" navigation option is visible and clickable
All options are accessible to free users
Navigation UI is intuitive and clear
User can easily identify where to go next
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Navigate to Setup from Landing Page | ID: NAV-003
---
Pre-conditions:
User is logged in
User is on landing page
Setup page/feature exists
---
Steps to Follow:
1. User lands on landing page after login
2. Click on "Setup" button/link/option
3. Observe navigation to Setup page
---
Test Data:
Source Page: Landing page
Destination: Setup page
---
Expected Results:
User is navigated to Setup page
Setup page loads successfully
URL changes to reflect Setup page
User can access Setup features
Navigation maintains logged-in state
Back button returns to landing page
---
Actual Results:
---
Test Results:
---

---
Test Case #4
---
Navigate to Detector from Landing Page | ID: NAV-004
---
Pre-conditions:
User is logged in
User is on landing page
Detector page/feature exists
---
Steps to Follow:
1. User lands on landing page after login
2. Click on "Detector" button/link/option
3. Observe navigation to Detector page
---
Test Data:
Source Page: Landing page
Destination: Detector page
---
Expected Results:
User is navigated to Detector page
Detector page loads successfully
URL changes to reflect Detector page
User can access Detector features
Navigation maintains logged-in state
Free tier detector features are available
Back button returns to landing page
---
Actual Results:
---
Test Results:
---

---
Test Case #5
---
Navigate to Results from Landing Page | ID: NAV-005
---
Pre-conditions:
User is logged in
User is on landing page
Results page/feature exists
---
Steps to Follow:
1. User lands on landing page after login
2. Click on "Results" button/link/option
3. Observe navigation to Results page
---
Test Data:
Source Page: Landing page
Destination: Results page
---
Expected Results:
User is navigated to Results page
Results page loads successfully
URL changes to reflect Results page
User can view their previous results (if any)
If no results exist, appropriate message is shown
Navigation maintains logged-in state
Back button returns to landing page
---
Actual Results:
---
Test Results:
---

---
Test Case #6
---
Landing Page After Google OAuth Login | ID: NAV-006
---
Pre-conditions:
User has Google account linked
User is on login page
Google OAuth is configured
---
Steps to Follow:
1. Click "Continue with Google"
2. Complete Google OAuth flow
3. Authentication succeeds
4. Observe redirect destination
---
Test Data:
Login Method: Google OAuth
Expected Destination: Landing page
---
Expected Results:
User is redirected to landing page (not another page)
Landing page shows Setup, Detector, Results options
User session is established
Navigation shows user is logged in
OAuth login provides same experience as email/password login
---
Actual Results:
---
Test Results:
---

---
Test Case #7
---
Landing Page After GitHub OAuth Login | ID: NAV-007
---
Pre-conditions:
User has GitHub account linked
User is on login page
GitHub OAuth is configured
---
Steps to Follow:
1. Click "Continue with GitHub"
2. Complete GitHub OAuth flow
3. Authentication succeeds
4. Observe redirect destination
---
Test Data:
Login Method: GitHub OAuth
Expected Destination: Landing page
---
Expected Results:
User is redirected to landing page
Landing page displays navigation options
Setup, Detector, Results are all accessible
User session is established
Navigation shows user is logged in
GitHub OAuth provides same landing page experience
---
Actual Results:
---
Test Results:
---

---
Test Case #8
---
Landing Page After First-Time Account Creation | ID: NAV-008
---
Pre-conditions:
User does NOT have an account
User completes first OAuth login
Account is created automatically
---
Steps to Follow:
1. Complete first-time OAuth login (Google or GitHub)
2. Account is created automatically
3. Authentication succeeds
4. Observe redirect destination
---
Test Data:
Account Status: New account (first login)
Login Method: OAuth (Google or GitHub)
Expected Destination: Landing page
---
Expected Results:
New user is redirected to landing page
Landing page displays welcome message (optional)
Setup, Detector, Results options are visible
New user can immediately navigate to any section
No additional onboarding forms are required
User can start using the application immediately
---
Actual Results:
---
Test Results:
---

---
Test Case #9
---
Direct URL Access Redirects to Landing After Login | ID: NAV-009
---
Pre-conditions:
User is not logged in
User tries to access protected page directly via URL
---
Steps to Follow:
1. User enters URL for protected page (e.g., /detector)
2. System detects user is not authenticated
3. User is redirected to login page
4. User logs in successfully
5. Observe redirect destination
---
Test Data:
Original URL: /detector or /setup or /results
Login Status: Not authenticated → Authenticated
---
Expected Results:
Option 1: User is redirected to landing page after login
- OR -
Option 2: User is redirected to originally requested page after login

Landing page allows user to navigate to desired section
User can access all navigation options
Session is maintained correctly
---
Actual Results:
---
Test Results:
---

---
Test Case #10
---
Landing Page Navigation State Persistence | ID: NAV-010
---
Pre-conditions:
User is logged in
User is on landing page
User navigates to Setup/Detector/Results
---
Steps to Follow:
1. From landing page, navigate to Setup
2. Click back button or "Home" to return to landing page
3. Navigate to Detector
4. Return to landing page again
5. Navigate to Results
6. Return to landing page
---
Test Data:
Navigation Flow: Landing → Setup → Landing → Detector → Landing → Results → Landing
---
Expected Results:
User can freely navigate between sections
Landing page is always accessible
Landing page state is consistent
Navigation options remain visible
User session persists throughout navigation
No errors occur during navigation
Each section loads correctly
Returning to landing page works from all sections
---
Actual Results:
---
Test Results:
---

---
Test Case #11
---
Landing Page UI Elements Display Correctly | ID: NAV-011
---
Pre-conditions:
User is logged in
User lands on landing page
---
Steps to Follow:
1. Observe landing page layout
2. Verify all UI elements are present
3. Check responsiveness of navigation elements
---
Test Data:
Expected Elements:
- Setup button/card/link
- Detector button/card/link
- Results button/card/link
- User profile/logout option
- Navigation bar
---
Expected Results:
All navigation options are clearly visible
Setup option has clear label/icon
Detector option has clear label/icon
Results option has clear label/icon
Navigation is intuitive and user-friendly
UI is responsive on different screen sizes
Free tier badge/indicator is visible (if applicable)
Logout option is accessible
User name/email is displayed (if applicable)
---
Actual Results:
---
Test Results:
---

---
Test Case #12
---
Landing Page Shows Free Tier Features | ID: NAV-012
---
Pre-conditions:
User is logged in as free tier user
User is on landing page
---
Steps to Follow:
1. Observe landing page content
2. Check if free tier limitations are indicated
3. Verify which features are accessible
---
Test Data:
User Tier: Free
Expected Features: Setup, Detector (limited), Results
---
Expected Results:
Landing page indicates user tier (Free)
Free tier features are clearly marked as available
Premium features may be shown but marked as locked/upgrade required
User understands what features they can access
Navigation to free features is enabled
Navigation to premium-only features shows upgrade prompt
User experience is clear and not confusing
---
Actual Results:
---
Test Results:
---

---
Test Case #13
---
Landing Page Loads Quickly After Login | ID: NAV-013
---
Pre-conditions:
User has valid credentials
User is on login page
Network connection is normal
---
Steps to Follow:
1. Log in with valid credentials
2. Measure time to landing page load
3. Observe loading states
---
Test Data:
Expected Load Time: < 2 seconds (reasonable)
Network: Normal connection
---
Expected Results:
Landing page loads within acceptable time
Loading indicator is shown during transition (optional)
Page is responsive immediately after load
All navigation elements are interactive
No errors occur during loading
User doesn't experience long delays
Transition from login to landing is smooth
---
Actual Results:
---
Test Results:
---

---
Test Case #14
---
Landing Page After Session Expiration and Re-login | ID: NAV-014
---
Pre-conditions:
User was previously logged in
User session has expired
User re-authenticates
---
Steps to Follow:
1. User session expires (timeout or manual expiration)
2. User attempts to access application
3. User is redirected to login page
4. User logs in again
5. Observe redirect destination
---
Test Data:
Session State: Expired → Re-authenticated
Expected Destination: Landing page
---
Expected Results:
User is redirected to landing page after re-login
Landing page displays normally
All navigation options are available
User's previous work/data is preserved (not lost)
Session is re-established correctly
User can continue using the application
No data corruption or loss occurs
---
Actual Results:
---
Test Results:
---

---
Test Case #15
---
Browser Back Button from Landing Page | ID: NAV-015
---
Pre-conditions:
User is logged in
User is on landing page
User arrived from login page
---
Steps to Follow:
1. User lands on landing page after successful login
2. Click browser back button
3. Observe behavior
---
Test Data:
Current Page: Landing page
Previous Page: Login page
Expected Behavior: Prevent returning to login page while logged in
---
Expected Results:
Option 1: Back button is disabled/prevented
- User stays on landing page
- OR -
Option 2: Back button returns to login page
- But login page detects active session
- And immediately redirects back to landing page

User does not get stuck in login page while authenticated
User experience is smooth and logical
Session state is maintained correctly
---
Actual Results:
---
Test Results:
---

## Summary

**Total Test Cases: 15**

**Coverage:**
- ✅ Post-login redirect to landing page
- ✅ Navigation to Setup, Detector, and Results
- ✅ Different login methods (email, Google OAuth, GitHub OAuth)
- ✅ First-time account creation flow
- ✅ Direct URL access and redirects
- ✅ Navigation state persistence
- ✅ UI elements and layout
- ✅ Free tier feature visibility
- ✅ Performance (page load time)
- ✅ Session expiration and re-login
- ✅ Browser navigation behavior

**Test Execution Notes:**
1. Test with different login methods (email/password, Google, GitHub)
2. Verify landing page is the consistent destination after all login types
3. Test navigation to all three sections: Setup, Detector, Results
4. Verify free tier users can access appropriate features
5. Check UI/UX is clear and intuitive
6. Test browser navigation (back/forward buttons)
7. Verify session persistence during navigation
8. Test with new accounts and existing accounts
9. Measure page load performance
10. Test edge cases (session expiration, direct URL access)
