# Basic Test Cases - Free Tier Analysis Limit

## User Story
As a free user, I want to run up to five analyses in total before I'm shown an upgrade prompt so that I can evaluate the tool on small tasks without paying.

---
Test Case #1
---
Run Analysis Within Free Tier Limit | ID: LIMIT-001
---
Pre-conditions:
User is logged in with free tier account
User has run 2 analyses previously
User has 3 remaining analyses before limit
User has completed setup and preprocessing
---
Steps to Follow:
1. Navigate to detector page
2. Click "Run Static Analysis" button
3. Analysis completes successfully
4. View results
5. Check for any limit warnings or upgrade prompts
---
Test Data:
User Tier: Free
Previous Analyses: 2
Current Analysis: 3rd analysis
Remaining Analyses: 2
Total Limit: 5
---
Expected Results:
Analysis runs successfully without restrictions
Analysis completes and shows results normally
No upgrade prompt is displayed
Optional: Usage counter is shown (e.g., "3 of 5 analyses used")
User can view all results without limitations
User can export report normally
User is informed of remaining analyses (e.g., "2 analyses remaining")
No functionality is blocked or restricted
User can continue using the tool
Analysis is counted toward the 5-analysis limit
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Run Fifth (Final) Analysis Before Limit | ID: LIMIT-002
---
Pre-conditions:
User is logged in with free tier account
User has run 4 analyses previously
This is the 5th and final free analysis
User has completed setup and preprocessing
---
Steps to Follow:
1. Navigate to detector page
2. Observe any warnings about reaching limit
3. Click "Run Static Analysis" button
4. Analysis runs (5th analysis)
5. Analysis completes
6. Observe upgrade prompt after completion
---
Test Data:
User Tier: Free
Previous Analyses: 4
Current Analysis: 5th analysis (final free analysis)
Remaining Analyses: 0 after this
Total Limit: 5
---
Expected Results:
System shows warning before/during 5th analysis:
  - "This is your last free analysis (5 of 5)"
  - "Upgrade to continue using the tool after this analysis"
Analysis runs successfully and completes
Results are displayed normally
User can view and export results from 5th analysis
After analysis completes, upgrade prompt is displayed:
  - "You've used all 5 free analyses"
  - "Upgrade to Premium for unlimited analyses"
  - Upgrade options are shown with pricing
  - "Continue" or "Upgrade Now" buttons
Upgrade prompt is informative, not blocking (user can dismiss)
User can still view previous analysis results
No existing functionality is removed
User understands they need to upgrade for more analyses
Clear call-to-action to upgrade
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Attempt to Run Analysis After Limit Exceeded | ID: LIMIT-003
---
Pre-conditions:
User is logged in with free tier account
User has already run 5 analyses (limit reached)
User attempts to run a 6th analysis
User has completed setup and preprocessing for new case
---
Steps to Follow:
1. Navigate to detector page with new case
2. Attempt to click "Run Static Analysis" button
3. Observe system response
---
Test Data:
User Tier: Free
Previous Analyses: 5 (limit reached)
Attempted Analysis: 6th analysis (exceeds limit)
Remaining Analyses: 0
Total Limit: 5
---
Expected Results:
System prevents running 6th analysis
Upgrade prompt is displayed immediately:
  - "Free tier limit reached"
  - "You've used all 5 free analyses"
  - "Upgrade to Premium for unlimited analyses"
"Run Static Analysis" button may be disabled or show upgrade prompt on click
Clear messaging explains the limitation
Upgrade options are prominently displayed:
  - Premium tier pricing and benefits
  - "Upgrade Now" call-to-action button
  - Comparison of free vs premium features
User can still access:
  - Previous analysis results (all 5 past analyses)
  - Export previous reports
  - Setup and preprocessing (but not detection)
User cannot run new analyses without upgrading
Upgrade process is clear and accessible
User can dismiss prompt and explore upgrade options later
All previously analyzed data remains accessible
No data loss occurs
System gracefully enforces the limit
---
Actual Results:
---
Test Results:
---
