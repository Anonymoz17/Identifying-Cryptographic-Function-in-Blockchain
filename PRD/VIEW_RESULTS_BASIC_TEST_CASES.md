# Basic Test Cases - View Results and Findings

## User Story
As a free user, I want to view results/findings so that I can inspect what was detected in my case.

---
Test Case #1
---
View Detection Results with Findings | ID: RESULTS-001
---
Pre-conditions:
User is logged in
User has completed static analysis/detection
Detection found cryptographic algorithms and patterns
User is on the results/findings screen
---
Steps to Follow:
1. Navigate to "Results" or "Findings" screen after detection completes
2. Observe list of detected findings
3. Review details for each finding
4. Inspect all result sections
---
Test Data:
Case ID: CRYPTO-2024-001
Findings: 8 cryptographic detections
  - 3 SHA-256 instances
  - 2 AES-CTR instances
  - 1 MD5 instance (flagged as weak)
  - 2 library references (OpenSSL, libsodium)
---
Expected Results:
Results screen displays all findings clearly
Each finding shows:
  - Algorithm name (e.g., "SHA-256")
  - Code location (file:line/function, e.g., "contract.sol:42/hashPassword")
  - Referenced library (e.g., "OpenSSL")
  - Pattern evidence (constants, S-boxes, key sizes)
  - Confidence score (e.g., "95%", "High")
  - Weak/deprecated flag (if applicable, e.g., MD5 flagged)
Findings are organized and easy to read
User can see all 8 findings listed
Weak algorithms (MD5) are visually highlighted with warnings
Results include detailed evidence for each detection
User can inspect each finding individually
Results are comprehensive and actionable
Navigation between findings is intuitive
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
View Results with No Findings | ID: RESULTS-002
---
Pre-conditions:
User is logged in
User has completed detection on a case
Detection found NO cryptographic algorithms
User is on the results screen
---
Steps to Follow:
1. Run detection on case with no cryptographic code
2. Detection completes successfully
3. Navigate to results screen
4. Observe empty/no findings message
---
Test Data:
Case ID: CRYPTO-2024-007
Files Analyzed: 5
Findings: 0 (no cryptographic code detected)
---
Expected Results:
Results screen displays clearly
Message shown: "No cryptographic findings detected"
Informative text: "The analyzed code does not contain identifiable cryptographic algorithms or libraries."
No false positives are displayed
Empty results sections are clearly marked:
  - Detected Algorithms: None
  - Referenced Libraries: None
  - Weak/Deprecated Flags: None
User understands analysis was successful but found nothing
Results summary shows: "0 findings from 5 files analyzed"
User can navigate back or run new detection
No confusion about empty results
Results page layout is still properly formatted
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
View Detailed Finding Information | ID: RESULTS-003
---
Pre-conditions:
User is logged in
User has detection results with findings
User wants to inspect a specific finding in detail
Results screen displays list of findings
---
Steps to Follow:
1. View results screen with multiple findings
2. Click on a specific finding (e.g., "SHA-256 detected in contract.sol")
3. Observe detailed view/expanded information
4. Review all detailed attributes
---
Test Data:
Selected Finding: SHA-256 in contract.sol:42
Expected Details:
  - Algorithm: SHA-256
  - File: contract.sol
  - Line: 42
  - Function: hashPassword()
  - Library: OpenSSL
  - Pattern Evidence: "Constant 0x6a09e667 detected (SHA-256 initial value)"
  - Key Size: 256-bit
  - Confidence: 98%
  - Status: Secure (not weak/deprecated)
---
Expected Results:
Detailed view opens for selected finding
All attributes are displayed clearly:
  - Algorithm name and type
  - Exact code location (file, line number, function name)
  - Referenced library/framework
  - Pattern evidence with technical details
  - Confidence score with explanation
  - Security status (secure/weak/deprecated)
Code snippet is shown (optional):
  - Lines around the detection point
  - Highlighted matching pattern
Additional context provided:
  - Why this was detected (evidence summary)
  - Security recommendations (if weak/deprecated)
  - Related findings in same file (if applicable)
User can navigate to source code location
User can export this finding
User can return to full results list
Detailed information helps user understand detection
All data is accurate and properly formatted
---
Actual Results:
---
Test Results:
---
