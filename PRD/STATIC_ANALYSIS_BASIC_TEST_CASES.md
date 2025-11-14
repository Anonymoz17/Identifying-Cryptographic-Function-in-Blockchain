# Basic Test Cases - Run Static Analysis

## User Story
As a free user, I want to run static analysis so that I can see findings such as detected algorithms (e.g., SHA-256, AES-CTR), referenced libraries (OpenSSL, libsodium, Crypto++), code locations (file:line/function), pattern evidence (constants, S-boxes, IV/key-size hints), weak/deprecated usage flags (e.g., MD5/SHA-1), and confidence scores, so I can prioritize fixes without executing the program.

---
Test Case #1
---
Run Static Analysis with Cryptographic Findings | ID: STATIC-001
---
Pre-conditions:
User is logged in
User has loaded a case with preprocessed files
Case contains blockchain code with cryptographic functions
User is on the detector screen
Preprocessing is complete
---
Steps to Follow:
1. Click "Run Static Analysis" button
2. System analyzes preprocessed files
3. Observe analysis progress in console
4. Wait for analysis to complete
5. View results on detector screen
---
Test Data:
Case ID: CRYPTO-2024-001
Files: 5 smart contract files with crypto usage
Expected Findings: SHA-256, AES-CTR, OpenSSL references
User Tier: Free
---
Expected Results:
Static analysis completes successfully
Results screen displays detected findings
Detected algorithms are listed: "SHA-256", "AES-CTR"
Referenced libraries are shown: "OpenSSL", "libsodium"
Code locations are displayed: "contract.sol:42/hashPassword"
Pattern evidence is shown:
  - Constants detected (e.g., "0x5A827999")
  - S-boxes identified
  - IV/key-size hints (e.g., "16-byte IV", "256-bit key")
Confidence scores are displayed for each finding (e.g., "95%", "High")
Findings are organized and readable
No weak/deprecated algorithms in this test
Console shows: "Static analysis completed. 8 findings detected."
User can review all findings without running code
Results are saved to work directory
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Static Analysis Detects Weak/Deprecated Algorithms | ID: STATIC-002
---
Pre-conditions:
User is logged in
User has loaded a case with preprocessed files
Case contains code using weak/deprecated algorithms (MD5, SHA-1)
User is on the detector screen
---
Steps to Follow:
1. Click "Run Static Analysis" button
2. System analyzes code for cryptographic usage
3. System detects weak/deprecated algorithms
4. View results with security warnings
---
Test Data:
Case ID: CRYPTO-2024-003
Files: Legacy code using MD5 and SHA-1
Expected Findings: MD5, SHA-1 with warning flags
---
Expected Results:
Static analysis completes successfully
Results display all detected findings
Weak/deprecated algorithms are flagged prominently:
  - "MD5" with warning icon/red flag
  - "SHA-1" with warning icon/red flag
Warning messages displayed:
  - "MD5 is cryptographically weak and deprecated"
  - "SHA-1 is vulnerable to collision attacks"
Code locations are shown: "auth.sol:78/generateHash"
Confidence scores are displayed (e.g., "MD5: 98% confidence")
Security severity levels shown (e.g., "High Risk", "Critical")
Recommendations provided:
  - "Replace MD5 with SHA-256 or SHA-3"
  - "Upgrade SHA-1 to SHA-256"
Findings are prioritized by risk level
User can identify security issues without code execution
Weak findings are visually distinct from secure findings
Console logs security warnings
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Static Analysis with No Cryptographic Findings | ID: STATIC-003
---
Pre-conditions:
User is logged in
User has loaded a case with preprocessed files
Case contains code with NO cryptographic functions
User is on the detector screen
---
Steps to Follow:
1. Click "Run Static Analysis" button
2. System analyzes all preprocessed files
3. System finds no cryptographic usage
4. View results screen
---
Test Data:
Case ID: CRYPTO-2024-004
Files: 3 smart contract files with basic business logic only
Expected Findings: None (no crypto usage)
---
Expected Results:
Static analysis completes successfully
Results screen shows: "No cryptographic findings detected"
Message displayed: "The analyzed code does not contain identifiable cryptographic algorithms or libraries."
No false positives are shown
Empty results sections:
  - Detected Algorithms: None
  - Referenced Libraries: None
  - Code Locations: None
  - Weak/Deprecated Flags: None
Console shows: "Static analysis completed. 0 findings."
User understands code is clean (no crypto detected)
Analysis time is reasonable even with no findings
Results are saved to work directory
User can run detection again or load different case
System doesn't crash or error on empty results
---
Actual Results:
---
Test Results:
---
