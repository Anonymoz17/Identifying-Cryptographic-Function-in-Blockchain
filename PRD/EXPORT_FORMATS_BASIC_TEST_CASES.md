# Basic Test Cases - Export Report in Multiple Formats

## User Story
As a free user, I want to export the report in PDF, JSON or TXT format so that I can review it.

---
Test Case #1
---
Export Report as PDF | ID: EXPORT-001
---
Pre-conditions:
User is logged in
User has completed detection with findings
Detection results are available
User is on the results/report screen
---
Steps to Follow:
1. Navigate to results screen
2. Click "Export Report" or "Generate Report" button
3. Select "PDF" format from format options
4. Choose save location
5. Click "Export" or "Save"
---
Test Data:
Case ID: CRYPTO-2024-001
Findings: 8 cryptographic detections
Export Format: PDF
User Tier: Free
---
Expected Results:
PDF export starts successfully
Progress indicator shows "Exporting to PDF..."
PDF file is generated successfully
Success message: "Report exported as PDF"
PDF report contains:
  - Professional formatted layout
  - Case ID and metadata header
  - Executive summary section
  - Detailed findings table with all detections
  - Algorithm names, code locations, confidence scores
  - Weak/deprecated algorithm warnings highlighted
  - Timestamps and file analysis summary
  - Page numbers and proper formatting
PDF is saved to selected location
Filename: "CRYPTO-2024-001_Report_2024-11-14.pdf"
PDF can be opened with any PDF reader
Report is readable and well-formatted for sharing
PDF is suitable for printing and archiving
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Export Report as JSON | ID: EXPORT-002
---
Pre-conditions:
User is logged in
User has completed detection with findings
Detection results are available
User wants machine-readable format for integration
---
Steps to Follow:
1. Navigate to results screen
2. Click "Export Report" button
3. Select "JSON" format from format options
4. Choose save location
5. Click "Export"
---
Test Data:
Case ID: CRYPTO-2024-001
Findings: 8 cryptographic detections
Export Format: JSON
Expected Use: API integration, data processing
---
Expected Results:
JSON export completes successfully
Success message: "Report exported as JSON"
JSON file is generated with structured data
Filename: "CRYPTO-2024-001_Report_2024-11-14.json"
JSON structure includes:
  - Case metadata (case_id, timestamp, files_analyzed)
  - Findings array with all detections
  - Each finding contains:
    - algorithm: "SHA-256"
    - file: "contract.sol"
    - line: 42
    - function: "hashPassword"
    - library: "OpenSSL"
    - pattern_evidence: {...}
    - confidence_score: 0.98
    - is_weak: false
    - security_status: "secure"
JSON is valid and properly formatted
JSON can be parsed by standard JSON libraries
Data is structured for easy programmatic access
JSON is suitable for automation and integration
All special characters are properly escaped
File is saved to selected location
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Export Report as TXT | ID: EXPORT-003
---
Pre-conditions:
User is logged in
User has completed detection with findings
Detection results are available
User wants simple text format for quick review
---
Steps to Follow:
1. Navigate to results screen
2. Click "Export Report" button
3. Select "TXT" or "Plain Text" format from format options
4. Choose save location
5. Click "Export"
---
Test Data:
Case ID: CRYPTO-2024-001
Findings: 8 cryptographic detections
Export Format: TXT (Plain Text)
Expected Use: Quick review, email, log files
---
Expected Results:
TXT export completes successfully
Success message: "Report exported as TXT"
Text file is generated with readable format
Filename: "CRYPTO-2024-001_Report_2024-11-14.txt"
TXT report contains:
  - Header with case information
  - Line separator characters for readability
  - Summary section with statistics
  - Findings listed in clear text format:
    ----------------------------------------
    Finding #1
    ----------------------------------------
    Algorithm: SHA-256
    File: contract.sol
    Line: 42
    Function: hashPassword()
    Library: OpenSSL
    Confidence: 98%
    Status: Secure
    Pattern Evidence: Constant 0x6a09e667 detected

    ----------------------------------------
    Finding #2
    ----------------------------------------
    [Additional findings...]
  - Footer with analysis completion info
Text is plain ASCII (no special formatting)
File can be opened with any text editor
Text is easily readable without special software
Format is suitable for copy-paste into emails
TXT format works on all platforms (Windows, Mac, Linux)
File size is minimal (efficient storage)
Content is searchable with text search tools
---
Actual Results:
---
Test Results:
---
