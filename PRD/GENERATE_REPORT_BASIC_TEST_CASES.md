# Basic Test Cases - Generate Report

## User Story
As a free user, I want to generate a report so that I can share or archive the results.

---
Test Case #1
---
Generate Report Successfully | ID: REPORT-001
---
Pre-conditions:
User is logged in
User has completed detection with findings
Detection results are available on results screen
User is on the results/report section
---
Steps to Follow:
1. Navigate to results screen with detection findings
2. Click "Generate Report" or "Export Report" button
3. Select report format (if options available, e.g., PDF, HTML, JSON)
4. Click "Generate" or "Export"
5. Wait for report generation to complete
---
Test Data:
Case ID: CRYPTO-2024-001
Findings: 8 cryptographic detections
Report Format: PDF (or default format)
User Tier: Free
---
Expected Results:
Report generation starts successfully
Progress indicator shows "Generating report..."
Report is generated without errors
Success message: "Report generated successfully"
Report contains all detection findings:
  - Case ID and metadata
  - Summary of findings (8 detections)
  - Detailed list of each finding with:
    - Algorithm names
    - Code locations (file:line/function)
    - Pattern evidence
    - Confidence scores
    - Weak/deprecated flags
  - Analysis timestamp
  - Files analyzed count
Report is saved to work directory
Report filename includes Case ID and timestamp (e.g., "CRYPTO-2024-001_Report_2024-11-14.pdf")
User can download/open the report
Report is well-formatted and readable
Report is suitable for sharing with team members
---
Actual Results:
---
Test Results:
---

---
Test Case #2
---
Generate Report with No Findings | ID: REPORT-002
---
Pre-conditions:
User is logged in
User has completed detection with zero findings
Results screen shows "No cryptographic findings"
User wants to generate a report anyway
---
Steps to Follow:
1. Navigate to results screen (no findings)
2. Click "Generate Report" button
3. Confirm report generation
4. Observe report generation
---
Test Data:
Case ID: CRYPTO-2024-007
Findings: 0 (no cryptographic code detected)
Files Analyzed: 5
Expected Report Content: Summary with no findings
---
Expected Results:
Report generation completes successfully
Report is created even with zero findings
Report contains:
  - Case ID: CRYPTO-2024-007
  - Analysis timestamp
  - Files analyzed: 5
  - Summary: "No cryptographic findings detected"
  - Statement: "The analyzed code does not contain identifiable cryptographic algorithms or libraries."
  - Empty findings section clearly marked
Report is properly formatted
Report serves as proof that analysis was performed
User can archive report as documentation
Report shows analysis was thorough but found nothing
No errors occur with empty results
---
Actual Results:
---
Test Results:
---

---
Test Case #3
---
Share/Export Report to Different Locations | ID: REPORT-003
---
Pre-conditions:
User is logged in
User has generated a report
Report file exists in work directory
User wants to share or archive the report
---
Steps to Follow:
1. Generate report successfully
2. Locate "Export" or "Save As" option
3. Choose export destination (different folder, downloads, etc.)
4. Optionally select format (PDF, HTML, JSON, CSV)
5. Save/export the report
---
Test Data:
Case ID: CRYPTO-2024-001
Generated Report: CRYPTO-2024-001_Report_2024-11-14.pdf
Export Destination: User's Downloads folder or custom location
Available Formats: PDF, HTML, JSON (if multiple formats supported)
---
Expected Results:
User can access generated report
Export/Save As dialog opens
User can select different save location
User can choose report format (if multiple formats available):
  - PDF: Professional formatted report
  - HTML: Web-viewable report
  - JSON: Machine-readable format
  - CSV: Findings data for spreadsheet analysis (optional)
Report is copied/saved to selected location
Original report remains in work directory
Success message: "Report exported to [location]"
User can share report via email or file sharing
Report is self-contained and readable without application
Report maintains formatting and all content
File is named appropriately for easy identification
User can generate multiple copies for distribution
---
Actual Results:
---
Test Results:
---
