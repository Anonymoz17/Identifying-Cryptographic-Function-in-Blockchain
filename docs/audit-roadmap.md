# Audit product roadmap & implementation notes

Date: 2025-10-31

This document captures the audit-focused product assessment, the current
state of the codebase (notable implemented features), identified gaps, and a
prioritized roadmap for next work. It's intended as a living planning doc for
you and the team.

---

## Current state (what's implemented in this branch)

Files / features of note:

- `src/pages/setup.py`
  - Setup UI with inputs for Workdir, Case ID, Scope and Policy.
  - New policy editor modal: template chooser (Whitelist, Rule Overrides,
    Scoring, Combined), JSON editor, Insert (writes a temp file and sets the
    Policy entry), Save As and Load.
  - Policy files are copied into the case workspace as
    `<workdir>/<case_id>/policy.baseline.json` via
    `Engagement.import_policy_baseline()` with a `.sha256` sidecar.
- `src/pages/results.py`
  - New Results page that discovers case workspaces and reads
    `<case>/detector_output/detector_results.summary.json` to render three
    charts: top-rule bar chart, engine breakdown pie chart, and confidence
    histogram. Chart rendering uses Matplotlib if available.
  - Case selector, Browse and Run Detectors button (invokes
    `tools/open_results.py` helper by default).
  - Summary parsing moved to a background thread; rendering and widget updates
    are scheduled on the main thread to keep the UI responsive.
- Dialog and UX fixes

  - File dialogs and messageboxes now pass `parent=` so they're attached to the
    main window and do not cause focus/stacking issues.
  - Introduced small dialog wrapper to call `update_idletasks()` before showing
    dialogs and schedule a short post-dialog cleanup via `after()`.

- `tools/open_results.py` (helper — present in tools/)

  - A helper script to run detectors for a case and open the GUI focused on
    the Results page. The Results UI falls back to letting the user pick this
    script if it's not found automatically.

- Tests
  - `tests/test_auditor_case.py` verifies `Engagement.import_policy_baseline()`
    behavior and SHA sidecar.

---

## Key gaps and why they matter

The following gaps are prioritized for security-auditor use-cases.

1. Policy governance and enforcement

   - Baseline files are stored but not used by detectors. Auditors need
     validated policy files and the ability to suppress/annotate findings.
   - Missing JSON Schema validation and inline guidance for authors.

2. Evidence & chain-of-custody

   - Evidence packs include policy and preproc inputs, but signing,
     timestamping, and manifest versioning are not present.
   - Auditors require verifiable, reproducible evidence for reports and
     legal/forensic handling.

3. Detection provenance & scoring

   - Findings should record richer provenance (file id, path, function name,
     byte offset, detector version) and structured confidence composition.

4. Execution safety & resource limits

   - Detectors or optional headless tools (Ghidra, Frida) can be heavy and
     potentially unsafe to run on untrusted inputs without timeouts,
     resource constraints or sandboxing.

5. UX & triage capabilities

   - Triage workflows (accept/reject findings, annotate, export filtered
     reports) are missing. Bulk actions and triage state tracking are needed.

6. CI, packaging, and distribution

   - CI workflows to enforce linting and tests are not yet configured to gate
     PRs. Windows packaging and install documentation need attention.

7. Observability and testing
   - Structured logging and metrics (timings, error rates), plus automated
     tests for policy handling and summary generation, are needed for
     reliability.

---

## Prioritized roadmap (short / medium / long)

Short term (days — high impact, low cost)

- Add JSON Schema for `policy.baseline.json` and validate in the policy editor
  on Save/Insert. Provide helpful error messages for common mistakes.
- Annotate summary generation with `baseline_match` flags when a finding's
  rule_id or evidence matches the baseline. Show this in the Results UI as a
  tag/column.
- Add a Results filter toggle: "Hide baseline-allowed findings" (non-
  destructive; NDJSON preserved).
- Add a lightweight loading overlay / spinner during summary parsing and chart
  rendering.
- Add unit tests for policy import + template generator and summary
  annotation behavior.

Medium term (weeks)

- Implement evidence pack signing (GPG option) and manifest versioning.
  Record signature events in `auditlog.ndjson`.
- Build a worker queue for heavy tasks (preproc, disasm parsing, Ghidra
  exports) to avoid main-thread blocking and to provide progress/cancellation.
- Add structured provenance fields to detections and enforce them in
  adapters/runner.
- Create CI (GitHub Actions) to run ruff/black/isort and pytest on PRs.

Long term (months)

- Packaging: build Windows installers (PyInstaller) and publish pinned
  requirements; add automated release notes.
- Access controls and encryption for sensitive evidence if you plan team
  deployments.
- Consider a server-backed option for collaborative triage and shared
  evidence storage (this is a larger architecture change).

---

## Concrete next steps I can implement now

Pick one and I'll prepare a patch + tests:

- A) JSON Schema + inline validation in Setup policy editor (recommended
  immediate step).
- B) Baseline annotation in summary generator + Results UI markers.
- C) Loading spinner overlay for Results while parsing and rendering.
- D) Unit tests for policy import and template functions.

---

## Notes about policy baseline semantics (recommended schema sketch)

A recommended shape for `policy.baseline.json` (versioned) is:

```json
{
  "version": "1.0",
  "metadata": { "author": "", "created_at": "" },
  "whitelist": {
    "file_hashes": [],
    "function_names": [],
    "rule_ids": []
  },
  "rules": {
    "YARA-0001": { "action": "allow", "reason": "vendor" }
  },
  "scoring": {
    "engine_weights": { "yara": 1.0, "treesitter": 0.8 },
    "confidence_thresholds": { "high": 0.9, "medium": 0.6, "low": 0.3 }
  }
}
```

Validators should accept unknown top-level keys (forward compatible) but
require `version` and at least one of `whitelist`, `rules`, or `scoring`.

---

## Files changed in this branch (quick reference)

- `src/pages/setup.py` — added policy editor and template insertion, improved
  file dialog handling.
- `src/pages/results.py` — added Results UI, background summary parsing,
  dialog parent attachment and small deferred-load behavior.
- `tools/open_results.py` — helper to run detectors and open Results view.

---

## How we'll track progress

I'll maintain the todo list in the repo issue tracker (or GitHub issues) and
keep this `docs/audit-roadmap.md` updated as pull requests land. For every
implementation I will:

- add/modify unit tests where possible,
- update `docs/` with user-facing instructions (how to author baselines,
  triage flow), and
- add changelog entries for release notes.

---

If you'd like I'll start by implementing (A) JSON Schema validation in the
policy editor and add tests for it — say "Do A" and I'll prepare the patch.
