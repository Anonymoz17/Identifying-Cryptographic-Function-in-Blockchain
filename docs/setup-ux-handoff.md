# Setup Page — UI/UX Handoff

## Purpose

This document explains the current Setup page behavior, the policy editor's JSON Schema validation integration, and concrete UX recommendations and acceptance criteria for finishing the Setup UI. It is intended for frontend/UI engineers and product designers who will implement the final UX polish (inline validation, animations, settings panel) and for backend/devs who need to consume/extend the validator.

## Where to find code

- Setup UI: `src/pages/setup.py`
- Settings persistence: `src/settings.py`
- Policy schema: `schemas/policy.baseline.schema.json`
- Policy validator: `src/policy_validator.py` — public helper: `validate_policy_text(txt) -> (bool, List[str])`
- Tests for validator: `tests/test_policy_validator.py`

## High-level behavior (current)

- The Setup page lets users choose a workspace (workdir), run a scan (pre-count + scan + preproc), and optionally insert or save a `policy.baseline.json` from the policy editor modal.
- Workdir field is pre-filled from `get_default_workdir()` (platform-canonical per-user path). When the user changes or browses for a path, `set_default_workdir()` is called to persist their choice.
- Progress is reported through centralized helpers in `src/pages/setup.py`:
  - `_begin_stage(name, determinate=False)` — mark a stage started; determinate True means it will show numeric progress.
  - `_update_progress(stage, processed, total=None, path=None)` — unified progress updater for all stages.
  - `_end_stage(name, keep_message=True)` — finish the stage and show final state briefly.
- Determinate stages (showing percentage): input counting and short, bounded work (manifest write). Indeterminate stages (ticker): long-running operations (disassembly, heavy preproc) show a subtle ticker instead of a busy spinner.
- Policy editor: Insert / Save actions call `validate_policy_text`. If the policy JSON is invalid (parse error or schema violations), the modal currently shows a modal messagebox listing validation errors and blocks the write. Valid policies are accepted and saved/inserted.
- Policy import in Setup: the Setup flow now validates the policy before importing it into the case. The import is recorded in `auditlog.ndjson` with an event `engagement.policy_imported` (payload includes source path, destination path, sha256 sidecar, and schema_version when available). Failed imports write `engagement.policy_import_failed` with error details. This helps downstream consumers rely on a stable contract and provides an audit trail.

## Policy validation contract

- Schema path: `schemas/policy.baseline.schema.json` (Draft-07).
- Public API: `validate_policy_text(txt: str) -> (valid: bool, errors: List[str])`
  - If `valid` is True, `errors` is an empty list.
  - If `valid` is False, `errors` contains human-readable messages (parse errors and schema validation messages).
- Implementation detail: the helper uses `jsonschema` Draft7 if installed; otherwise a minimal fallback checks the essential structure (top-level object, `version`, and at least one of `whitelist|rules|scoring`).

## UX notes and recommended changes (priority)

1. Inline validation in the policy editor (High priority)

   - Replace the current blocking modal errors with live validation while editing.
   - UI pattern:
     - Validate on paste/typing with a 400ms debounce.
     - Show a small non-modal error pane at the bottom of the editor listing up to 5 validation errors.
     - When hovering an entry in the error list, highlight the approximate location in the text (line numbers). If precise spans are available from validator, use them; otherwise map by reported line numbers if present.
     - Disable the Insert/Save buttons while errors exist; show a tooltip "Fix validation errors before saving".
   - Acceptance criteria:
     - Editor re-runs `validate_policy_text` on content change with debounce and updates inline errors.
     - Insert/Save buttons disabled when errors array non-empty.
     - Error list shows parse errors first, then schema errors.

2. Improve progress bar semantics and copy (Medium priority)

   - Keep centralized update flow; change visible text per stage to be user-friendly and actionable.
   - Suggested copy per stage:
     - "Counting files..." (show determinate % if total known)
     - "Scanning sources..." (Show ETA if available; otherwise indeterminate ticker)
     - "Disassembling binaries..." (indeterminate ticker)
     - "Writing manifest..." (determinate short burst)
   - Add small spinner or subtle pulsing to the indeterminate ticker to convey progress. Avoid large, constantly spinning elements that feel stuck.
   - Acceptance criteria: when a stage starts, the bar and label update immediately; there is no confusing stuck state for >3s without feedback (ticker animates and label updates periodically, e.g., every 500–900ms).

3. Workdir selection and migration guidance (Medium priority)

   - Provide a "Reset to default" button next to the workdir entry that:
     - Sets the entry to `get_default_workdir()` and persists it.
     - If the new selected path differs and contains existing project data, offer a migration confirmation modal. This modal gives three choices: "Migrate existing cases", "Keep both", "Cancel".
   - Acceptance criteria: Reset to default applies settings immediately and shows a short toast confirming the change.

4. Settings / Preferences panel (Lower priority)
   - Expose a small preferences UI to manage:
     - Default workspace (workdir)
     - Fast-count timeout (e.g., default 0.8s)
     - Permission tightening toggle for manifests (attempt to set restrictive perms where platform supports)
   - Acceptance criteria: settings persisted via `src/settings.py` and the Setup page reads them at open-time.

## Accessibility and copy

- All actionable controls must have accessible labels (e.g., workdir input labeled "Workspace folder", Start button labeled "Start Scan").
- Progress text must be readable by screen readers; prefer text updates over live-only animations.
- Error messages in the policy editor must be keyboard-focusable (so keyboard-only users can read and clear them).

## Edge cases and error flows

- Large policy files: validate in a background thread if necessary; avoid freezing the UI. Use debounced validation to avoid heavy CPU on each keystroke.
- Missing `jsonschema` library: the validator falls back to minimal checks. If you want full validation support in production, add `jsonschema` to runtime requirements and vendor lockfile (or require it at install time).
- Permission errors when saving policy or writing manifests: show clear error message with the OS path and suggested remedy (run with elevated permissions or choose a different workspace).

## Developer notes

- When implementing inline validation, call `validate_policy_text` directly. It is lightweight for moderate size files but if you observe performance issues for very large policy files, run it in a worker thread and post results back to the UI thread.
- For mapping error messages to line numbers, the `jsonschema` library may include a `path` with the failing JSON pointer; combine that with a JSON parser that reports line/column to provide precise locations.
- Tests: keep and extend `tests/test_policy_validator.py`. Add UI-level integration tests that simulate bad policy insert/save behavior (mock the validator to return errors) and confirm the modal buttons are disabled.

## Acceptance checklist for this handoff

- [ ] Inline validation implemented with debounce and error pane.
- [ ] Insert/Save disabled when validation fails; user can still copy the text out.
- [ ] Policy schema file remains at `schemas/policy.baseline.schema.json` (versioned); validator uses it.
- [ ] Progress bar text and ticker behavior updated according to guidelines and verified by QA.
- [ ] "Reset to default" workdir behavior implemented and persisted via `src/settings.py`.
- [ ] Unit tests cover validator and settings persistence; UI integration tests cover the editor error flow.
- [ ] Policy import into a case is validated and recorded in `auditlog.ndjson` with `engagement.policy_imported` or `engagement.policy_import_failed` events; tests cover both success and failure paths.

## Priority short todo (what to implement next — 2–3 sprint-sized items)

1. Inline validation in the policy editor (high) — implement the error pane, debounced validator calls, and disabled save/insert behavior. Add unit and simple integration tests.
2. Add "Reset to default" button for Workdir and a small confirmation/migration dialog (medium). Persist via `src/settings.py` and show a toast.
3. Improve progress bar copy + light ticker animation (small, polish). Ensure no >3s stuck state without visible animation or message.

## Contact / follow-up

If you want, I can implement item (1) (inline validation) next. I can open small PR(s) with unit tests and a short demo of the inline error pane in the modal editor.
