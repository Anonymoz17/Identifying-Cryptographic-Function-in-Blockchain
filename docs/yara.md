# YARA integration (optional)

This project supports YARA-based detection via the `YaraAdapter` in `src/detectors/adapter.py`.
YARA is optional — the codebase falls back to regex-based adapters when the `yara` Python
bindings are not available.

Installation (development)

- Option 1 (recommended for local/dev): install into your virtualenv:

```powershell
# activate your venv first
python -m pip install yara-python
```

- Option 2 (if the above fails): use your system package manager to install the libyara
  development headers and then `pip install yara-python`.

Notes:

- On many systems you must have development headers available (libyara) before installing.
- If building from source is problematic, consider running the detection step inside a Docker
  container that has `yara-python` preinstalled.

How to author rules

- Place `.yar` files in a directory, or supply a single `.yar` file.
- Rules support `meta:` fields and `tags` which will be preserved and lifted into the
  NDJSON output for easier filtering.

Example YARA rule (save as `rules/test_rules.yar`):

```
rule ExampleSecret {
  meta:
    author = "researcher"
    confidence = 7
  tags: crypto, secret
  strings:
    $s = "SECRET_KEY"
  condition:
    $s
}
```

Using the CLI with a rules directory

Create a small detectors config `detectors.json`:

```json
{
  "adapters": [
    { "kind": "yara", "rules_dir": "rules" },
    { "kind": "binary-regex", "rules": { "magic": "MAGIC" } }
  ]
}
```

Run the detectors (uses `inputs.manifest.ndjson` produced by the preprocessor):

```powershell
python tools/run_detectors.py inputs.manifest.ndjson detector_results.ndjson detectors.json
```

Outputs & provenance

- `detector_results.ndjson` contains lines like:
  - path, offset, rule, details, engine
  - if YARA rules include `tags` or `meta` fields, those will be present as top-level
    `tags` and `meta` fields in each NDJSON line
  - rule filename (if available) will appear as `rule_file` and rule namespace as `rule_namespace`.
  - a `confidence` float is included for each detection. By default the adapter assigns a
    per-engine baseline (yara=0.9, binary-regex=0.65, regex=0.5, etc.). If a rule provides
    a `confidence` meta field, that value is used instead.

Troubleshooting

- If a YARA compile fails, the adapter will fall back to `rules_map` if provided, otherwise
  it will raise during initialization. Check the YARA syntax using `yara -C` or a linter.

CI

- YARA is optional in CI. If you want to test YARA-specific behavior in CI, add a job
  that installs `yara-python` and runs the yara integration tests. See `tests/test_yara_integration_optional.py`.
  \*\*\* End Patch
