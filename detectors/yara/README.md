This directory contains YARA rules used by the project's YaraAdapter.

Guidance:

- Files should end with `.yar` and contain one or more `rule` blocks.
- Use `meta` fields for `author`, `description`, and `confidence` (0.0-1.0).
- Prefer regex matches with word boundaries and `nocase` to reduce false positives.
- Keep rules conservative; pair YARA hits with other detectors (Tree-sitter, disasm) when possible.

Example rule conventions:

- `crypto_keccak256` for keccak/keccak256 matches
- `crypto_sha3` for sha3 tokens
- `crypto_sha256` for sha256 matches

Testing:

- Integration tests live in `tests/test_yara_adapter_integration.py` and are skipped unless `yara-python` is installed.

CI:

- Add an optional CI job that installs `yara-python` and runs the integration tests when enabled.

OS notes:

- On some platforms (notably Windows) building `yara-python` from source may
  require additional tooling. Prefer using the Ubuntu runner in CI or
  provide a prebuilt wheel for Windows runners.
