Run preprocessing helpers

This folder contains small helper scripts for running preprocessing and detectors on a case workspace.

run_preproc.py

- Usage: run the script from the repository root. Use `--workdir` to point to the case workspace.
- Examples:

```powershell
# basic run
python tools\run_preproc.py --workdir ./case_demo

# read a manifest and build AST/disasm caches with verbose logging
python tools\run_preproc.py --workdir ./case_demo --manifest ./case_demo/inputs.manifest.json --build-ast --build-disasm -v
```

The script configures logging (default INFO). Use `-v` or `--log-level DEBUG` for more details. It is a thin wrapper around `auditor.preproc.preprocess_items`.
