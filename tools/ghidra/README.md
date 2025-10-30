# Ghidra integration notes

This folder contains a headless Ghidra export script and usage helpers for
integrating Ghidra exports into the static detection pipeline.

Files

- `ExportFunctions.py`: Jython script to be executed by Ghidra's
  `analyzeHeadless` with `-postScript`. It exports a JSON file containing
  functions and lightweight metrics into a specified output directory.

  New fields exported (best-effort):

  - `instr_count`: approximate number of instructions in function
  - `sample_mnemonics`: first few instruction mnemonics for quick inspection
  - `refs_to`, `refs_from`: counts of references to/from the function
  - `called_functions`: list of resolved callee function names referenced from the function body
  - `called_count`: number of unique called functions
  - `entry_bytes_sample`: hex string of the first ~64 bytes at the function entry (if readable)

- `README.md`: this file.

## Usage

1. Ensure Ghidra is installed and `analyzeHeadless` is on PATH or set
   `GHIDRA_INSTALL_DIR` to point to your Ghidra installation.

2. Run the provided helper to print commands (dry-run):

```powershell
python ..\run_ghidra_headless.py --case ..\case_demo\CASE-001
```

3. To execute the commands (this will run Ghidra headless and produce
   `artifacts/ghidra_exports/<sha>/*_functions.json` files):

```powershell
python ..\run_ghidra_headless.py --case ..\case_demo\CASE-001 --run
```

4. Re-run detectors (the `GhidraAdapter` is wired into `tools/run_detectors_local.py`)
   to pick up `ghidra` engine detections.

## Notes

- The ExportFunctions.py script uses Ghidra scripting APIs (e.g. `currentProgram`)
  and therefore only runs inside the Ghidra headless environment.
- The exports are intentionally lightweight and best-effort to keep headless
  runs fast. You can enhance `ExportFunctions.py` to include more features
  (xrefs, basic block metrics, instruction samples) as needed.
