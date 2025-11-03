# ruff: noqa
# ExportFunctions.py
# Ghidra headless script to export function list and basic metadata to JSON.
# Usage (headless):
#   analyzeHeadless <projectDir> <file> -postScript ExportFunctions.py -scriptPath <path> <out_dir>

import json
import os

# Ghidra scripts inherit helpers from GhidraScript; getScriptArgs() returns list
gsa = globals().get("getScriptArgs")
if callable(gsa):
    try:
        args = gsa()
    except Exception:
        args = []
else:
    args = []

# When linting outside of Ghidra (editor/static checks) provide harmless
# placeholders so linters do not report F821 undefined-name errors. These
# definitions are guarded by `if False` so they are never executed at runtime
# but they satisfy static analyzers.
if False:

    def getScriptArgs():
        return []

    currentProgram = None

    def getFunctionContaining(addr):
        return None


out_dir = args[0] if args else None
if not out_dir:
    print("ExportFunctions: missing output directory argument")
    exit(1)

out_dir = os.path.abspath(out_dir)
os.makedirs(out_dir, exist_ok=True)

prog_name = None
out_path = None
funcs = []
try:
    cp = globals().get("currentProgram")
    if cp is None:
        raise RuntimeError("currentProgram not available in this environment")
    prog_name = cp.getName()
    out_path = os.path.join(out_dir, prog_name + "_functions.json")
    fm = cp.getFunctionManager()
    listing = cp.getListing()
    it = fm.getFunctions(True)
    for f in it:
        try:
            entry = str(f.getEntryPoint())
            name = f.getName()
            try:
                sig = str(f.getSignature())
            except Exception:
                sig = None
            # attempt to gather basic metrics: instruction count and sample mnemonic
            instr_count = 0
            sample_mnemonics = []
            try:
                ins_iter = listing.getInstructions(f.getBody(), True)
                for i_idx, ins in enumerate(ins_iter):
                    try:
                        m = ins.getMnemonicString()
                        if i_idx < 5:
                            sample_mnemonics.append(m)
                        instr_count += 1
                    except Exception:
                        continue
            except Exception:
                instr_count = None
            # try to find callers and references counts
            try:
                refmgr = cp.getReferenceManager()
                refs_to = list(refmgr.getReferencesTo(f.getEntryPoint()))
                refs_from = list(refmgr.getReferencesFrom(f.getEntryPoint()))
                refs_to_count = len(refs_to)
                refs_from_count = len(refs_from)
            except Exception:
                refs_to_count = None
                refs_from_count = None

            # attempt to collect called functions (callees) by scanning references from function body
            called_funcs = []
            try:
                refs_from_full = list(refmgr.getReferencesFrom(f.getEntryPoint()))
                g_getFunc = globals().get("getFunctionContaining")
                for r in refs_from_full:
                    try:
                        to_addr = r.getToAddress()
                        callee = None
                        if callable(g_getFunc):
                            callee = g_getFunc(to_addr)
                        if callee is not None:
                            cname = callee.getName()
                            if cname and cname not in called_funcs:
                                called_funcs.append(cname)
                    except Exception:
                        continue
            except Exception:
                called_funcs = []

            # attempt to read a short sample of bytes at the entry (best-effort)
            sample_bytes_hex = None
            try:
                mem = cp.getMemory()
                entry_addr = f.getEntryPoint()
                if mem is not None and entry_addr is not None:
                    try:
                        # read up to 64 bytes; Ghidra may return a jarray('b')
                        b = mem.getBytes(entry_addr, 64)
                        try:
                            sample_bytes_hex = "".join(["%02x" % (x & 0xFF) for x in b])
                        except Exception:
                            sample_bytes_hex = bytes(b).hex()
                    except Exception:
                        sample_bytes_hex = None
            except Exception:
                sample_bytes_hex = None

            funcs.append(
                {
                    "name": name,
                    "entry": entry,
                    "signature": sig,
                    "instr_count": instr_count,
                    "sample_mnemonics": sample_mnemonics,
                    "refs_to": refs_to_count,
                    "refs_from": refs_from_count,
                    "called_functions": called_funcs,
                    "called_count": len(called_funcs),
                    "entry_bytes_sample": sample_bytes_hex,
                }
            )
        except Exception:
            continue
except Exception as e:
    print("ExportFunctions: error enumerating functions:", e)

try:
    with open(out_path, "w") as fh:
        json.dump({"program": prog_name, "functions": funcs}, fh, indent=2)
    print("Wrote functions to", out_path)
except Exception as e:
    print("ExportFunctions: failed to write:", e)
