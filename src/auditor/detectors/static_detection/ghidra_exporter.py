"""Bundled Ghidra exporter script (Jython) used by the headless adapter.

This string is written to disk and passed to Ghidra's -postScript option when
performing an export. It's intentionally minimal: enumerate functions and
write a JSON array of simple dicts to the given output path.

The script expects a single argument: the absolute output file path to write.
When executed inside Ghidra (analyzeHeadless), pass the filename as an arg.
"""

EXPORTER_SCRIPT = r"""
# Ghidra exporter (Jython)
from __future__ import print_function
import json
import sys
import hashlib

def _md5(s):
    try:
        m = hashlib.md5()
        m.update(s.encode('utf-8'))
        return m.hexdigest()
    except Exception:
        return None

try:
    out_path = sys.argv[-1]
except Exception:
    out_path = 'ghidra-functions.json'

functions = []
try:
    fm = currentProgram.getFunctionManager()
    it = fm.getFunctions(True)
    for f in it:
        try:
            name = f.getName()
            addr = str(f.getEntryPoint())
            # size in bytes (approx): use number of addresses in body
            try:
                size = int(f.getBody().getNumAddresses())
            except Exception:
                size = 0

            # prototype: try signature, fallback to empty
            proto = ''
            try:
                sig = f.getSignature()
                if sig:
                    proto = str(sig)
                else:
                    proto = f.getPrototypeString() if hasattr(f, 'getPrototypeString') else ''
            except Exception:
                try:
                    proto = f.getPrototypeString() if hasattr(f, 'getPrototypeString') else ''
                except Exception:
                    proto = ''

            # calling convention (best-effort)
            cc = ''
            try:
                if hasattr(f, 'getCallingConventionName'):
                    cc = f.getCallingConventionName()
                elif hasattr(f, 'getCallingConvention'):
                    cc = str(f.getCallingConvention())
            except Exception:
                cc = ''

            # disassembly snippet: attempt to gather first few instructions
            disasm = ''
            try:
                listing = currentProgram.getListing()
                instr_iter = listing.getInstructions(f.getBody(), True)
                parts = []
                count = 0
                while instr_iter.hasNext() and count < 8:
                    instr = instr_iter.next()
                    try:
                        parts.append(str(instr))
                        count += 1
                    except Exception:
                        break
                disasm = '\n'.join(parts)
            except Exception:
                disasm = ''

            # parameters: try to enumerate parameter names and types
            params = []
            try:
                pars = f.getParameters()
                for p in pars:
                    try:
                        pname = p.getName() if callable(getattr(p, 'getName', None)) else str(p)
                        ptype = ''
                        try:
                            if hasattr(p, 'getDataType'):
                                ptype = str(p.getDataType())
                            else:
                                ptype = str(p.getPrototypeString())
                        except Exception:
                            ptype = ''
                        params.append({'name': pname, 'type': ptype})
                    except Exception:
                        continue
            except Exception:
                params = []

            # small function hash to identify changes: name+addr+proto+size
            fh_seed = '%s|%s|%s|%d' % (name, addr, proto, size)
            fhash = _md5(fh_seed) or ''

            fdict = {
                'name': name,
                'address': addr,
                'size': size,
                'prototype': proto,
                'parameters': params,
                'calling_convention': cc,
                'disasm': disasm,
                'function_hash': fhash,
            }

            functions.append(fdict)

            # write per-function file into a functions/ subdir next to out_path (best-effort)
            try:
                import os as _os
                base_dir = _os.path.dirname(out_path) or '.'
                funcs_dir = _os.path.join(base_dir, 'functions')
                try:
                    _os.makedirs(funcs_dir)
                except Exception:
                    pass
                per_path = _os.path.join(funcs_dir, fhash + '.json')
                with open(per_path, 'w') as pf:
                    json.dump(fdict, pf)
            except Exception:
                # ignore per-file write failures
                pass
        except Exception:
            # best-effort per-function
            pass
except Exception:
    # not running inside Ghidra or API unavailable
    pass

try:
    with open(out_path, 'w') as fh:
        json.dump(functions, fh)
except Exception:
    # best-effort
    pass
"""
