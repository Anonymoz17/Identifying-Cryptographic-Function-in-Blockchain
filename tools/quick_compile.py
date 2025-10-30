import compileall
import os
import sys

errs = 0
stack = ["src"]

while stack:
    p = stack.pop()
    try:
        with os.scandir(p) as it:
            for e in it:
                if e.is_dir():
                    if e.name in ("node_modules", ".git"):
                        continue
                    stack.append(e.path)
                elif e.name.endswith(".py"):
                    ok = compileall.compile_file(e.path, quiet=1)
                    if not ok:
                        print("FAILED:", e.path)
                        errs += 1
    except Exception:
        # ignore permission errors or removed files during walk
        pass

if errs:
    sys.exit(1)

print("Compile check: OK")
