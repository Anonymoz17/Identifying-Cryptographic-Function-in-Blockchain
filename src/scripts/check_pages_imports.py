import sys, traceback, importlib
sys.path.insert(0, 'src')
modules=['pages.login','pages.dashboard','pages.landing','pages.setup','pages.advisor','pages.analysis','pages.auditor']
for m in modules:
    try:
        importlib.invalidate_caches()
        importlib.import_module(m)
        print('OK:', m)
    except Exception as e:
        print('FAIL:', m, type(e).__name__, e)
        traceback.print_exc()
