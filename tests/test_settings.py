from pathlib import Path

from settings import (
    get_canonical_workdir,
    get_default_workdir,
    reset_default_workdir,
    set_default_workdir,
    settings_path,
)


def test_set_and_reset_workdir(tmp_path, monkeypatch):
    # Ensure settings write to a temp location by overriding platform env vars
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    # reset to ensure clean state
    try:
        reset_default_workdir()
    except Exception:
        pass

    canonical = get_canonical_workdir()
    assert canonical.exists()

    # set custom workdir
    custom = tmp_path / "custom_cases"
    custom_str = str(custom)
    set_default_workdir(custom_str)
    got = get_default_workdir()
    assert Path(got).resolve() == custom.resolve()

    # settings file should exist
    sp = settings_path()
    assert sp.exists()

    # reset and verify canonical is returned again
    reset_default_workdir()
    got2 = get_default_workdir()
    assert Path(got2).resolve() == Path(canonical).resolve()
