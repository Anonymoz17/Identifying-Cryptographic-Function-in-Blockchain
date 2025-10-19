from pathlib import Path

from src.detectors.adapter import RegexAdapter, SimpleSemgrepAdapter


def test_regex_adapter(tmp_path: Path):
    f = tmp_path / "a.sol"
    f.write_text("function foo() { return 1 }\nfunction bar() {}", encoding="utf-8")
    adapter = RegexAdapter({"func": r"function\s+([A-Za-z0-9_]+)"})
    found = list(adapter.scan_files([str(f)]))
    assert any(d.rule == "func" for d in found)


def test_semgrep_adapter(tmp_path: Path):
    f = tmp_path / "b.go"
    f.write_text("package main\nfunc Bar() {}\n", encoding="utf-8")
    adapter = SimpleSemgrepAdapter({"bar_call": "func Bar()"})
    found = list(adapter.scan_files([str(f)]))
    assert len(found) == 1
    assert found[0].rule == "bar_call"
