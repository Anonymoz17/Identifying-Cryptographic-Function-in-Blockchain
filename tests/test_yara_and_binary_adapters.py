from pathlib import Path

from src.detectors.adapter import BinaryRegexAdapter, YaraAdapter


def test_yara_adapter_fallback(tmp_path: Path):
    # create a small text file
    f = tmp_path / "a.txt"
    f.write_text("this file contains SECRET_TOKEN here", encoding="utf-8")

    # initialize YaraAdapter with a rules_map fallback
    adapter = YaraAdapter(rules_map={"secret": "SECRET_TOKEN"})
    found = list(adapter.scan_files([str(f)]))
    assert any(d.rule == "secret" for d in found)


def test_binary_regex_adapter(tmp_path: Path):
    # create a small binary file containing bytes 0x00 0xDE 0xAD 0xBE 0xEF 0x00
    data = bytes([0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00])
    f = tmp_path / "b.bin"
    f.write_bytes(data)

    # pattern expressed as bytes
    adapter = BinaryRegexAdapter({"deadbeef": b"\xDE\xAD\xBE\xEF"})
    found = list(adapter.scan_files([str(f)]))
    assert len(found) == 1
    d = found[0]
    assert d.rule == "deadbeef"
    assert d.offset == 1
