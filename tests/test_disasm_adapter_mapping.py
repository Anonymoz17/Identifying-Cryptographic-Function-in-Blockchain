import json

from src.detectors.disasm_adapter import DisasmJsonAdapter


def test_disasm_adapter_uses_mappings(tmp_path):
    # create a fake preproc input and disasm artifact
    sha = "cafebabefeedface" * 2
    preproc_dir = tmp_path / "preproc" / sha
    preproc_dir.mkdir(parents=True, exist_ok=True)
    bin_path = preproc_dir / "input.bin"
    bin_path.write_bytes(b"\x90\x90\xc3")

    art_dir = tmp_path / "artifacts" / "disasm"
    art_dir.mkdir(parents=True, exist_ok=True)

    # two instructions with addresses 0 and 1; mapping translates address 1 -> offset 123
    dis = {
        "sha": sha,
        "disasm": [
            {"addr": 0, "mnemonic": "nop", "op_str": ""},
            {"addr": 1, "mnemonic": "ret", "op_str": ""},
        ],
        "mappings": [{"address": 0, "offset": 0}, {"address": 1, "offset": 123}],
    }
    p = art_dir / (sha + ".json")
    p.write_text(json.dumps(dis), encoding="utf-8")

    # write a simple rules file that matches 'ret'
    rules = [{"id": "ret_insn", "pattern": "ret"}]
    rules_p = tmp_path / "rules.json"
    rules_p.write_text(json.dumps(rules), encoding="utf-8")

    adapter = DisasmJsonAdapter(rules_path=str(rules_p))
    # scan the preproc input file
    dets = list(adapter.scan_files([str(bin_path)]))

    # find detection for the ret instruction and ensure offset uses mapping (123)
    found = [d for d in dets if d.rule == "disasm:ret_insn"]
    assert len(found) == 1
    assert found[0].offset == 123
