from src.detectors.tree_sitter_utils import is_ethereum_address, normalize_hex_literal


def test_normalize_hex_literal_basic():
    assert normalize_hex_literal("0x1234ABCD") == "1234abcd"
    assert normalize_hex_literal("0Xdeadbeef") == "deadbeef"
    assert normalize_hex_literal('"0x12_34"') == "1234"
    assert normalize_hex_literal("0x") is None
    assert normalize_hex_literal("") is None


def test_normalize_hex_literal_variants():
    # underscores and punctuation
    assert normalize_hex_literal("(0x12_34);") == "1234"
    assert normalize_hex_literal("/* 0xAB_CD_EF */") == "abcdef"
    # suffix-like tokens (e.g., 0xdeadbeefU) where trailing non-hex should be ignored
    assert normalize_hex_literal("0x1234abcdU") == "1234abcd"
    # embedded in text pick the longest hex chunk
    assert normalize_hex_literal("prefix0x11_22middle0x3344") == "3344"


def test_is_ethereum_address():
    assert is_ethereum_address("0x1234567890abcdef1234567890abcdef12345678")
    assert not is_ethereum_address("0xdead")
    assert not is_ethereum_address("nothex")
