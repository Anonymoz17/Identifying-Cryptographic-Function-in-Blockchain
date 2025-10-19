// Minimal crypto fingerprint YARA rules (MVP)

rule crypto_keccak256
{
    meta:
        author = "repo"
        description = "keccak/keccak256 usage (Solidity / JS)"
        confidence = 0.7
    strings:
        $s1 = /\bkeccak256\b/ nocase
        $s2 = /\bkeccak\b/ nocase
    condition:
        any of ($s*)
}

rule crypto_sha3
{
    meta:
        author = "repo"
        description = "sha3 or sha3(...) token usage"
        confidence = 0.6
    strings:
        $s1 = /\bsha3\b/ nocase
    condition:
        $s1
}

rule crypto_sha256
{
    meta:
        author = "repo"
        description = "sha256 usage"
        confidence = 0.7
    strings:
        $s1 = /\bsha256\b/ nocase
    condition:
        $s1
}

rule crypto_aes
{
    meta:
        author = "repo"
        description = "AES usage keywords"
        confidence = 0.5
    strings:
        $s1 = /\baes\b/ nocase
        $s2 = /AES_encrypt|AES_decrypt/ nocase
    condition:
        any of ($s*)
}
