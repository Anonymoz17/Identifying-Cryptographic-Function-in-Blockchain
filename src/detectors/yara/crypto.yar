/* Minimal YARA rules for MVP static crypto detection
   This is intentionally simple and should be replaced with curated rules.
*/
rule Crypto_AES_Sha
{
    meta:
        author = "mvp"
        description = "Detect common crypto keywords (AES, SHA)"

    strings:
        $aes = "AES"
        $aes_lower = "aes"
        $sha1 = "sha1"
        $sha256 = "sha256"
        $keccak = "keccak"

    condition:
        any of ($*)
}
rule sha3_calls {
    meta:
        author = "auto"
        description = "detect sha3/keccak invocations by literal tokens"
        confidence = "0.6"
    strings:
        $s1 = /\b(sha3|keccak256)\b/i
        $s2 = /\bsha256\b/i
    condition:
        any of them
}
