rule sha3_calls {
    meta:
        author = "auto"
        description = "detect sha3/keccak invocations by literal tokens"
        confidence = 0.6
    strings:
        $s1 = /\b(sha3|keccak256)\b/i
        $s2 = /\bsha256\b/i
    condition:
        any of them
}
