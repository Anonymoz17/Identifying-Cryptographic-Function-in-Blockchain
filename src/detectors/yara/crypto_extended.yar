/* Extended crypto-oriented yara rules (text/binary friendly) */
rule Crypto_AES
{
    meta:
        description = "Match AES-related identifiers"
    strings:
        $s1 = "AES"
        $s2 = "AES_encrypt"
        $s3 = "rijndael"
    condition:
        any of them
}

rule Crypto_SHA
{
    meta:
        description = "Match common SHA identifiers"
    strings:
        $s1 = "SHA1"
        $s2 = "SHA256"
        $s3 = "sha256"
        $s4 = "sha3"
        $s5 = "keccak"
    condition:
        any of them
}

rule Crypto_HMAC
{
    meta:
        description = "Match HMAC identifiers"
    strings:
        $s1 = "HMAC"
        $s2 = "hmac"
    condition:
        any of them
}

rule Crypto_PKC
{
    meta:
        description = "Match public-key crypto names"
    strings:
        $rsa = "RSA"
        $ecdsa = "ECDSA"
        $modexp = "modexp"
    condition:
        any of them
}

rule Crypto_Solidity
{
    meta:
        description = "Solidity-specific crypto functions"
    strings:
        $keccak = "keccak256"
        $ecrecover = "ecrecover"
    condition:
        any of them
}
