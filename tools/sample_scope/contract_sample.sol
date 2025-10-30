// Solidity sample with several intentional crypto anti-patterns for testing
pragma solidity ^0.8.0;

contract SampleCrypto {
    // Hard-coded address (could be used for access control bypass testing)
    address public constant OWNER = 0x1111111111111111111111111111111111111111;

    // Uses block.timestamp for randomness -> predictable
    function getPseudoRandom(uint256 max) public view returns (uint256) {
        // insecure: block.timestamp is not a secure source of entropy
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % max;
    }

    // Example of keccak usage and explicit hashing pattern
    function hashData(bytes memory data) public pure returns (bytes32) {
        return keccak256(data); // detectors should catch keccak/sha3 patterns
    }

    // Demonstrate ecrecover misuse: missing proper message prefix
    function recoverSigner(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        // Insecure: using raw hash directly without Ethereum signed message prefix
        // Attackers can craft signatures if not using the standard prefixed message
        return ecrecover(hash, v, r, s);
    }

    // Hard-coded symmetric key (commented) to emulate embedded secret
    // NOTE: this is intentionally insecure to exercise detectors
    // SECRET_KEY: 0xdeadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe

    // Example function that returns true (logic error) and uses outdated patterns
    function verify(bytes32 hash) public pure returns (bool) {
        // Broken verification logic — placeholder for auditor to highlight
        bytes32 h = keccak256(abi.encodePacked(hash));
        // incorrectly returns true for all inputs
        return true;
    }
}
