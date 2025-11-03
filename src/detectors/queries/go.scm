;; Go tree-sitter queries (MVP)
;; Target common crypto package usages like crypto/sha256 and sha3/keccak.

;; Match calls like sha256.Sum256(...), crypto.SHA256(...)
(call_expression
	function: (selector_expression
		field: (identifier) @method_name))

;; Match plain function identifiers (e.g., Sum256, NewKeccak256)
(call_expression
	function: (identifier) @func_ident)

;; capture identifiers for heuristics
(identifier) @identifier
