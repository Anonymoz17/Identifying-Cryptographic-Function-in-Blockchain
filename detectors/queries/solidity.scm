;; Solidity tree-sitter queries (MVP)
;; These are example queries targeting common crypto-related constructs.
;; They are intentionally conservative and should be reviewed and extended
;; with more precise AST shapes for production use.

;; Capture keccak/sha3 calls and their argument literals when possible
(call_expression
	function: (identifier) @sha_call
	arguments: (argument_list
		(expression_list (expression (string_literal) @sha_arg))))
(#match? @sha_call "(?i)^(keccak256|sha3)$")

;; Capture sha256 calls
(call_expression
	function: (identifier) @sha256_call
	arguments: (argument_list (expression_list (expression) @sha256_arg)))
(#match? @sha256_call "(?i)^sha256$")

;; Capture ecrecover and friend functions
(call_expression
	function: (identifier) @ecrecover_call
	arguments: (argument_list (expression_list (expression) @ec_arg)))
(#match? @ecrecover_call "(?i)^(ecrecover|recover)$")

;; Fallback capture for identifiers (helpful for heuristics)
(identifier) @identifier

;; NOTE: These queries are conservative examples. For production-grade rules,
;; refine the node shapes and add additional captures (addresses, call targets,
;; numeric/hex literals) to increase precision.
