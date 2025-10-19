;; Solidity tree-sitter queries (MVP)
;; These are example queries targeting common crypto-related constructs.
;; They are intentionally conservative and should be reviewed and extended
;; with more precise AST shapes for production use.

;; Solidity tree-sitter queries (refined)
;; Capture common crypto calls with argument shapes.

;; keccak256 / sha3 called with abi.encodePacked(...) or string literal
(call_expression
	function: (identifier) @keccak_call
	arguments: (argument_list
		(expression_list (expression (call_expression
			function: (member_expression
				;; handle abi.encodePacked and nested member expressions like X.abi.encodePacked
				(member_expression
					object: (identifier) @maybe_obj
					property: (identifier) @maybe_prop)
				property: (identifier) @abi_prop)
			arguments: (argument_list (expression_list (expression (string_literal) @keccak_str))))))))
(#match? @keccak_call "(?i)^(keccak256|sha3)$")

;; sha256 called with abi.encodePacked or other expressions
(call_expression
	function: (identifier) @sha256_call
	arguments: (argument_list (expression_list (expression) @sha256_arg)))
(#match? @sha256_call "(?i)^sha256$")

;; ecrecover and recover
(call_expression
	function: (identifier) @ecrecover_call
	arguments: (argument_list (expression_list (expression) @ecrecover_arg)))
(#match? @ecrecover_call "(?i)^(ecrecover|recover)$")

;; hex and address literal captures (heuristic)
(hex_literal) @hex_literal
;; capture address-like hex literals (0x followed by 40 hex chars) - heuristic
(hex_literal) @address_literal
(#match? @address_literal "(?i)^0x[0-9a-f]{40}$")
(number) @number_literal
(#match? @number_literal "^[0-9]+$")

;; string literal capture for easier snippet extraction
(string_literal) @string_literal

;; NOTE: These are refined yet still conservative queries; expand with
;; more precise node shapes and type checks as needed.
