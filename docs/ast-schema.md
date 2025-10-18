AST cache schema and usage

The preprocessor writes AST caches to `artifacts/ast/<sha>.json`. These
files are intended to be consumed by detectors that need a fast way to
enumerate function symbols and their source spans.

Shape (summary)

- `sha` (string): hex SHA256 of the original input item.
- `ast` (object|null): if null, no AST was produced. Otherwise contains:
  - `functions` (array): list of function descriptors. Each descriptor has:
    - `name` (string): function identifier.
    - `lang` (string): language hint (e.g., `solidity`, `go`).
    - optional `start_byte`/`end_byte` (integers): byte offsets into the
      file when available (Tree-sitter provides these). Regex fallbacks
      may omit offsets and only provide `name` and `lang`.

Notes for detectors

- Treat `ast` as advisory: function names can be incomplete. Always verify
  that the referenced span is present in the source file before trusting
  offsets.
- The AST cache is produced using Tree-sitter when available and falls
  back to a regex heuristic otherwise. Consumers should handle both cases.

See `schemas/ast.schema.json` for a machine-readable schema.
