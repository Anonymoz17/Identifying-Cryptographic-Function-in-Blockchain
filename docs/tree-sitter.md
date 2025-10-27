Tree-sitter setup for AST caching

````markdown
Tree-sitter setup for AST caching

This project supports Tree-sitter for producing higher-quality AST caches for
languages like Solidity and Go. The preprocessor will attempt to load a
compiled language bundle called `tree_sitter_langs.so` from the `workdir`
or the repository root. If the library or Tree-sitter bindings are not
available the preprocessor falls back to a fast regex-based heuristic and
remains fully functional.

Overview (non-OS-specific)

- Install the Tree-sitter CLI (npm) and fetch the language grammars you need.
- Generate language parsers and link them into a single shared library
  named `tree_sitter_langs.so` and place it in the repo root or the
  preprocessing workdir.

Docker-based example (cross-platform)

You can build the language bundle inside a Docker container to avoid
platform-specific toolchain steps on developer machines. The following is a
minimal example Dockerfile you can adapt for your needs:

```dockerfile
FROM node:18-bullseye
RUN apt-get update && apt-get install -y build-essential gcc
WORKDIR /work
RUN npm install -g tree-sitter-cli
# clone grammars into .treesitter and generate the C parsers there
# then compile the .c files into a shared library (one-time operation)
# Example steps (run inside the container):
# git clone https://github.com/tree-sitter/tree-sitter-go .treesitter/tree-sitter-go
# git clone https://github.com/tree-sitter/tree-sitter-solidity .treesitter/tree-sitter-solidity
# (cd .treesitter/tree-sitter-go && tree-sitter generate)
# (cd .treesitter/tree-sitter-solidity && tree-sitter generate)
# gcc -O3 -fPIC -shared -o /work/tree_sitter_langs.so \
#     .treesitter/tree-sitter-go/src/parser.c .treesitter/tree-sitter-solidity/src/parser.c
```
````

Notes

- The Docker approach isolates the native build from host platform tooling.
- You may also build the shared object natively if you have a matching
  C toolchain. The repository purposefully avoids committing platform
  binaries — the AST integration is optional and the code falls back when
  Tree-sitter is not present.

If you produce `tree_sitter_langs.so` and place it in the repo root or a
workdir, `build_ast_cache()` will attempt to load solidity and go
parsers automatically and generate richer AST caches.

```

```
