# Task 1.3 Report: Falco filter expression parser

## Status

Implemented a public filter AST, nom-based parser, and canonical printer in
`rustagon-parser`. The grammar supports `not > and > or` precedence, nested
parentheses, bare and quoted values, value lists, unary `exists`, and all
required binary operators.

## TDD evidence

### RED

Added `rustagon-parser/tests/filter_parse_basic.rs` first, then ran:

```text
cargo test -p rustagon-parser --test filter_parse_basic
```

Exit code 101: compilation failed with the expected missing-feature error,
`could not find filter in rustagon_parser`.

### GREEN

After implementing the AST, parser, printer, and public module export, reran the
targeted test. Exit code 0: 7 passed, 0 failed.

## Final verification

Ran:

```text
cargo test -p rustagon-parser
```

Exit code 0: 8 unit tests and 7 integration tests passed; doc-tests had zero
failures.

## Scope and concerns

- Printing preserves quoted tokens and emits minimal precedence-required
  parentheses with stable operator/list spacing.
- The parser intentionally does not replace the engine's current string-based
  normalization in this task.
- No eBPF code was changed.
- Workspace-wide `cargo fmt --all -- --check` still reports pre-existing
  formatting differences outside this task; all newly created parser and test
  files were formatted directly.

Commit subject: `feat(parser): Falco filter expression grammar`
