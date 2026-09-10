# Task 3.5 Report: Engine evaluation against sinsp `Evt`

## Result

- Replaced the engine-local event double with a re-export of
  `rustagon_sinsp::Evt`; the dependency direction is engine → sinsp.
- `Inspector::inject` now supplies canonical `evt.type` values alongside
  process, FD, and container enrichment.
- `process_event` parses the loader's macro/list-expanded condition into the
  parser filter AST and evaluates it against extracted event fields.
- Evaluation supports AND/OR/NOT, exists, equality and membership, numeric or
  lexical comparisons, common string operators, glob/pmatch, and the
  `tolower`, `toupper`, and `basename` transformers.

## TDD and verification

The Inspector-to-engine integration test was added first and observed failing
at its alert assertion under the old string matcher. A second red cycle added
macro/list expansion to ensure `process_event` uses the compiled condition.

- `cargo test -p rustagon-engine`: pass (153 tests)
- `cargo test -p rustagon-sinsp`: pass (15 tests)
- `cargo clippy -p rustagon-engine -p rustagon-sinsp --all-targets -- -D warnings`: pass
- `git diff --check`: pass

## Metrics and phase exit

`libs_equiv` changed from 224/224 to 226/226 for the matching and non-matching
engine↔sinsp integration cases. The enrichment slices and engine wire-up are
green, so Phase 3 acceptance is complete.

## Remaining scope

This is an incremental evaluator, not complete Falco filter parity. Unknown
transformers and unresolved identifiers do not match, and richer Falco
multi-value/path semantics remain future work. Conditions are parsed during
event dispatch rather than cached as ASTs. A rule initially loaded disabled
falls back to its source condition when enabled later, so such a rule using
macros or lists requires future compiled-condition retention.
