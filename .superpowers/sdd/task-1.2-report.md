# Task 1.2 Report: Macro expansion and condition append

## Status

Implemented Falco macro expansion for compiled sequence-rule conditions and
`override.condition: append` for both macros and rules. Macro definitions remain
available in `CompiledRuleset.macros`.

The resolver expands complete macro identifiers, supports nested macros, avoids
rewriting field-name components, and reports recursive expansion as an error.
List expansion and equality normalization still run after macro expansion.

## TDD evidence

### RED

Created `rustagon-engine/tests/rule_loader_condition_append.rs` from Falco's
`condition_append` fixture, then ran:

```text
cargo test -p rustagon-engine --test rule_loader_condition_append
```

Exit code: 101. The test failed before its condition assertion with:

```text
["missing field `items`"]
test result: FAILED. 0 passed; 1 failed
```

This showed the loader could not deserialize `override.condition`.

### GREEN

After implementing condition append and macro resolution, reran the same
command. Exit code: 0:

```text
test condition_append ... ok
test result: ok. 1 passed; 0 failed
```

The compiled condition exactly matches Falco:

```text
(evt.type = open and (((proc.aname = sshd and proc.name != sshd) or proc.name = systemd-logind or proc.name = login) or proc.name = ssh))
```

## Final verification

Ran:

```text
cargo fmt -p rustagon-engine
cargo test -p rustagon-engine
cargo clippy -p rustagon-engine --all-targets -- -D warnings
```

All commands exited 0. Engine tests: 8 passed, 0 failed; doc-tests: 0 failed.
The existing list append, operator normalization, malformed sequence, and
legacy multi-document fallback regressions remain green.

## Scope and concerns

- Macro expansion remains a condition-aware string pass rather than an AST
  transformation, matching the current loader architecture.
- Recursive macro references return a load error.
- No eBPF or core files were changed.

Commit subject: `feat(engine): macro expansion and condition append`
