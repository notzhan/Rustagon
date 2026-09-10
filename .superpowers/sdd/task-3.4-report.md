# Task 3.4 Report: Container metadata MVP

## Result

- Added common Docker/containerd cgroup-path container ID extraction.
- Added an injectable `ContainerLookup` interface and a pure-Rust filesystem
  fixture implementation using `name`/`image` metadata files.
- Added per-thread container state to `Inspector`, inherited on clone and
  removed on exit.
- Events with a resolved cgroup expose `container.id`; successful lookups also
  expose `container.name` and `container.image`.

## TDD and verification

The three integration tests were added first and failed because the container
module and inspector API did not exist. A self-review regression test was then
changed first and observed failing before preserving IDs across lookup misses.

- `cargo test -p rustagon-sinsp`: pass (15 tests)
- `cargo clippy -p rustagon-sinsp --all-targets -- -D warnings`: pass
- `git diff --check`: pass

## Metrics

`libs_equiv` changed from 221/221 to 224/224 by adding three passing behavioral
cases: cgroup ID extraction, fixture-backed metadata enrichment, and lookup
miss behavior.

## Remaining scope

Docker/containerd socket clients and automatic `/proc/<tid>/cgroup` reads are
not included. Callers provide the cgroup path through `set_container_cgroup`.
The fixture lookup reads on each enriched event; runtime caching belongs with a
future socket/filesystem production lookup.
