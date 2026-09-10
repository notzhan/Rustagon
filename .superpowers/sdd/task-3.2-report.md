# Task 3.2 Report: Process table / thread table

## Outcome

- Added a pure-Rust `RawEventKind` model for exec, clone/fork, exit, and other events.
- Added `ThreadInfo` and a tid-keyed `ProcessTable` with PID and parent lookup.
- `Inspector::inject` now updates process state and enriches `Evt` with process
  identity, executable, command-line, parent, and indexed ancestor fields.
- Exit events are enriched before their thread entry is removed.

## TDD evidence

The three synthetic sequence tests were added first. The initial
`cargo test -p rustagon-sinsp` failed because `RawEventKind` and the `kind`
field did not exist. After the minimal event model and table implementation,
all seven `rustagon-sinsp` tests passed.

## Behavioral coverage

1. Exec populates `proc.pid`, `proc.ppid`, `proc.name`, `proc.exe`,
   `proc.exepath`, and `proc.cmdline`.
2. Fork inheritance resolves `proc.pname`, `proc.aname`, and indexed
   `proc.aname[0..]` lineage.
3. Thread clone inherits process metadata; exit removes only the exiting tid
   after enriching that event.

## Metrics

`libs_equiv` is 216/216: 213 registry-name cases plus 3 process enrichment
behavioral cases.

## Notes

`RawEventKind::Clone` models both process fork and thread clone: a differing
child PID creates a child process, while the parent's PID creates another
thread in the same process.
