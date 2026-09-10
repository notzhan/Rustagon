# Rustagon ↔ Falco Parity Metrics

| Suite | Pass | Total | % |
|-------|------|-------|---|
| falco_unit_engine | 152 | 152 | 100 |
| falco_unit_app | 81 | 81 | 100 |
| libs_equiv | 226 | 226 | 100 |
| e2e_evtgen | 20 | 20 | 100 |

Totals from Falco tip inventory (Task 0.2). `libs_equiv` measures the 213-field
Task 3.1 syscall-source registry baseline plus 11 synthetic enrichment cases:
3 process/thread cases covering exec, fork ancestry, thread clone, and exit; and
5 FD cases covering open, close, dup, connect, and accept; and 3 container cases
covering cgroup ID extraction, successful fixture enrichment, and lookup misses.
Two engine↔sinsp cases cover a compiled rule matching an enriched event and
rejecting a non-match. Phase 3 acceptance is complete.

`e2e_evtgen` measures offline synthetic HostRunner behavioral parity for one
expanded representative from each of the 20 suite YAML files. It does not
claim live `modern_ebpf`/CAP_BPF coverage; that privileged capture path remains
deferred until full syscall arguments and process/container metadata are
available.
