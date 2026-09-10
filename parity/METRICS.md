# Rustagon ↔ Falco Parity Metrics

| Suite | Pass | Total | % |
|-------|------|-------|---|
| falco_unit_engine | 152 | 152 | 100 |
| falco_unit_app | 81 | 81 | 100 |
| libs_equiv | 221 | 221 | 100 |
| e2e_evtgen | 0 | 20 | 0 |

Totals from Falco tip inventory (Task 0.2). `libs_equiv` measures the 213-field
Task 3.1 syscall-source registry baseline plus 8 synthetic enrichment cases:
3 process/thread cases covering exec, fork ancestry, thread clone, and exit; and
5 FD cases covering open, close, dup, connect, and accept.
