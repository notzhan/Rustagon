# Task 3.3 Report: FD table + file/net fields

## Result

- Added synthetic `Open`, `Close`, `Dup`, `Connect`, and `Accept` raw event kinds.
- Added a per-thread FD table with inherited snapshots on clone and cleanup on exit.
- File events expose `fd.num`, `fd.name`, `fd.type=file`, and `fd.typechar=f`.
- IPv4 socket events expose tuple `fd.name`, `fd.type=ipv4`, `fd.typechar=4`,
  `fd.cip/cport`, `fd.sip/sport`, and the brief's `fd.dip/dport` aliases.
- Close events are enriched before their FD entry is removed; dup entries remain
  valid independently after the original descriptor closes.

## Falco compatibility

Falco libs 0.26 formats IPv4 tuples as
`client_ip:client_port->server_ip:server_port`. Its `fd.sip/sport` names mean
server address/port, while `fd.cip/cport` mean client address/port. The brief
also names `fd.dip/dport`, which are not registered Falco fields, so Rustagon
emits them as destination aliases without changing the Falco field baseline.

## TDD and verification

The five behavioral tests were added first and failed because the raw event
variants and FD behavior did not exist. After implementation:

- `cargo test -p rustagon-sinsp -p rustagon-scap`: pass (12 sinsp tests, 0 scap tests)
- `cargo clippy -p rustagon-sinsp -p rustagon-scap --all-targets -- -D warnings`: pass
- `git diff --check`: pass

## Metrics

`libs_equiv` changed from 216/216 to 221/221 by adding five passing behavioral
cases: open, close, dup, connect, and accept.

## Remaining scope

Socket enrichment currently models IPv4 connected tuples only. IPv6, Unix
sockets, listening sockets, protocol/service resolution, and local/remote
interface classification remain outside Task 3.3's minimum acceptance scope.
