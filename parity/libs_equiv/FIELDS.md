# Syscall-source field registry

Baseline: falcosecurity/libs `0.26.0-rc1`.

The `evt`, `proc`, `fd`, and `user` names were extracted from the static
`filtercheck_field_info` tables in:

- `sinsp_filtercheck_gen_event.cpp` and `sinsp_filtercheck_event.cpp`
- `sinsp_filtercheck_thread.cpp`
- `sinsp_filtercheck_fd.cpp`
- `sinsp_filtercheck_user.cpp`

The referenced libs tag does not expose a `container.*` filtercheck table:
those fields are supplied by the container plugin. The container entries are
therefore the explicitly supported Phase 3.1 plugin-field subset, not a claim
of complete plugin parity.

## Coverage

- [x] `evt.*`: 75/75 registered
- [x] `proc.*`: 70/70 registered
- [x] `fd.*`: 46/46 registered
- [x] `user.*`: 6/6 registered
- [x] `container.*`: 16/16 supported subset registered

Total registry baseline: 213/213 names.

Registry coverage means names and classes are exposed by
`Inspector::get_field_names()`. In Task 3.1, extraction reads values already
present in `Evt.fields`; process, FD, user, and container enrichment remains
deferred to Tasks 3.2–3.4.

Other field classes (`thread`, `group`, `syscall`, Kubernetes, cloud, and
plugin-specific classes) are deferred.
