use core::mem::{align_of, size_of};

use rustagon_common::ppm::{PpmEventHeader, PpmEventType};

#[test]
fn starter_event_ids_match_falco_libs_0_26_rc1() {
    assert_eq!(PpmEventType::EXECVE_E.raw(), 292);
    assert_eq!(PpmEventType::EXECVE_X.raw(), 293);
    assert_eq!(PpmEventType::OPENAT_E.raw(), 306);
    assert_eq!(PpmEventType::OPENAT_X.raw(), 307);
    assert_eq!(PpmEventType::CONNECT_E.raw(), 22);
    assert_eq!(PpmEventType::CONNECT_X.raw(), 23);
    assert_eq!(PpmEventType::ACCEPT_E.raw(), 246);
    assert_eq!(PpmEventType::ACCEPT_X.raw(), 247);
    assert_eq!(PpmEventType::ACCEPT4_E.raw(), 388);
    assert_eq!(PpmEventType::ACCEPT4_X.raw(), 389);
    assert_eq!(PpmEventType::CLOSE_E.raw(), 4);
    assert_eq!(PpmEventType::CLOSE_X.raw(), 5);
    assert_eq!(PpmEventType::CLONE_E.raw(), 222);
    assert_eq!(PpmEventType::CLONE_X.raw(), 223);
    assert_eq!(PpmEventType::CLONE3_E.raw(), 334);
    assert_eq!(PpmEventType::CLONE3_X.raw(), 335);
    assert_eq!(PpmEventType::FORK_E.raw(), 224);
    assert_eq!(PpmEventType::FORK_X.raw(), 225);
    assert_eq!(PpmEventType::EXIT_E.raw(), 186);
    assert_eq!(PpmEventType::EXIT_X.raw(), 187);
    assert_eq!(PpmEventType::EXIT_GROUP_E, PpmEventType::EXIT_E);
    assert_eq!(PpmEventType::EXIT_GROUP_X, PpmEventType::EXIT_X);
}

#[test]
fn event_header_matches_packed_ppm_wire_layout() {
    assert_eq!(size_of::<PpmEventType>(), 2);
    assert_eq!(align_of::<PpmEventType>(), 2);
    assert_eq!(size_of::<PpmEventHeader>(), 26);
    assert_eq!(align_of::<PpmEventHeader>(), 1);
}

#[test]
fn event_header_constructor_uses_event_parameter_count() {
    let header = PpmEventHeader::new(10, 20, 30, PpmEventType::OPENAT_X);
    let PpmEventHeader {
        timestamp_ns,
        tid,
        len,
        event_type,
        nparams,
    } = header;

    assert_eq!(timestamp_ns, 10);
    assert_eq!(tid, 20);
    assert_eq!(len, 30);
    assert_eq!(event_type, PpmEventType::OPENAT_X);
    assert_eq!(nparams, 7);
}

#[test]
fn starter_parameter_counts_match_falco_event_table() {
    assert_eq!(PpmEventType::EXECVE_E.parameter_count(), 1);
    assert_eq!(PpmEventType::EXECVE_X.parameter_count(), 31);
    assert_eq!(PpmEventType::OPENAT_E.parameter_count(), 4);
    assert_eq!(PpmEventType::OPENAT_X.parameter_count(), 7);
    assert_eq!(PpmEventType::CONNECT_E.parameter_count(), 2);
    assert_eq!(PpmEventType::CONNECT_X.parameter_count(), 4);
    assert_eq!(PpmEventType::ACCEPT_E.parameter_count(), 0);
    assert_eq!(PpmEventType::ACCEPT_X.parameter_count(), 5);
    assert_eq!(PpmEventType::ACCEPT4_E.parameter_count(), 1);
    assert_eq!(PpmEventType::ACCEPT4_X.parameter_count(), 6);
    assert_eq!(PpmEventType::CLOSE_E.parameter_count(), 1);
    assert_eq!(PpmEventType::CLOSE_X.parameter_count(), 2);
    assert_eq!(PpmEventType::CLONE_E.parameter_count(), 0);
    assert_eq!(PpmEventType::CLONE_X.parameter_count(), 21);
    assert_eq!(PpmEventType::CLONE3_E.parameter_count(), 0);
    assert_eq!(PpmEventType::CLONE3_X.parameter_count(), 21);
    assert_eq!(PpmEventType::FORK_E.parameter_count(), 0);
    assert_eq!(PpmEventType::FORK_X.parameter_count(), 21);
    assert_eq!(PpmEventType::EXIT_E.parameter_count(), 5);
    assert_eq!(PpmEventType::EXIT_X.parameter_count(), 0);
}
