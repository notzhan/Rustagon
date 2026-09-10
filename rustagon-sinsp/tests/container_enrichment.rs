use rustagon_scap::{RawEvent, RawEventKind};
use rustagon_sinsp::{container_id_from_cgroup, FixtureContainerLookup, Inspector};

const CONTAINER_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn exec(tid: i64) -> RawEvent {
    RawEvent {
        timestamp: 1,
        tid,
        type_id: 0,
        payload: Vec::new(),
        kind: RawEventKind::Exec {
            pid: tid,
            ppid: 1,
            comm: "worker".into(),
            exe: "worker".into(),
            exepath: "/usr/bin/worker".into(),
            args: Vec::new(),
        },
    }
}

#[test]
fn resolves_container_id_from_common_cgroup_paths() {
    assert_eq!(
        container_id_from_cgroup(&format!("/docker/{CONTAINER_ID}")).as_deref(),
        Some(CONTAINER_ID)
    );
    assert_eq!(
        container_id_from_cgroup(&format!(
            "/kubepods.slice/kubepods-burstable.slice/cri-containerd-{CONTAINER_ID}.scope"
        ))
        .as_deref(),
        Some(CONTAINER_ID)
    );
    assert_eq!(
        container_id_from_cgroup("/user.slice/user-1000.slice"),
        None
    );
}

#[test]
fn fixture_lookup_enriches_container_fields_on_exec() {
    let lookup = FixtureContainerLookup::new(format!(
        "{}/tests/fixtures/containers",
        env!("CARGO_MANIFEST_DIR")
    ));
    let mut inspector = Inspector::with_container_lookup(lookup);
    assert!(inspector.set_container_cgroup(42, &format!("/docker/{CONTAINER_ID}")));

    let evt = inspector.inject(exec(42));

    assert_eq!(
        evt.get_field_as_string("container.id").as_deref(),
        Some(CONTAINER_ID)
    );
    assert_eq!(
        evt.get_field_as_string("container.name").as_deref(),
        Some("fixture-web")
    );
    assert_eq!(
        evt.get_field_as_string("container.image").as_deref(),
        Some("registry.example/web:1.2.3")
    );
}

#[test]
fn missing_fixture_still_emits_the_cgroup_container_id() {
    let lookup = FixtureContainerLookup::new(format!(
        "{}/tests/fixtures/containers",
        env!("CARGO_MANIFEST_DIR")
    ));
    let mut inspector = Inspector::with_container_lookup(lookup);
    let unknown = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert!(inspector.set_container_cgroup(7, &format!("/docker/{unknown}")));

    let evt = inspector.inject(exec(7));

    assert_eq!(
        evt.get_field_as_string("container.id").as_deref(),
        Some(unknown)
    );
    assert_eq!(evt.get_field_as_string("container.name"), None);
    assert_eq!(evt.get_field_as_string("container.image"), None);
}
