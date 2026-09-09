use rustagon_engine::FalcoEngine;

#[test]
fn basic() {
    let mut engine = FalcoEngine::new();
    let index = engine.add_source("syscall", "filter", "formatter", "ruleset");
    assert!(engine.is_source_valid("syscall"));
    assert_eq!(engine.filter_factory_for_source("syscall"), Some("filter"));
    assert_eq!(
        engine.filter_factory_for_source_index(index),
        Some("filter")
    );
    assert_eq!(
        engine.formatter_factory_for_source("syscall"),
        Some("formatter")
    );
    assert_eq!(
        engine.ruleset_factory_for_source("syscall"),
        Some("ruleset")
    );
    assert_eq!(engine.ruleset_for_source("syscall"), Some("ruleset"));
}
