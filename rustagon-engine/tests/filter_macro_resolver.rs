use std::collections::HashMap;

use pretty_assertions::assert_eq;
use rustagon_engine::macro_resolver::resolve_macros;

const MACRO_NAME: &str = "test_macro";
const MACRO_A_NAME: &str = "test_macro_1";
const MACRO_B_NAME: &str = "test_macro_2";

fn macros(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries
        .iter()
        .map(|(name, condition)| ((*name).to_string(), (*condition).to_string()))
        .collect()
}

#[test]
fn should_resolve_macros_on_a_filter_ast() {
    let definitions = macros(&[(MACRO_NAME, "test.field exists")]);

    let first = resolve_macros("evt.name exists and not test_macro", &definitions).unwrap();
    assert_eq!(first, "evt.name exists and not (test.field exists)");

    // A second pass is stable, corresponding to Falco's resolver reporting no change.
    assert_eq!(resolve_macros(&first, &definitions).unwrap(), first);
}

#[test]
fn should_resolve_macros_on_a_filter_ast_single_node() {
    let definitions = macros(&[(MACRO_NAME, "test.field exists")]);

    let first = resolve_macros(MACRO_NAME, &definitions).unwrap();
    assert_eq!(first, "(test.field exists)");
    assert_eq!(resolve_macros(&first, &definitions).unwrap(), first);
}

#[test]
fn should_resolve_macros_on_a_filter_ast_multiple_macros() {
    let definitions = macros(&[
        (MACRO_A_NAME, "one.field exists"),
        (MACRO_B_NAME, "another.field exists"),
    ]);

    let first = resolve_macros("test_macro_1 or test_macro_2", &definitions).unwrap();
    assert_eq!(first, "(one.field exists) or (another.field exists)");
    assert_eq!(resolve_macros(&first, &definitions).unwrap(), first);
}

#[test]
fn should_resolve_macros_on_a_filter_ast_nested_macros() {
    let definitions = macros(&[
        (MACRO_A_NAME, "one.field exists and test_macro_2"),
        (MACRO_B_NAME, "another.field exists"),
    ]);

    let first = resolve_macros(MACRO_A_NAME, &definitions).unwrap();
    assert_eq!(first, "(one.field exists and (another.field exists))");
    assert_eq!(resolve_macros(&first, &definitions).unwrap(), first);
}

#[test]
fn should_find_unknown_macros() {
    let condition = "evt.name exists and not test_macro";

    assert_eq!(
        resolve_macros(condition, &HashMap::new()).unwrap(),
        condition
    );
}

#[test]
fn should_find_unknown_nested_macros() {
    let definitions = macros(&[(MACRO_A_NAME, "one.field exists and test_macro_2")]);

    assert_eq!(
        resolve_macros(MACRO_A_NAME, &definitions).unwrap(),
        "(one.field exists and test_macro_2)"
    );
}

#[test]
fn should_undefine_macro() {
    let mut definitions = macros(&[(MACRO_NAME, "test.field exists")]);
    assert_eq!(
        resolve_macros(MACRO_NAME, &definitions).unwrap(),
        "(test.field exists)"
    );

    definitions.remove(MACRO_NAME);
    assert_eq!(
        resolve_macros(MACRO_NAME, &definitions).unwrap(),
        MACRO_NAME
    );
}

#[test]
fn should_clone_macro_ast() {
    let mut definitions = macros(&[(MACRO_NAME, "test.field exists")]);
    let resolved = resolve_macros(MACRO_NAME, &definitions).unwrap();
    assert_eq!(resolved, "(test.field exists)");

    definitions.insert(MACRO_NAME.to_string(), "another.field exists".to_string());
    assert_eq!(resolved, "(test.field exists)");
    assert_eq!(
        resolve_macros(MACRO_NAME, &definitions).unwrap(),
        "(another.field exists)"
    );
}

#[test]
fn should_not_resolve_macro_inside_field_transformer() {
    let definitions = macros(&[(MACRO_NAME, "resolved.field exists")]);

    assert_eq!(
        resolve_macros("tolower(some.field) = value and test_macro", &definitions,).unwrap(),
        "tolower(some.field) = value and (resolved.field exists)"
    );
}

#[test]
fn should_not_resolve_macro_inside_multi_value_transformer() {
    let definitions = macros(&[(MACRO_NAME, "x")]);
    let condition = "join(\",\", proc.name, proc.pname) = value";

    assert_eq!(resolve_macros(condition, &definitions).unwrap(), condition);
}

#[test]
fn should_not_resolve_macro_inside_transformer_list() {
    let definitions = macros(&[(MACRO_NAME, "x")]);
    let condition = "join(\",\", (proc.name, proc.pname)) = value";

    assert_eq!(resolve_macros(condition, &definitions).unwrap(), condition);
}
