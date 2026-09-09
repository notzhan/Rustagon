use std::collections::HashSet;

use rustagon_engine::filter_details::{resolve_filter_details, FilterDetails};
use rustagon_engine::filter_warnings::{resolve_filter_warnings, FilterWarning};
use rustagon_engine::FalcoEngine;
use rustagon_parser::filter::{parse_filter, Expr, Operand, Value};

fn parse(condition: &str) -> Expr {
    parse_filter(condition).unwrap_or_else(|error| panic!("{condition}: {error}"))
}

fn details(condition: &str) -> FilterDetails {
    let mut details = FilterDetails {
        known_macros: HashSet::from(["spawned_process".to_string()]),
        known_lists: HashSet::from(["known_procs".to_string()]),
        ..FilterDetails::default()
    };
    resolve_filter_details(&parse(condition), &mut details);
    details
}

fn warns(condition: &str) -> bool {
    !resolve_filter_warnings(&parse(condition)).is_empty()
}

#[test]
fn details_resolve_ast() {
    let details = details(
        "(spawned_process or evt.type = open) and \
         (proc.name icontains cat or proc.name in (known_procs, ps))",
    );
    assert_eq!(
        details.fields,
        HashSet::from(["evt.type".into(), "proc.name".into()])
    );
    assert_eq!(details.macros, HashSet::from(["spawned_process".into()]));
    assert_eq!(
        details.operators,
        HashSet::from(["=".into(), "icontains".into(), "in".into()])
    );
    assert_eq!(details.lists, HashSet::from(["known_procs".into()]));
}

#[test]
fn details_resolve_single_value_transformer() {
    let details = details("tolower(proc.name) = nginx");
    assert_eq!(details.fields, HashSet::from(["proc.name".into()]));
    assert_eq!(details.transformers, HashSet::from(["tolower".into()]));
    assert_eq!(details.operators, HashSet::from(["=".into()]));
}

#[test]
fn details_resolve_multi_value_transformer() {
    let details = details("concat(proc.name, proc.pname) = value");
    assert_eq!(
        details.fields,
        HashSet::from(["proc.name".into(), "proc.pname".into()])
    );
    assert_eq!(details.transformers, HashSet::from(["concat".into()]));
}

#[test]
fn details_resolve_transformer_with_list() {
    let expr = Expr::binary(
        Operand::transformer(
            "join",
            vec![
                Operand::Literal(Value::Bare(",".into())),
                Operand::List(vec![
                    Operand::field("proc.name"),
                    Operand::field("proc.pid"),
                ]),
            ],
        ),
        rustagon_parser::filter::BinaryOp::Eq,
        Value::Bare("value".into()),
    );
    let mut details = FilterDetails::default();
    resolve_filter_details(&expr, &mut details);
    assert_eq!(
        details.fields,
        HashSet::from(["proc.name".into(), "proc.pid".into()])
    );
    assert_eq!(details.transformers, HashSet::from(["join".into()]));
}

#[test]
fn details_resolve_nested_transformers() {
    let details = details("toupper(tolower(proc.name)) = value");
    assert_eq!(details.fields, HashSet::from(["proc.name".into()]));
    assert_eq!(
        details.transformers,
        HashSet::from(["toupper".into(), "tolower".into()])
    );
}

#[test]
fn warnings_in_filtering_conditions() {
    assert!(!warns("ka.field exists"));
    assert!(!warns("some.field = <NA>"));
    for condition in [
        "jevt.field = <NA>",
        "ka.field = <NA>",
        "ka.field == <NA>",
        "ka.field != <NA>",
        "ka.field in (<NA>)",
        "ka.field in (otherval, <NA>)",
        "ka.field intersects (<NA>)",
        "ka.field intersects (otherval, <NA>)",
        "ka.field pmatch (<NA>)",
        "ka.field pmatch (otherval, <NA>)",
        "evt.dir = <",
        "evt.dir = >",
        "proc.name=test and evt.dir = <",
        "evt.dir = < and proc.name=test",
    ] {
        assert!(warns(condition), "expected warning for {condition}");
    }
}

#[test]
fn warnings_with_transformer_wrapping_unsafe_field() {
    assert!(warns("tolower(ka.field) = <NA>"));
    assert!(!warns("tolower(safe.field) = <NA>"));
}

#[test]
fn warnings_with_multi_value_transformer() {
    assert!(warns("concat(safe.field, ka.field) = <NA>"));
}

#[test]
fn warnings_no_crash_with_transformer_list() {
    let expr = Expr::binary(
        Operand::transformer(
            "join",
            vec![
                Operand::Literal(Value::Bare(",".into())),
                Operand::List(vec![
                    Operand::field("ka.field"),
                    Operand::field("safe.field"),
                ]),
            ],
        ),
        rustagon_parser::filter::BinaryOp::Eq,
        Value::Bare("<NA>".into()),
    );
    let _ = resolve_filter_warnings(&expr);
}

fn load(yaml: &str) -> rustagon_engine::LoadResult {
    FalcoEngine::new().load_rules(yaml, "rules.yaml")
}

fn rule(condition: &str, extra: &str) -> String {
    format!(
        "- rule: test_rule\n  desc: test\n  condition: {condition}\n  output: test\n  priority: INFO\n{extra}"
    )
}

fn has_evt_type_warning(result: &rustagon_engine::LoadResult) -> bool {
    result
        .warnings
        .iter()
        .any(|warning| warning.contains("Rule matches too many evt.type values"))
}

#[test]
fn no_evttype_warning_for_narrow_condition() {
    assert!(!has_evt_type_warning(&load(&rule("evt.type = close", ""))));
}

#[test]
fn evttype_warning_for_broad_condition() {
    assert!(has_evt_type_warning(&load(&rule("proc.name = cat", ""))));
}

#[test]
fn evttype_warning_disabled_by_warn_evttypes() {
    assert!(!has_evt_type_warning(&load(&rule(
        "proc.name = cat",
        "  warn_evttypes: false\n"
    ))));
}

#[test]
fn no_evttype_warning_for_unsatisfiable_condition() {
    assert!(!has_evt_type_warning(&load(&rule("evt.num = 0", ""))));
}

#[test]
fn no_evttype_warning_for_evt_type_contradiction() {
    assert!(!has_evt_type_warning(&load(&rule(
        "evt.type = open and evt.type = close",
        ""
    ))));
}

#[test]
fn no_evttype_warning_for_never_true_macro() {
    let result = load(
        "- macro: never_true\n\
         \x20 condition: (evt.num=0)\n\
         - macro: user_known_activity\n\
         \x20 condition: (never_true)\n\
         - rule: anchored_rule_with_placeholder\n\
         \x20 desc: test\n\
         \x20 condition: evt.type = open and not user_known_activity\n\
         \x20 output: test\n\
         \x20 priority: INFO\n\
         - rule: placeholder_only_rule\n\
         \x20 desc: test\n\
         \x20 condition: never_true\n\
         \x20 output: test\n\
         \x20 priority: INFO\n",
    );
    assert!(result.ok, "{:?}", result.errors);
    assert!(!has_evt_type_warning(&result), "{:?}", result.warnings);
}

#[test]
fn warning_kind_is_unsafe_na_check() {
    assert_eq!(
        resolve_filter_warnings(&parse("ka.field = <NA>")),
        vec![FilterWarning::UnsafeNaCheck]
    );
}
