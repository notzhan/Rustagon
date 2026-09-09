use rustagon_engine::{MatchType, Ruleset};

#[test]
fn enable_disable_rules_using_names() {
    let mut ruleset = Ruleset::default();
    for name in ["rule_A", "rule_B", "rule_C"] {
        ruleset.add(name, &[]);
    }
    ruleset.enable("rule_A", MatchType::Exact, 0);
    assert_eq!(ruleset.enabled_count(0), 1);
    ruleset.disable("rule_A", MatchType::Exact, 1);
    assert_eq!(ruleset.enabled_count(1), 0);
    ruleset.enable("rule_", MatchType::Substring, 0);
    assert_eq!(ruleset.enabled_count(0), 3);
    ruleset.disable("rule_", MatchType::Exact, 0);
    assert_eq!(ruleset.enabled_count(0), 3);
    ruleset.disable("*C*", MatchType::Wildcard, 0);
    assert_eq!(ruleset.enabled_count(0), 2);
    ruleset.disable("*_*", MatchType::Wildcard, 0);
    assert_eq!(ruleset.enabled_count(0), 0);
}

#[test]
fn enable_disable_rules_using_tags() {
    let mut ruleset = Ruleset::default();
    ruleset.add("rule_A", &["first_A", "second_A", "common"]);
    ruleset.add("rule_B", &["first_B", "second_B", "common"]);
    ruleset.enable_tags(&["first_A"], 0);
    assert_eq!(ruleset.enabled_count(0), 1);
    ruleset.enable_tags(&["common"], 2);
    assert_eq!(ruleset.enabled_count(2), 2);
    ruleset.disable_tags(&["second_A"], 0);
    assert_eq!(ruleset.enabled_count(0), 0);
    ruleset.disable_tags(&["common"], 2);
    assert_eq!(ruleset.enabled_count(2), 0);
}

#[test]
fn enabling_multiple_tags_matches_any_tag() {
    let mut ruleset = Ruleset::default();
    ruleset.add("rule_A", &["a"]);

    ruleset.enable_tags(&["a", "b"], 0);

    assert!(ruleset.is_enabled("rule_A", 0));
}
