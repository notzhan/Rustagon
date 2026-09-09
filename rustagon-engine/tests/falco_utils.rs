use rustagon_engine::utils::{
    is_unix_scheme, matches_wildcard, parse_prometheus_interval, sanitize_rule_name,
};

#[test]
fn is_unix_scheme_matches_falco() {
    assert!(!is_unix_scheme("something:///run/falco/falco.sock"));
    assert!(!is_unix_scheme("unix///falco.sock"));
    assert!(is_unix_scheme("unix:///falco.sock"));
}

#[test]
fn parse_prometheus_interval_matches_falco() {
    assert_eq!(parse_prometheus_interval("1ms"), 1);
    assert_eq!(parse_prometheus_interval("1s"), 1_000);
    assert_eq!(parse_prometheus_interval("1h3m2s1ms"), 3_782_001);
    assert_eq!(parse_prometheus_interval("1y1w1d1h1m1s1ms"), 32_230_861_001);
    assert_eq!(parse_prometheus_interval("2h 5m"), 7_500_000);
    for invalid in ["1ms1y", "1t1y", "1t", "200"] {
        assert_eq!(parse_prometheus_interval(invalid), 0);
    }
}

#[test]
fn sanitize_rule_name_matches_falco() {
    assert_eq!(
        sanitize_rule_name("Testing rule   2 (CVE-2244)"),
        "Testing_rule_2_CVE_2244"
    );
    assert_eq!(sanitize_rule_name("Testing rule__:2)"), "Testing_rule_:2");
    assert_eq!(
        sanitize_rule_name("This@is_a$test rule123"),
        "This_is_a_test_rule123"
    );
    assert_eq!(
        sanitize_rule_name("RULEwith:special#characters"),
        "RULEwith:special_characters"
    );
}

#[test]
fn wildcard_matching_backtracks_like_falco() {
    for (pattern, value) in [
        ("*", "anything"),
        ("**", "anything"),
        ("*", ""),
        ("no star", "no star"),
        ("", ""),
        ("hello*world", "hello new world"),
        ("*ab", "xabab"),
        ("*.yaml", "backup.yaml.yaml"),
        ("*foo*bar", "foofoobar"),
        ("*ab*ab", "ababab"),
        ("hello*world", "hello world hello world"),
        ("**ab**ab", "ababab"),
    ] {
        assert!(matches_wildcard(pattern, value), "{pattern:?} {value:?}");
    }
    for (pattern, value) in [
        ("no star", ""),
        ("", "no star"),
        ("hello*world", "hello new world yes"),
        ("*ab", "xabcd"),
        ("*foo*bar", "foofoobaz"),
    ] {
        assert!(!matches_wildcard(pattern, value), "{pattern:?} {value:?}");
    }
}
