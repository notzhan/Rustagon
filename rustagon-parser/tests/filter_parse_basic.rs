use rustagon_parser::filter::{parse_filter, print_filter};

fn canonical(input: &str) -> String {
    print_filter(&parse_filter(input).unwrap())
}

#[test]
fn parses_equality_without_spaces() {
    assert_eq!(canonical("evt.type=open"), "evt.type = open");
}

#[test]
fn parses_membership_list() {
    assert_eq!(canonical("proc.name in (a, b)"), "proc.name in (a, b)");
}

#[test]
fn respects_boolean_precedence() {
    assert_eq!(
        canonical("evt.type=open or proc.name=bash and not fd.name contains tmp"),
        "evt.type = open or proc.name = bash and not fd.name contains tmp"
    );
}

#[test]
fn preserves_required_nested_parentheses() {
    assert_eq!(
        canonical("not (evt.type=open or (proc.name=bash and fd.name contains tmp))"),
        "not (evt.type = open or proc.name = bash and fd.name contains tmp)"
    );
}

#[test]
fn parses_all_binary_operators() {
    for (input, expected) in [
        ("evt.type != open", "evt.type != open"),
        ("evt.num < 1", "evt.num < 1"),
        ("evt.num <= 1", "evt.num <= 1"),
        ("evt.num > 1", "evt.num > 1"),
        ("evt.num >= 1", "evt.num >= 1"),
        ("fd.name contains tmp", "fd.name contains tmp"),
        ("fd.name startswith /tmp", "fd.name startswith /tmp"),
        ("fd.name endswith .log", "fd.name endswith .log"),
        ("proc.name pmatch (bash, sh)", "proc.name pmatch (bash, sh)"),
        ("fd.name glob '/tmp/*'", "fd.name glob '/tmp/*'"),
    ] {
        assert_eq!(canonical(input), expected);
    }
}

#[test]
fn parses_exists_as_a_unary_field_operator() {
    assert_eq!(canonical("fd.name exists"), "fd.name exists");
}

#[test]
fn rejects_unparsed_trailing_input() {
    assert!(parse_filter("evt.type=open unexpected").is_err());
}
