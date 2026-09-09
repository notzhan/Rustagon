use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("recursive macro expansion detected for `{0}`")]
    RecursiveMacro(String),
}

impl Error {
    fn cycle(name: &str) -> Self {
        Self::RecursiveMacro(name.to_string())
    }
}

pub fn resolve_macros(condition: &str, macros: &HashMap<String, String>) -> Result<String, Error> {
    resolve_condition(condition, macros, &mut HashSet::new())
}

fn resolve_condition(
    condition: &str,
    macros: &HashMap<String, String>,
    resolving: &mut HashSet<String>,
) -> Result<String, Error> {
    let mut resolved = String::with_capacity(condition.len());
    let mut chars = condition.char_indices().peekable();

    while let Some((start, ch)) = chars.next() {
        if !is_identifier_start(ch) {
            resolved.push(ch);
            continue;
        }

        let mut end = start + ch.len_utf8();
        while let Some(&(index, next)) = chars.peek() {
            if !is_identifier_continue(next) {
                break;
            }
            chars.next();
            end = index + next.len_utf8();
        }

        let identifier = &condition[start..end];
        let touches_field_separator =
            condition[..start].ends_with('.') || condition[end..].starts_with('.');
        let Some(macro_condition) = (!touches_field_separator
            && is_bare_boolean_term(condition, start, end)
            && !is_comparison_rhs(&condition[..start]))
        .then(|| macros.get(identifier))
        .flatten() else {
            resolved.push_str(identifier);
            continue;
        };

        if !resolving.insert(identifier.to_string()) {
            return Err(Error::cycle(identifier));
        }
        let expansion = resolve_condition(macro_condition, macros, resolving)?;
        resolving.remove(identifier);
        resolved.push('(');
        resolved.push_str(&expansion);
        resolved.push(')');
    }

    Ok(resolved)
}

fn is_identifier_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn is_identifier_continue(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn is_bare_boolean_term(condition: &str, start: usize, end: usize) -> bool {
    let before = condition[..start].trim_end();
    let after = condition[end..].trim_start();

    let valid_before = before.is_empty()
        || before.ends_with('(')
        || trailing_word(before).is_some_and(|word| matches!(word, "and" | "or" | "not"));
    let valid_after = after.is_empty()
        || after.starts_with(')')
        || leading_word(after).is_some_and(|word| matches!(word, "and" | "or"));

    valid_before && valid_after
}

fn is_comparison_rhs(prefix: &str) -> bool {
    let mut comparison_seen = false;
    let mut chars = prefix.char_indices().peekable();

    while let Some((_, ch)) = chars.next() {
        if is_identifier_start(ch) {
            let mut word = String::from(ch);
            while let Some(&(_, next)) = chars.peek() {
                if !is_identifier_continue(next) {
                    break;
                }
                chars.next();
                word.push(next);
            }
            match word.as_str() {
                "and" | "or" => comparison_seen = false,
                "contains" | "icontains" | "bcontains" | "startswith" | "bstartswith"
                | "endswith" | "in" | "intersects" | "pmatch" | "glob" | "regex" => {
                    comparison_seen = true;
                }
                _ => {}
            }
        } else if matches!(ch, '=' | '!' | '<' | '>') {
            comparison_seen = true;
        }
    }

    comparison_seen
}

fn trailing_word(value: &str) -> Option<&str> {
    let end = value.len();
    let start = value
        .char_indices()
        .rev()
        .find_map(|(index, ch)| (!is_identifier_continue(ch)).then_some(index + ch.len_utf8()))
        .unwrap_or(0);
    (start < end).then_some(&value[start..end])
}

fn leading_word(value: &str) -> Option<&str> {
    let end = value
        .char_indices()
        .find_map(|(index, ch)| (!is_identifier_continue(ch)).then_some(index))
        .unwrap_or(value.len());
    (end > 0).then_some(&value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_nested_macros_without_replacing_field_names() {
        let macros = HashMap::from([
            (
                "interactive".to_string(),
                "shell and proc.name=sh".to_string(),
            ),
            ("shell".to_string(), "proc.name=bash".to_string()),
            ("proc".to_string(), "unexpected".to_string()),
        ]);

        assert_eq!(
            resolve_macros("interactive", &macros).unwrap(),
            "((proc.name=bash) and proc.name=sh)"
        );
    }
}
