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
        let Some(macro_condition) = (!touches_field_separator)
            .then(|| macros.get(identifier))
            .flatten()
        else {
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
