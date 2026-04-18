extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
}

pub fn parse_loader_env_text(input: &str) -> Vec<EnvVar> {
    let mut vars = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        if ch == '"' {
            in_quotes = !in_quotes;
            current.push(ch);
            continue;
        }
        if ch.is_whitespace() && !in_quotes {
            push_token(&mut vars, &current);
            current.clear();
            continue;
        }
        current.push(ch);
    }
    push_token(&mut vars, &current);
    vars
}

pub fn parse_loader_conf_text(input: &str) -> Vec<EnvVar> {
    let mut vars = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut line = trimmed.to_string();
        if let Some(idx) = line.find('#') {
            if !is_within_quotes(&line, idx) {
                line.truncate(idx);
            }
        }
        let Some((key, value)) = split_key_value(&line) else {
            continue;
        };
        vars.push(EnvVar { key, value });
    }
    vars
}

fn push_token(vars: &mut Vec<EnvVar>, token: &str) {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return;
    }
    if let Some((key, value)) = split_key_value(trimmed) {
        vars.push(EnvVar { key, value });
    }
}

fn split_key_value(input: &str) -> Option<(String, String)> {
    let idx = input.find('=')?;
    let key = input[..idx].trim();
    if key.is_empty() {
        return None;
    }
    let mut value = input[idx + 1..].trim().to_string();
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        value = value[1..value.len() - 1].to_string();
    } else if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        value = value[1..value.len() - 1].to_string();
    }
    Some((key.to_string(), value))
}

fn is_within_quotes(line: &str, idx: usize) -> bool {
    let mut in_quotes = false;
    for (i, ch) in line.chars().enumerate() {
        if i >= idx {
            break;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
        }
    }
    in_quotes
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::string::ToString;

    use super::{EnvVar, parse_loader_conf_text, parse_loader_env_text};

    #[test]
    fn test_parse_loader_env_text_basic() {
        let vars = parse_loader_env_text("foo=1 bar=two");
        assert_eq!(
            vars,
            alloc::vec![
                EnvVar {
                    key: "foo".to_string(),
                    value: "1".to_string()
                },
                EnvVar {
                    key: "bar".to_string(),
                    value: "two".to_string()
                }
            ]
        );
    }

    #[test]
    fn test_parse_loader_env_text_quotes() {
        let vars = parse_loader_env_text("foo=\"one two\" bar=3");
        assert_eq!(vars[0].value, "one two");
        assert_eq!(vars[1].value, "3");
    }

    #[test]
    fn test_parse_loader_conf_text_basic() {
        let input = r#"
            # comment
            kern.geom.label.disk_ident.enable="0"
            boot_verbose="YES"
        "#;
        let vars = parse_loader_conf_text(input);
        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].key, "kern.geom.label.disk_ident.enable");
        assert_eq!(vars[0].value, "0");
        assert_eq!(vars[1].key, "boot_verbose");
        assert_eq!(vars[1].value, "YES");
    }

    #[test]
    fn test_parse_loader_conf_inline_comment() {
        let vars = parse_loader_conf_text("foo=bar # comment");
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].value, "bar");
    }
}
