extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub fn parse_ucs2_args(raw: &[u16]) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = Vec::new();

    for &word in raw {
        if word == 0 {
            break;
        }
        if word == b' ' as u16 || word == b'\t' as u16 || word == b'\n' as u16 {
            if !current.is_empty() {
                args.push(ucs2_to_string(&current));
                current.clear();
            }
            continue;
        }
        current.push(word);
    }

    if !current.is_empty() {
        args.push(ucs2_to_string(&current));
    }

    args
}

pub fn parse_load_options(load_options: Option<&[u16]>, add_prog: bool) -> Vec<String> {
    let mut args = match load_options {
        Some(raw) if !raw.is_empty() => parse_ucs2_args(raw),
        _ => Vec::new(),
    };

    if add_prog && (args.is_empty() || args[0] != "loader.efi") {
        args.insert(0, String::from("loader.efi"));
    }

    args
}

fn ucs2_to_string(raw: &[u16]) -> String {
    let mut out = String::new();
    for &ch in raw {
        if ch == 0 {
            break;
        }
        if let Some(c) = core::char::from_u32(ch as u32) {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::string::ToString;

    use super::{parse_load_options, parse_ucs2_args};

    #[test]
    fn test_parse_ucs2_args_splits_words() {
        let raw = [
            b'l' as u16,
            b'o' as u16,
            b'a' as u16,
            b'd' as u16,
            b'e' as u16,
            b'r' as u16,
            b'.' as u16,
            b'e' as u16,
            b'f' as u16,
            b'i' as u16,
            b' ' as u16,
            b'-' as u16,
            b'v' as u16,
            0,
        ];
        let args = parse_ucs2_args(&raw);
        assert_eq!(
            args,
            alloc::vec!["loader.efi".to_string(), "-v".to_string()]
        );
    }

    #[test]
    fn test_parse_ucs2_args_trims_separators() {
        let raw = [b' ' as u16, b'\t' as u16, b'a' as u16, 0];
        let args = parse_ucs2_args(&raw);
        assert_eq!(args, alloc::vec!["a".to_string()]);
    }

    #[test]
    fn test_parse_load_options_empty() {
        let args = parse_load_options(None, false);
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_load_options_add_prog() {
        let args = parse_load_options(None, true);
        assert_eq!(args, alloc::vec!["loader.efi".to_string()]);
    }
}
