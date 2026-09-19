/// Masks `password=...`-style tokens in libpq's alternate connection
/// format (`host=x user=y password=z dbname=w`, space-separated, no
/// `scheme://`) — the other DSN shape Postgres tooling actually accepts,
/// distinct from the URI form `dsn.rs` handles. Also covers the
/// semicolon-separated ADO/ODBC style (`Server=x;User Id=y;Password=z;`)
/// SQL Server/some MySQL drivers use, since both are "bag of key=value
/// pairs" once you stop assuming a single separator character.
pub fn redact_keyword_value(s: &str) -> String {
    let separators: &[char] = &[' ', ';'];
    let mut result = String::new();
    let mut last_end = 0;

    for (start, part) in split_keep_separators(s, separators) {
        if let Some(eq_pos) = part.find('=') {
            let key = &part[..eq_pos];
            let value = &part[eq_pos + 1..];
            if is_password_like_key(key.trim()) && !value.trim().is_empty() {
                result.push_str(&s[last_end..start]);
                result.push_str(key);
                result.push('=');
                result.push_str("***");
                last_end = start + part.len();
                continue;
            }
        }
    }
    result.push_str(&s[last_end..]);
    result
}

fn is_password_like_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower == "password"
        || lower == "pwd"
        || lower == "user id password"
        || lower.contains("password")
        || lower.contains("pwd")
}

/// Splits `s` on any of `seps`, returning `(byte_offset, token)` pairs for
/// the non-separator tokens — used instead of `str::split` because the
/// caller needs each token's original byte position to splice a
/// replacement back into the untouched surrounding text.
fn split_keep_separators<'a>(s: &'a str, seps: &[char]) -> Vec<(usize, &'a str)> {
    let mut result = Vec::new();
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if seps.contains(&c) {
            if i > start {
                result.push((start, &s[start..i]));
            }
            start = i + c.len_utf8();
        }
    }
    if start < s.len() {
        result.push((start, &s[start..]));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_password_in_space_separated_libpq_format() {
        let redacted =
            redact_keyword_value("host=db.internal user=app password=hunter2 dbname=mydb");
        assert!(!redacted.contains("hunter2"));
        assert!(redacted.contains("password=***"));
        assert!(redacted.contains("host=db.internal"));
        assert!(redacted.contains("user=app"));
        assert!(redacted.contains("dbname=mydb"));
    }

    #[test]
    fn masks_password_in_semicolon_separated_ado_format() {
        let redacted =
            redact_keyword_value("Server=myserver;Database=mydb;User Id=sa;Password=Sup3rSecret;");
        assert!(!redacted.contains("Sup3rSecret"));
        assert!(redacted.contains("Password=***"));
        assert!(redacted.contains("Server=myserver"));
        assert!(redacted.contains("Database=mydb"));
    }

    #[test]
    fn pwd_abbreviation_is_also_recognized() {
        let redacted = redact_keyword_value("host=x pwd=secretvalue");
        assert!(!redacted.contains("secretvalue"));
        assert!(redacted.contains("pwd=***"));
    }

    #[test]
    fn no_password_field_leaves_string_unchanged() {
        let input = "host=db.internal user=app dbname=mydb";
        assert_eq!(redact_keyword_value(input), input);
    }

    #[test]
    fn empty_password_value_is_left_as_is_nothing_to_leak() {
        let input = "host=x password=";
        assert_eq!(redact_keyword_value(input), input);
    }
}
