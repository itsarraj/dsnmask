use std::sync::OnceLock;

use regex::Regex;

use crate::dsn::redact_uri;

fn dsn_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // A URI-shaped token: scheme://everything-up-to-whitespace-or-a-quote.
    // Stopping at quotes matters for the common `KEY="postgres://..."`
    // `.env` shape — without it the match would swallow the closing `"`
    // as part of the "path".
    RE.get_or_init(|| Regex::new(r#"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s'"]+"#).unwrap())
}

/// Finds every URI-shaped token in `line` and replaces it with its
/// password-masked form, leaving the rest of the line — variable name,
/// quotes, trailing comments — untouched. A found token that isn't
/// actually a well-formed connection URI (or has no password to mask) is
/// left exactly as it was; this only ever redacts, never corrupts.
/// This is what makes `cat .env | dsnmask` work directly on a real file
/// instead of needing the caller to pre-extract just the DSN value.
pub fn redact_in_text(line: &str) -> String {
    dsn_pattern()
        .replace_all(line, |caps: &regex::Captures| {
            let matched = &caps[0];
            redact_uri(matched).unwrap_or_else(|_| matched.to_string())
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_a_dsn_embedded_in_a_dotenv_style_line() {
        let line = r#"DATABASE_URL="postgres://appuser:hunter2@db.internal:5432/mydb""#;
        let redacted = redact_in_text(line);
        assert!(!redacted.contains("hunter2"));
        assert!(
            redacted.starts_with(r#"DATABASE_URL="postgres://appuser:***@db.internal:5432/mydb""#)
        );
        assert!(
            redacted.ends_with('"'),
            "the closing quote must survive, not get swallowed into the match"
        );
    }

    #[test]
    fn line_with_no_dsn_at_all_is_returned_unchanged() {
        let line = "NODE_ENV=production";
        assert_eq!(redact_in_text(line), line);
    }

    #[test]
    fn an_ordinary_url_with_no_credentials_passes_through_unchanged() {
        let line = "WEBHOOK_URL=https://example.com/hooks/abc123";
        assert_eq!(redact_in_text(line), line);
    }

    #[test]
    fn multiple_dsns_on_one_line_are_both_redacted() {
        let line = "postgres://a:secret1@host1/db redis://:secret2@host2:6379/0";
        let redacted = redact_in_text(line);
        assert!(!redacted.contains("secret1"));
        assert!(!redacted.contains("secret2"));
    }

    #[test]
    fn trailing_comment_after_a_dsn_is_preserved() {
        let line = "postgres://a:secret@host/db # prod, do not touch";
        let redacted = redact_in_text(line);
        assert!(!redacted.contains("secret"));
        assert!(redacted.ends_with("# prod, do not touch"));
    }
}
