use url::Url;

const PASSWORD_LIKE_QUERY_KEYS: &[&str] = &[
    "password", "pwd", "pass", "secret", "token", "apikey", "api_key",
];

fn is_password_like_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    PASSWORD_LIKE_QUERY_KEYS
        .iter()
        .any(|k| lower == *k || lower.contains(k))
}

/// Masks the password in a URI-style connection string —
/// `postgres://user:PASSWORD@host/db`, `mysql://...`, `redis://...`,
/// `mongodb://...`/`mongodb+srv://...` all follow the same
/// `scheme://user:password@host/path?query` shape the `url` crate already
/// parses correctly, so this doesn't hand-roll DSN parsing. Also masks
/// password-shaped query parameters (`?sslpassword=...`), since some
/// drivers put a second secret there instead of (or in addition to) the
/// userinfo slot.
///
/// Everything else — scheme, username, host, port, database name, other
/// query params — is left visible on purpose: those are almost always
/// fine to share when debugging, and stripping them too would make the
/// masked output useless for the "which environment was this" question
/// it's meant to still answer.
pub fn redact_uri(dsn: &str) -> Result<String, String> {
    let mut url = Url::parse(dsn).map_err(|e| format!("not a valid connection URI: {e}"))?;

    if url.password().is_some() {
        url.set_password(Some("***"))
            .map_err(|_| "failed to set masked password".to_string())?;
    }

    let redacted_pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| {
            if is_password_like_key(&k) {
                (k.into_owned(), "***".to_string())
            } else {
                (k.into_owned(), v.into_owned())
            }
        })
        .collect();

    if !redacted_pairs.is_empty() {
        url.query_pairs_mut().clear();
        url.query_pairs_mut().extend_pairs(&redacted_pairs);
    }

    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_postgres_password() {
        let redacted = redact_uri("postgres://appuser:hunter2@db.internal:5432/mydb").unwrap();
        assert_eq!(redacted, "postgres://appuser:***@db.internal:5432/mydb");
        assert!(!redacted.contains("hunter2"));
    }

    #[test]
    fn masks_mysql_and_redis_and_mongodb_the_same_way() {
        assert_eq!(
            redact_uri("mysql://root:supersecret@127.0.0.1:3306/app").unwrap(),
            "mysql://root:***@127.0.0.1:3306/app"
        );
        assert_eq!(
            redact_uri("redis://:mypassword@cache:6379/0").unwrap(),
            "redis://:***@cache:6379/0"
        );
        assert_eq!(
            redact_uri("mongodb+srv://user:pw123@cluster0.abcde.mongodb.net/mydb").unwrap(),
            "mongodb+srv://user:***@cluster0.abcde.mongodb.net/mydb"
        );
    }

    #[test]
    fn no_password_present_is_unchanged() {
        let dsn = "postgres://readonly@db.internal:5432/mydb";
        assert_eq!(redact_uri(dsn).unwrap(), dsn);
    }

    #[test]
    fn masks_a_password_shaped_query_parameter_too() {
        let redacted =
            redact_uri("postgres://user@host/db?sslpassword=leaky123&sslmode=require").unwrap();
        assert!(!redacted.contains("leaky123"));
        assert!(redacted.contains("sslpassword=***"));
        assert!(
            redacted.contains("sslmode=require"),
            "non-password params must survive untouched"
        );
    }

    #[test]
    fn non_password_fields_stay_fully_visible() {
        let redacted = redact_uri("postgres://appuser:hunter2@db.internal:5432/mydb").unwrap();
        assert!(redacted.contains("appuser"));
        assert!(redacted.contains("db.internal"));
        assert!(redacted.contains("5432"));
        assert!(redacted.contains("mydb"));
    }

    #[test]
    fn garbage_input_is_a_clean_error_not_a_panic() {
        assert!(redact_uri("this is not a dsn at all").is_err());
    }
}
