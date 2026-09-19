use std::io::{self, BufRead, Write};

use clap::Parser;
use dsnmask::{dsn, kvformat, scan};

#[derive(Parser)]
#[command(
    name = "dsnmask",
    about = "Mask the password in a DSN/connection string before it goes into Slack or a bug report"
)]
struct Cli {
    /// A single DSN to mask, e.g. postgres://user:pass@host/db, or a
    /// libpq-style 'host=x user=y password=z' string. Omit to read lines
    /// from stdin instead (for `cat .env | dsnmask`).
    dsn: Option<String>,
}

fn mask_one(input: &str) -> String {
    // Try the URI form first (the common case); a libpq/ADO keyword=value
    // string will fail `Url::parse` outright (no `scheme://`), so falling
    // through to the keyword-value masker is safe and not ambiguous.
    match dsn::redact_uri(input) {
        Ok(redacted) => redacted,
        Err(_) => kvformat::redact_keyword_value(input),
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(input) = cli.dsn {
        println!("{}", mask_one(&input));
        return Ok(());
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line?;
        writeln!(out, "{}", scan::redact_in_text(&line))?;
    }
    Ok(())
}
