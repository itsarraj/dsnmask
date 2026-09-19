# dsnmask

Mask the password in a database connection string before it goes into a
Slack message or a GitHub issue. "Here's my connection string, can you
help debug this" with the real password still in it is a constant,
mundane leak — nothing addresses it directly today.

## Usage

```bash
dsnmask "postgres://appuser:hunter2@db.internal:5432/mydb"
# -> postgres://appuser:***@db.internal:5432/mydb

dsnmask "host=db.internal user=app password=hunter2 dbname=mydb"   # libpq keyword=value form too
cat .env | dsnmask                                                  # pipe a whole file, only DSN lines change
```

The pipe mode is the one actually meant for daily use: point it at a real
`.env` and every non-DSN line — comments, `NODE_ENV=production`, a Slack
webhook URL with no credentials in it — passes through byte-for-byte,
only the password inside an actual connection string gets replaced.

## What it recognizes

Two DSN shapes: URI-style (`postgres://`, `mysql://`, `redis://`,
`mongodb://`/`mongodb+srv://` — anything `scheme://user:pass@host/path`
shaped, handled by the same parser regardless of scheme) and libpq/ADO
keyword=value style (`host=x user=y password=z`, space- or
semicolon-separated — what Postgres's alternate connection format and
SQL Server/some MySQL drivers use). In URI mode, a password-shaped query
parameter (`?sslpassword=...`) is masked too, since some drivers put a
second secret there. Everything else — scheme, username, host, port,
database name, other query params — stays fully visible on purpose:
that's almost always fine to share, and stripping it too would make the
masked output useless for "which environment was this."

## Status: built and verified against a realistic `.env` file, byte-for-byte

- **16 unit tests** (`cargo test --lib`): URI masking across Postgres/
  MySQL/Redis/MongoDB (one parser, all four schemes, since they share the
  same URI shape); a DSN with no password left completely unchanged, not
  given a spurious `***`; a password-shaped query parameter masked while
  an unrelated one (`sslmode=require`) survives; every other field
  (username, host, port, dbname) confirmed still visible in the output;
  the libpq keyword=value and ADO semicolon-separated forms, including
  that an *empty* `password=` value is left as-is (nothing there to
  leak); and the text-scanning mode — a DSN embedded in a real
  `KEY="postgres://..."` `.env`-style line redacted with **the closing
  quote confirmed to survive** (not swallowed into the match, a real
  failure mode a naive "match until whitespace" regex would hit),
  multiple DSNs on one line both caught, a trailing comment preserved,
  and — the actual point of the pipe mode — an ordinary credential-free
  URL (a Slack webhook) passed through byte-for-byte unchanged.
- **Live CLI run against a realistic `.env` file**: five lines —
  `NODE_ENV`, a Postgres `DATABASE_URL` with a real-shaped password, a
  Redis URL, a Slack webhook URL, and a plain numeric setting — piped
  through `dsnmask`. Confirmed line-by-line: the two DSN lines had their
  passwords replaced with `***` and nothing else changed (host, port,
  dbname, the surrounding quotes all intact); the other three lines came
  out **byte-for-byte identical** to the input, including the credential-
  free webhook URL, which a less careful implementation might have
  mangled by treating any `scheme://` token as fair game.

**Not done / deliberately deferred**: password-in-cleartext detection for
formats this doesn't recognize at all (a raw `PGPASSWORD=x` env var next
to a separate `PGHOST=`/`PGUSER=`, Postgres's fully-split environment-variable
convention — no single token to pattern-match against, would need
correlating multiple env var names together, a real v2); JDBC connection
strings (`jdbc:postgresql://...;password=...`, a hybrid of both shapes
this tool handles separately but not together in one string).
