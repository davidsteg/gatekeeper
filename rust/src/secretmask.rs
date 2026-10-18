//! Masks secret-shaped values in tool output (1.18.0).
//!
//! The `Redactor` in [`crate::audit`] masks the secrets gatekeeper holds
//! itself. A tool that prints a whole config file (`cat .env`,
//! `docker compose config`, a `file` read of `config.yaml`) also prints
//! secrets gatekeeper has never seen: a database password in a compose
//! file, another service's API token. This module catches those by shape:
//!
//! - an assignment whose key names a secret (`POSTGRES_PASSWORD=...`,
//!   `api_key: ...`, `"token": "..."`, `--token=...`,
//!   `Authorization: Bearer ...`), keyed by the same normalized-name rule
//!   the audit log uses ([`crate::audit::is_secret_key`]) plus a few
//!   output-only names;
//! - the password in a URL's userinfo (`postgres://user:pw@host`);
//! - a PEM private-key block.
//!
//! Deliberately generous, like the audit rule: a wrongly masked
//! `max_tokens: 4096` costs readability, a missed one costs a secret. The
//! toolkit's `redact_secrets` (Tier 1) decides whether it runs; it is on by
//! default for the executors that read host files and commands.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::audit::is_secret_key;

/// What a masked value is replaced by. Distinct from the `***` of
/// known-secret masking, so a `file` write can refuse content that still
/// carries it (writing it back would replace the real secret).
pub const MASK: &str = "[redacted]";

/// Key substrings that mark a secret in output but are not in the audit
/// log's list. Matched against the same normalized key.
const OUTPUT_ONLY: [&str; 4] = ["passwd", "privatekey", "accesskey", "cookie"];

static PEM_PRIVATE_KEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----).*?(-----END [A-Z0-9 ]*PRIVATE KEY-----)").unwrap()
});

static URL_USERINFO: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"([A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@"'<>]*):([^\s@/"'<>]+)@"#).unwrap()
});

/// `key <sep> value`: the key bare or quoted, `:` or `=` between, the value
/// double-quoted, single-quoted or bare up to a delimiter or the line end.
static ASSIGNMENT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?P<key>"[^"\r\n]{1,128}"|'[^'\r\n]{1,128}'|[A-Za-z0-9_.\-]{1,128})(?P<sep>[ \t]*[:=][ \t]*)(?P<val>"(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*'|[^\r\n"',;}\])&]*)"#,
    )
    .unwrap()
});

fn is_secret_output_key(key: &str) -> bool {
    if is_secret_key(key) {
        return true;
    }
    let normalized: String =
        key.to_lowercase().chars().filter(|c| !matches!(c, '-' | '_' | '.' | ' ')).collect();
    OUTPUT_ONLY.iter().any(|token| normalized.contains(token))
}

/// Where a bare `key=value` value ends: at a space that starts the next
/// flag or assignment (`--token=abc --port=1`, `A_TOKEN=x B=y`). Anything
/// else stays part of the value, as an env file reads it.
fn bare_value_end(value: &str) -> usize {
    if value.starts_with('"') || value.starts_with('\'') {
        return value.len();
    }
    for (i, c) in value.char_indices() {
        if c == ' ' || c == '\t' {
            let rest = value[i..].trim_start();
            if rest.starts_with('-') || NEXT_ASSIGNMENT.is_match(rest) {
                return i;
            }
        }
    }
    value.len()
}

static NEXT_ASSIGNMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_.]+=").unwrap());

/// True for a value that carries nothing worth masking.
fn already_empty(value: &str) -> bool {
    matches!(value, "" | "***" | MASK | "\"\"" | "''")
}

/// Returns `text` with every secret-shaped value replaced by [`MASK`].
pub fn mask_secrets(text: &str) -> String {
    let text = PEM_PRIVATE_KEY.replace_all(text, format!("$1\n{MASK}\n$2").as_str());
    let text = URL_USERINFO.replace_all(&text, format!("$1:{MASK}@").as_str());
    mask_assignments(&text)
}

fn mask_assignments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut pos = 0;
    while let Some(caps) = ASSIGNMENT.captures_at(text, pos) {
        let key = caps.name("key").unwrap();
        let sep = caps.name("sep").unwrap();
        let val = caps.name("val").unwrap();
        let raw_key = key.as_str().trim_matches(|c| c == '"' || c == '\'');
        let mut value = val.as_str().trim_end();
        if sep.as_str().contains('=') {
            value = &value[..bare_value_end(value)];
        }
        // `Token::new`, `a == b`, `x:=y`: a separator run, not an assignment.
        let doubled = value.starts_with(':') || value.starts_with('=');
        if !is_secret_output_key(raw_key) || doubled || already_empty(value) {
            // Rescan from the value: `command: --token=abc` holds a secret
            // behind a key that is not one.
            pos = sep.end().max(pos + 1);
            continue;
        }
        let masked = match value.chars().next() {
            Some(q @ ('"' | '\'')) => format!("{q}{MASK}{q}"),
            _ => MASK.to_string(),
        };
        out.push_str(&text[copied..val.start()]);
        out.push_str(&masked);
        copied = val.start() + value.len();
        pos = copied.max(pos + 1);
    }
    out.push_str(&text[copied..]);
    out
}

/// True if `text` still carries a [`MASK`] -- content that came from a
/// masked read and would overwrite a real secret if written back.
pub fn carries_mask(text: &str) -> bool {
    text.contains(MASK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_and_yaml_assignments() {
        let input = "POSTGRES_USER=app\nPOSTGRES_PASSWORD=hunter2\nexport API_TOKEN=abc def\n  api_key: k-123\nname: web\n";
        let out = mask_secrets(input);
        assert_eq!(
            out,
            "POSTGRES_USER=app\nPOSTGRES_PASSWORD=[redacted]\nexport API_TOKEN=[redacted]\n  api_key: [redacted]\nname: web\n"
        );
    }

    #[test]
    fn json_keeps_quotes_and_structure() {
        let out = mask_secrets(r#"{"user": "a", "token": "t\"x", "secret":'s', "n": 1}"#);
        assert_eq!(out, r#"{"user": "a", "token": "[redacted]", "secret":'[redacted]', "n": 1}"#);
    }

    #[test]
    fn secret_behind_a_harmless_key_is_found() {
        assert_eq!(mask_secrets("command: --token=abc --port=1"), "command: --token=[redacted] --port=1");
        assert_eq!(mask_secrets("environment:\n  - \"DB_PASSWORD=pw\""), "environment:\n  - \"DB_PASSWORD=[redacted]\"");
        assert_eq!(mask_secrets("GET /x?access_token=abc&page=2"), "GET /x?access_token=[redacted]&page=2");
    }

    #[test]
    fn headers_urls_and_pem() {
        assert_eq!(mask_secrets("Authorization: Bearer eyJabc"), "Authorization: [redacted]");
        assert_eq!(
            mask_secrets("DATABASE_URL=postgres://app:s3cret@db:5432/app"),
            "DATABASE_URL=postgres://app:[redacted]@db:5432/app"
        );
        let pem = "a\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----\nb";
        assert_eq!(mask_secrets(pem), "a\n-----BEGIN OPENSSH PRIVATE KEY-----\n[redacted]\n-----END OPENSSH PRIVATE KEY-----\nb");
    }

    #[test]
    fn leaves_harmless_text_alone() {
        for text in [
            "name: web\nimage: nginx:1.27\nports:\n  - \"8080:80\"",
            "token:\n  file: /run/secrets/x",
            "let t = Token::new();",
            "if password == other {",
            "PASSWORD=",
            "password: ***",
            "https://example.org/path",
            "password_changed: true",
        ] {
            assert_eq!(mask_secrets(text), text, "{text}");
        }
    }

    #[test]
    fn output_only_keys() {
        assert_eq!(mask_secrets("ssh_private_key: x"), "ssh_private_key: [redacted]");
        assert_eq!(mask_secrets("AWS_ACCESS_KEY_ID=AKIA1"), "AWS_ACCESS_KEY_ID=[redacted]");
        assert_eq!(mask_secrets("Set-Cookie: sid=1; Path=/"), "Set-Cookie: [redacted]; Path=/");
        assert_eq!(mask_secrets("db_passwd = 'x'"), "db_passwd = '[redacted]'");
    }

    #[test]
    fn unicode_and_masks_are_detected() {
        assert_eq!(mask_secrets("grüße: ä\ntoken: ö"), "grüße: ä\ntoken: [redacted]");
        assert!(carries_mask("x: [redacted]"));
        assert!(!carries_mask("x: ***"));
    }
}
