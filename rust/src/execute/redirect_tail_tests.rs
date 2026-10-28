//! 1.30.0: `follow_redirect` (one hop, GET only, checked before connect,
//! no credential, no URL in the result) and `output_tail_lines`, plus
//! secret masking before the byte cap. DNS is pinned to public addresses
//! and every connection lands on a loopback server (`test_hooks`).

use super::test_hooks::{connects, install_dns, redirect_to};
use super::*;
use crate::catalog::{parse_tool_spec, validate_against_tier1, ToolDef};
use crate::credentials::tests::env;
use crate::tier1::{load_tier1, Tier1};
use crate::validate::{build_http_request, Values};
use hyper::service::service_fn;

const BLOB: &str = "productionresultssa0.blob.core.windows.net";
const SIG: &str = "sig=SIGNEDSECRET";

type Seen = Arc<parking_lot::Mutex<Vec<(String, Option<String>, String, bool, bool)>>>;

async fn server(location: String, blob_body: Arc<Vec<u8>>) -> Seen {
    server_opts(location, blob_body, false).await
}

/// `second_redirect`: the hop target itself answers with a further 3xx
/// instead of 200 -- used to prove `follow_redirect.max` is 1 at runtime
/// (m4, 140G): nothing ever connects past the one allowed hop.
async fn server_opts(location: String, blob_body: Arc<Vec<u8>>, second_redirect: bool) -> Seen {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    let location = Arc::new(location);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let seen = seen2.clone();
            let blob_body = blob_body.clone();
            let location = location.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<Incoming>| {
                    let seen = seen.clone();
                    let blob_body = blob_body.clone();
                    let location = location.clone();
                    async move {
                        let h = |n: &str| req.headers().get(n).map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
                        let host = h("host").unwrap_or_default();
                        let auth = h("authorization");
                        let path = req.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
                        let has_cookie = req.headers().contains_key("cookie");
                        let has_api_key = req.headers().contains_key("x-api-key");
                        let _ = req.into_body().collect().await;
                        seen.lock().push((host.clone(), auth, path.clone(), has_cookie, has_api_key));
                        let resp = if host == "api.github.com" && path.contains("/logs") {
                            hyper::Response::builder().status(302).header("Location", location.as_str())
                                .header("Set-Cookie", "session=attacker; Path=/")
                                .body(Full::new(Bytes::new())).unwrap()
                        } else if host != "api.github.com" && second_redirect {
                            // the hop target answers with a further redirect.
                            hyper::Response::builder().status(302).header("Location", "https://evil.example.invalid/x").body(Full::new(Bytes::new())).unwrap()
                        } else {
                            hyper::Response::builder().status(200).header("Content-Type", "text/plain")
                                .body(Full::new(Bytes::from(blob_body.as_ref().clone()))).unwrap()
                        };
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    redirect_to(addr);
    seen
}

fn tier1(dir: &std::path::Path, redirect_hosts: &str) -> Tier1 {
    tier1_opts(dir, redirect_hosts, true)
}

/// m4 fix (140G): `redact_secrets` is exercised as a real toolkit field
/// here (wired through `call()` to `HttpOptions.mask_secrets` exactly as
/// `service.rs:678` does), not hardcoded -- so a test can prove the wiring
/// by toggling it, not just that `secretmask::mask_secrets` itself works.
fn tier1_opts(dir: &std::path::Path, redirect_hosts: &str, redact_secrets: bool) -> Tier1 {
    let path = dir.join("toolkits.yaml");
    std::fs::write(&path, format!(
        "toolkits:\n  github:\n    executor: http\n    base_url: \"https://api.github.com\"\n    allowed_methods: [\"GET\", \"POST\"]\n    allowed_path_prefixes: [\"/repos/\"]\n    allowed_hosts: [\"api.github.com\"]\n    credential: demo_cred\n    redact_secrets: {redact_secrets}\n    redirect_allowed_hosts: {redirect_hosts}\naudit:\n  dir: {}\n",
        dir.join("logs").display())).unwrap();
    load_tier1(path.to_str().unwrap()).unwrap()
}

fn spec(overrides: Value) -> Value {
    let mut spec = serde_json::json!({
        "id": "github.actions_job_log_tail", "toolkit": "github", "version": 1,
        "title": "Job log tail", "description": "test", "category": "read", "enabled": true, "idempotent": true,
        "method": "GET", "path": "/repos/davidsteg/gatekeeper/actions/jobs/{job_id}/logs",
        "parameters": {"job_id": {"type": "string", "pattern": "^[0-9]{1,20}$", "required": true}},
        "timeout_seconds": 20, "max_output_bytes": 65536,
        "follow_redirect": {"max": 1, "allowed_hosts": [BLOB]},
        "output_tail_lines": 3,
    });
    for (k, v) in overrides.as_object().unwrap() { spec[k] = v.clone(); }
    spec
}

fn log_body(lines: usize) -> Arc<Vec<u8>> {
    let mut s = String::new();
    for i in 1..=lines { s.push_str(&format!("line {i}\n")); }
    s.push_str("export GH_TOKEN=ghp_notreal123\n");
    Arc::new(s.into_bytes())
}

async fn call(e: &crate::credentials::tests::Env, t: &Tier1, tool: &ToolDef, method: &str, max: i64) -> ExecResult {
    let tk = t.toolkit("github").unwrap();
    let vals: Values = [("job_id".to_string(), "123".to_string())].into_iter().collect();
    let req = build_http_request(tool, &vals, tk).unwrap();
    // m4 fix (140G): mirrors service.rs:678 (`mask_secrets: toolkit.redact_secrets`)
    // instead of hardcoding true, so toggling the toolkit field here actually
    // changes behaviour.
    let opts = HttpOptions { follow_redirect: tool.follow_redirect.clone(), tail_lines: tool.output_tail_lines, mask_secrets: tk.redact_secrets };
    run_with(method, &req.path, &req.query, None, None, tk, Some(&e.store), 20.0, max, true, None, &opts).await.unwrap()
}

fn leaks(r: &ExecResult) -> bool {
    let all = format!("{}{}{}{}", r.stdout, r.stderr, r.denial_detail.clone().unwrap_or_default(), r.redirect.clone().unwrap_or_default());
    all.contains("SIGNEDSECRET") || all.contains("/blobpath")
}

const GOOD: &str = "https://productionresultssa0.blob.core.windows.net/blobpath/job-logs.txt?sig=SIGNEDSECRET&se=x";

fn setup() -> (crate::credentials::tests::Env, Tier1) {
    let e = env();
    e.store.create("demo_cred", "bearer", "tok-SECRET-1", None, None, None, "t", "").unwrap();
    install_dns(&[("api.github.com", &[&["20.250.119.72"]]), (BLOB, &[&["20.60.40.4"]])]);
    let t = tier1(e.dir.path(), &format!("[\"{BLOB}\"]"));
    (e, t)
}

#[tokio::test]
async fn allowed_redirect_followed_without_credential_tail_and_redacted() {
    let (e, t) = setup();
    let seen = server(GOOD.into(), log_body(50)).await;
    let tool = parse_tool_spec(&spec(serde_json::json!({})), &t).unwrap();
    validate_against_tier1(&tool, t.toolkit("github").unwrap()).unwrap();
    let r = call(&e, &t, &tool, "GET", 65536).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(r.stdout, "line 49\nline 50\nexport GH_TOKEN=[redacted]\n");
    let seen = seen.lock().clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].1.as_deref(), Some("Bearer tok-SECRET-1"));
    assert_eq!(seen[1].0, BLOB);
    assert_eq!(seen[1].1, None, "credential must not follow the redirect");
    assert!(seen[1].2.contains(SIG));
    let c = connects();
    assert_eq!(c[1].addr.ip().to_string(), "20.60.40.4");
    assert_eq!(c[1].sni_hostname.as_deref(), Some(BLOB));
    assert_eq!(r.redirect, Some(serde_json::json!({"from_status": 302, "host": BLOB, "status": 200, "followed": true})));
    assert!(!leaks(&r));
}

#[tokio::test]
async fn refused_targets_never_connect() {
    for loc in [
        "https://evil.blob.core.windows.net/blobpath/x?sig=SIGNEDSECRET",
        "http://productionresultssa0.blob.core.windows.net/blobpath?sig=SIGNEDSECRET",
        "https://10.1.2.3/blobpath",
        "https://user:pw@productionresultssa0.blob.core.windows.net/blobpath",
        "https://productionresultssa0.blob.core.windows.net:8443/blobpath",
    ] {
        let (e, t) = setup();
        server(loc.into(), log_body(5)).await;
        let before = connects().len();
        let tool = parse_tool_spec(&spec(serde_json::json!({})), &t).unwrap();
        let r = call(&e, &t, &tool, "GET", 65536).await;
        assert_ne!(r.outcome, OUTCOME_OK, "{loc}");
        assert_eq!(connects().len() - before, 1, "{loc}");
        assert!(!leaks(&r), "{loc}: {:?}", r.denial_detail);
    }
    let (e, t) = setup();
    install_dns(&[("api.github.com", &[&["20.250.119.72"]]), (BLOB, &[&["10.0.0.5"]])]);
    server(GOOD.into(), log_body(5)).await;
    let before = connects().len();
    let tool = parse_tool_spec(&spec(serde_json::json!({})), &t).unwrap();
    let r = call(&e, &t, &tool, "GET", 65536).await;
    assert_ne!(r.outcome, OUTCOME_OK);
    assert_eq!(connects().len() - before, 1);
}

#[tokio::test]
async fn post_never_follows_and_does_not_echo_location() {
    let (e, t) = setup();
    let seen = server(GOOD.into(), log_body(5)).await;
    let err = parse_tool_spec(&spec(serde_json::json!({"method": "POST", "category": "write"})), &t).unwrap_err();
    assert!(err.to_string().contains("only allowed on a GET"), "{err}");
    let tool = parse_tool_spec(&spec(serde_json::json!({})), &t).unwrap();
    let r = call(&e, &t, &tool, "POST", 65536).await;
    assert_eq!(r.exit_code, Some(302));
    assert_eq!(seen.lock().len(), 1);
    assert!(!leaks(&r), "{}", r.stderr);
}

#[tokio::test]
async fn tail_read_cap_marks_truncated() {
    let (e, t) = setup();
    let big: Vec<u8> = (0..TAIL_READ_CAP + 4096).map(|i| if i % 100 == 99 { b'\n' } else { b'x' }).collect();
    server(GOOD.into(), Arc::new(big)).await;
    let tool = parse_tool_spec(&spec(serde_json::json!({})), &t).unwrap();
    let r = call(&e, &t, &tool, "GET", 150).await;
    assert!(r.truncated);
    assert!(r.stderr.contains("larger than 20 MiB"), "{}", r.stderr);
    assert!(r.stdout.len() <= 150);
}

#[test]
fn last_lines_and_byte_cap() {
    assert_eq!(last_lines("a\nb\nc\n", 2), "b\nc\n");
    assert_eq!(last_lines("a\nb\nc", 2), "b\nc");
    assert_eq!(last_lines("a\nb", 5), "a\nb");
    assert_eq!(keep_last_bytes("hello", 3), ("llo".to_string(), true));
    assert_eq!(keep_last_bytes("a\u{e9}", 1).0, "");
}

#[test]
fn field_validation() {
    let e = env();
    let t = tier1(e.dir.path(), &format!("[\"{BLOB}\"]"));
    for b in [
        serde_json::json!({"follow_redirect": {"max": 2, "allowed_hosts": [BLOB]}}),
        serde_json::json!({"follow_redirect": {"max": 1, "allowed_hosts": []}}),
        serde_json::json!({"follow_redirect": {"max": 1, "allowed_hosts": ["*.blob.core.windows.net"]}}),
        serde_json::json!({"follow_redirect": {"max": 1, "allowed_hosts": ["20.60.40.4"]}}),
        serde_json::json!({"follow_redirect": {"max": 1, "allowed_hosts": [BLOB], "extra": 1}}),
        serde_json::json!({"output_tail_lines": 0}),
        serde_json::json!({"output_tail_lines": 1001}),
    ] {
        assert!(parse_tool_spec(&spec(b.clone()), &t).is_err(), "{b}");
    }
    // Outside the toolkit's Tier 1 ceiling: a Tier 1 violation.
    let err = parse_tool_spec(&spec(serde_json::json!({"follow_redirect": {"max": 1, "allowed_hosts": ["other.blob.core.windows.net"]}})), &t).unwrap_err();
    assert!(err.to_string().contains("redirect_allowed_hosts"), "{err}");
}

#[tokio::test]
async fn hop_carries_no_cookie_or_api_key_header() {
    // m4 fix (140G): the credential here is `api_key_header` (not `bearer`,
    // as `setup()` uses), specifically so `seen[0].4` proves the header was
    // actually sent on the first request -- a vacuous "it's absent at the
    // hop" is worthless if it was never present to begin with. The first
    // response's `Set-Cookie` (added in `server`'s 302 branch) is the bait
    // for a would-be cookie jar; there is none, so it must not come back
    // as a `Cookie` header on the hop either.
    let e = env();
    e.store.create("demo_cred", "api_key_header", "secretapikey123", Some("X-Api-Key"), None, None, "t", "").unwrap();
    install_dns(&[("api.github.com", &[&["20.250.119.72"]]), (BLOB, &[&["20.60.40.4"]])]);
    let t = tier1(e.dir.path(), &format!("[\"{BLOB}\"]"));
    let seen = server(GOOD.into(), log_body(5)).await;
    let tool = parse_tool_spec(&spec(serde_json::json!({})), &t).unwrap();
    let r = call(&e, &t, &tool, "GET", 65536).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    let seen = seen.lock().clone();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].4, "the first request must actually carry the api_key_header credential");
    assert!(!seen[1].3, "the hop must not carry a Cookie header (no cookie jar exists)");
    assert!(!seen[1].4, "the hop must not carry the api_key_header credential");
    assert!(!leaks(&r));
}

#[tokio::test]
async fn a_second_redirect_from_the_hop_target_is_not_followed() {
    // m4 fix (140G): `follow_redirect.max` is validated to be exactly 1
    // (`validate.rs`), but that is a config-time ceiling, not proof the
    // runtime stops after one hop. Here the hop target itself answers with
    // a further 302 to an off-allowlist host; nothing may ever connect to
    // that second target.
    let (e, t) = setup();
    let seen = server_opts(GOOD.into(), log_body(5), true).await;
    let before = connects().len();
    let tool = parse_tool_spec(&spec(serde_json::json!({})), &t).unwrap();
    let r = call(&e, &t, &tool, "GET", 65536).await;
    assert_ne!(r.outcome, OUTCOME_OK);
    assert_eq!(r.exit_code, Some(302));
    assert_eq!(r.stdout, "", "a non-2xx hop response's body must be discarded (m3)");
    assert_eq!(seen.lock().len(), 2, "only the original request and the one allowed hop -- never a third");
    // One connect for api.github.com, one for the hop -- never a third to
    // the evil host the hop's own Location pointed at.
    assert_eq!(connects().len() - before, 2);
    assert!(!leaks(&r), "{:?}", r.stderr);
}

#[tokio::test]
async fn audit_record_carries_no_url_for_a_followed_redirect() {
    // m4 fix (140G): the earlier tests only inspect the `ExecResult` that
    // `run_with` returns; the audit line is built separately in
    // `audit::AuditLog::call` from a `CallRecord` (`service.rs:940` wires
    // `ExecResult.redirect` into `CallRecord.redirect` unchanged) and
    // written to disk as its own JSON line. This drives that real
    // audit-log write-and-read path end to end and checks the line itself,
    // not just the in-memory `redirect` field it was built from.
    let (e, t) = setup();
    server(GOOD.into(), log_body(5)).await;
    let tool = parse_tool_spec(&spec(serde_json::json!({})), &t).unwrap();
    let r = call(&e, &t, &tool, "GET", 65536).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert!(r.redirect.is_some());
    let record = crate::audit::CallRecord {
        identity: "test-agent".into(),
        tool_id: "github.job_logs".into(),
        outcome: r.outcome.clone(),
        exit_code: r.exit_code,
        redirect: r.redirect.clone(),
        ..Default::default()
    };
    e.store.audit.call(record).unwrap();
    let line = e.audit_lines().pop().unwrap();
    let raw = line.to_string();
    assert!(!raw.contains(SIG), "{raw}");
    assert!(!raw.contains("blobpath"), "{raw}");
    assert_eq!(line["redirect"], serde_json::json!({"from_status": 302, "host": BLOB, "status": 200, "followed": true}));
}

#[tokio::test]
async fn redact_secrets_false_on_the_toolkit_leaves_the_tail_unmasked() {
    // m4 fix (140G): `call()` passes `mask_secrets: tk.redact_secrets`
    // (not a hardcoded `true`) so this toggles the *toolkit* field through
    // the same path `service.rs:678` uses, proving the wiring is real --
    // a hardcoded `true` in `call()` would make every other test in this
    // file pass regardless of what the toolkit says.
    let e = env();
    e.store.create("demo_cred", "bearer", "tok-SECRET-1", None, None, None, "t", "").unwrap();
    install_dns(&[("api.github.com", &[&["20.250.119.72"]]), (BLOB, &[&["20.60.40.4"]])]);
    let t = tier1_opts(e.dir.path(), &format!("[\"{BLOB}\"]"), false);
    server(GOOD.into(), log_body(5)).await;
    let tool = parse_tool_spec(&spec(serde_json::json!({})), &t).unwrap();
    let r = call(&e, &t, &tool, "GET", 65536).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert_eq!(r.stdout, "line 4\nline 5\nexport GH_TOKEN=ghp_notreal123\n", "redact_secrets: false must leave the tail unmasked");
}

#[tokio::test]
async fn m1_pem_block_outside_the_tail_window_is_still_masked_whole() {
    // M1 fix (140G): the `BEGIN` line sits outside the last-N-lines window
    // that `output_tail_lines` keeps; the old order (cut to tail, then
    // mask) would drop `BEGIN` before the masker ever ran, so the PEM
    // regex -- which must see `BEGIN` and `END` together -- would not
    // match, and the key line plus `END` would reach the agent bare. The
    // fix masks the full text first, so the whole block collapses to a
    // single `[redacted]` line before the tail cut ever sees it.
    const KEY_LINE: &str = "MIIsecretKEYDATAthatmustnotleak";
    const FILLER: &str = "filler-outside-the-tail-window";
    let body = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{FILLER}\n{KEY_LINE}\n-----END RSA PRIVATE KEY-----\nafter1\nafter2\n"
    );
    let (e, t) = setup();
    server(GOOD.into(), Arc::new(body.into_bytes())).await;
    // 4 lines keeps the key line and the END marker in the tail window
    // while the BEGIN marker (line 1 of 6) falls outside it.
    let tool = parse_tool_spec(&spec(serde_json::json!({"output_tail_lines": 4})), &t).unwrap();
    let r = call(&e, &t, &tool, "GET", 65536).await;
    assert_eq!(r.outcome, OUTCOME_OK, "{}", r.stderr);
    assert!(!r.stdout.contains(KEY_LINE), "key line leaked: {:?}", r.stdout);
    assert!(!r.stdout.contains(FILLER), "filler line leaked: {:?}", r.stdout);
    assert!(r.stdout.contains("[redacted]"), "the PEM block must still be masked: {:?}", r.stdout);
    assert_eq!(r.stdout, "[redacted]\n-----END RSA PRIVATE KEY-----\nafter1\nafter2\n");
}
