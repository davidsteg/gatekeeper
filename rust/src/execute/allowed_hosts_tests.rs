//! Toolkit network targets by hostname (`allowed_hosts`, 1.10.0) -- port
//! of `tests/test_allowed_hosts.py`.
//!
//! What has to hold, and what each test below pins:
//!
//! - an allowed name connects, to the address resolved *once* and checked,
//!   with the real hostname kept for `Host` and TLS (no second lookup, so
//!   no DNS-rebinding window between check and connect);
//! - a name not on the list is refused before any DNS query;
//! - a name resolving to a private/loopback/link-local/multicast address is
//!   refused, IPv4 and IPv6, even when `allowed_cidrs` would cover it;
//! - a redirect is reported, never followed;
//! - a toolkit with only `allowed_cidrs` behaves exactly as before;
//! - each refusal lands in the audit log with its own reason, no secret;
//! - a change to the list goes through a toolkit_update proposal and is
//!   live after approval (or a SIGHUP's reload) without a restart.
//!
//! DNS answers are pinned with a fake resolver (`test_hooks::install_dns`)
//! and every connection is routed to a loopback server
//! (`test_hooks::redirect_to`), which records where it would have gone --
//! the addresses involved are public ones, and no outside network is ever
//! contacted.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{json, Map, Value};

use super::test_hooks::{connects, dns_calls, install_dns, redirect_to};
use super::{resolve_and_check, run};
use crate::audit::AuditLog;
use crate::catalog::{load_catalog, load_catalog_value, parse_tool_spec};
use crate::errors::{ConfigError, DenialReason};
use crate::execute::{ExecResult, OUTCOME_FAILED, OUTCOME_OK};
use crate::identity::{generate_token, hash_token, Identity};
use crate::service::Service;
use crate::tier1::{load_tier1, Tier1, Toolkit};
use crate::toolkit_proposals::ToolkitProposalStore;
use crate::validate::build_http_request;

/// What api.github.com answered with in the report.
const GITHUB_IP: &str = "20.250.119.72";

fn write_tier1_value(dir: &Path, body: Value, name: &str) -> String {
    let path = dir.join(name);
    let doc = json!({"toolkits": body, "audit": {"dir": dir.join("logs").to_str().unwrap()}});
    std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
    path.to_str().unwrap().to_string()
}

fn write_tier1(dir: &Path, body: Value) -> String {
    write_tier1_value(dir, body, "toolkits.yaml")
}

fn github_toolkit(extra: Value) -> Value {
    let mut spec = json!({
        "executor": "http",
        "base_url": "https://api.github.com",
        "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/repos/"],
        "allowed_hosts": ["api.github.com"],
    });
    for (k, v) in extra.as_object().unwrap() {
        spec[k] = v.clone();
    }
    spec
}

fn tool_spec(overrides: Value) -> Value {
    let mut spec = json!({
        "id": "github.ref_get",
        "toolkit": "github",
        "version": 1,
        "title": "Get ref",
        "description": "test",
        "category": "read",
        "enabled": true,
        "idempotent": true,
        "method": "GET",
        "path": "/repos/{name}",
        "parameters": {"name": {"type": "string", "pattern": "^[a-z]+$", "required": true}},
        "timeout_seconds": 5,
        "max_output_bytes": 65536,
    });
    for (k, v) in overrides.as_object().unwrap() {
        spec[k] = v.clone();
    }
    spec
}

fn load(dir: &Path, body: Value) -> Tier1 {
    load_tier1(&write_tier1(dir, body)).unwrap()
}

/// What the loopback server saw: one `Host` header per request.
type Seen = Arc<parking_lot::Mutex<Vec<String>>>;

/// The HTTP side (what httpx's `MockTransport` was in Python): a loopback
/// server every connection of this thread is redirected to. `status` is
/// what it answers with: 200 with `{"ok": true}`, or a 302 to the cloud
/// metadata address.
async fn transport(status: Arc<parking_lot::Mutex<u16>>) -> Seen {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let seen = seen2.clone();
            let status = status.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<Incoming>| {
                    let seen = seen.clone();
                    let status = *status.lock();
                    async move {
                        let host = req
                            .headers()
                            .get("host")
                            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                            .unwrap_or_default();
                        let _ = req.into_body().collect().await;
                        seen.lock().push(host);
                        let resp = if status == 302 {
                            hyper::Response::builder()
                                .status(302)
                                .header("Location", "http://169.254.169.254/latest/meta-data/")
                                .body(Full::new(Bytes::new()))
                                .unwrap()
                        } else {
                            hyper::Response::builder()
                                .status(200)
                                .header("Content-Type", "application/json")
                                .body(Full::new(Bytes::from_static(br#"{"ok": true}"#)))
                                .unwrap()
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

async fn ok_transport() -> Seen {
    transport(Arc::new(parking_lot::Mutex::new(200))).await
}

/// The hosts (IP literals) the executor connected to, in order.
fn connected_hosts() -> Vec<String> {
    connects().iter().map(|c| c.addr.ip().to_string()).collect()
}

async fn run_tool(tk: &Toolkit, tier1: &Tier1, overrides: Value) -> ExecResult {
    let tool = parse_tool_spec(&tool_spec(overrides), tier1).unwrap();
    let values = [("name".to_string(), "gatekeeper".to_string())].into_iter().collect();
    let req = build_http_request(&tool, &values, tk).unwrap();
    run(&req.method, &req.path, &req.query, req.body.as_ref(), None, tk, None, 5.0, 65536, true, None).await.unwrap()
}

fn reason(r: &ExecResult) -> Option<&str> {
    r.denial_reason.as_deref()
}

fn err_text(r: Result<Tier1, ConfigError>) -> String {
    r.unwrap_err().to_string()
}

// -- Connect-time behaviour ---------------------------------------------------

#[tokio::test]
async fn allowed_hostname_connects_to_the_checked_address() {
    let tmp = tempfile::tempdir().unwrap();
    let tier1 = load(tmp.path(), json!({"github": github_toolkit(json!({}))}));
    install_dns(&[("api.github.com", &[&[GITHUB_IP]])]);
    let seen = ok_transport().await;

    let result = run_tool(tier1.toolkit("github").unwrap(), &tier1, json!({})).await;

    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
    assert_eq!(dns_calls(), ["api.github.com"]);
    // The socket goes to the IP that was checked; the name stays in Host
    // and SNI, so TLS still verifies api.github.com's certificate.
    let [connect] = connects().try_into().unwrap();
    assert_eq!(connect.addr, format!("{GITHUB_IP}:443").parse::<SocketAddr>().unwrap());
    assert_eq!(connect.sni_hostname.as_deref(), Some("api.github.com"));
    assert_eq!(*seen.lock(), ["api.github.com"]);
}

#[tokio::test]
async fn hostname_not_in_allowed_hosts_is_refused_before_dns() {
    let tmp = tempfile::tempdir().unwrap();
    let tier1 = load(tmp.path(), json!({"github": github_toolkit(json!({}))}));
    install_dns(&[("evil.example.com", &[&["93.184.216.34"]])]);
    let seen = ok_transport().await;
    let mut toolkit = tier1.toolkit("github").unwrap().clone();
    toolkit.base_url = Some("https://evil.example.com".into());

    let result = run_tool(&toolkit, &tier1, json!({})).await;

    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert_eq!(reason(&result), Some(DenialReason::HostNotAllowed.as_str()));
    assert!(result.stderr.contains("evil.example.com"), "{}", result.stderr);
    assert!(dns_calls().is_empty());
    assert!(seen.lock().is_empty());
}

#[tokio::test]
async fn hostname_resolving_to_non_public_address_is_blocked() {
    for private in [
        "10.0.0.1",
        "192.168.1.10",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let tier1 = load(tmp.path(), json!({"github": github_toolkit(json!({}))}));
        install_dns(&[("api.github.com", &[&[private]])]);
        let seen = ok_transport().await;

        let result = run_tool(tier1.toolkit("github").unwrap(), &tier1, json!({})).await;

        assert_eq!(result.outcome, OUTCOME_FAILED, "{private}");
        assert_eq!(reason(&result), Some(DenialReason::AddressNotPublic.as_str()), "{private}");
        assert!(seen.lock().is_empty(), "{private}");
    }
}

/// Fail-closed: a round-robin answer does not get to pick the permissive one.
#[tokio::test]
async fn one_private_address_in_the_answer_blocks_the_call() {
    let tmp = tempfile::tempdir().unwrap();
    let tier1 = load(tmp.path(), json!({"github": github_toolkit(json!({}))}));
    install_dns(&[("api.github.com", &[&[GITHUB_IP, "127.0.0.1"]])]);
    let seen = ok_transport().await;

    let result = run_tool(tier1.toolkit("github").unwrap(), &tier1, json!({})).await;

    assert_eq!(reason(&result), Some(DenialReason::AddressNotPublic.as_str()));
    assert!(seen.lock().is_empty());
}

/// The resolver answers public first and loopback on every later query.
///
/// One lookup is made, and the request goes to that checked address as an
/// IP literal -- the client never resolves the name itself, so the
/// rebinding answer is never used.
#[tokio::test]
async fn dns_rebinding_after_the_check_never_reaches_a_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let tier1 = load(tmp.path(), json!({"github": github_toolkit(json!({}))}));
    install_dns(&[("api.github.com", &[&[GITHUB_IP], &["127.0.0.1"]])]);
    let seen = ok_transport().await;

    let result = run_tool(tier1.toolkit("github").unwrap(), &tier1, json!({})).await;

    assert_eq!(result.outcome, OUTCOME_OK);
    assert_eq!(dns_calls(), ["api.github.com"]);
    assert_eq!(connected_hosts(), [GITHUB_IP]);

    // And the second call re-resolves, sees the rebinding answer, refuses.
    let again = run_tool(tier1.toolkit("github").unwrap(), &tier1, json!({})).await;
    assert_eq!(reason(&again), Some(DenialReason::AddressNotPublic.as_str()));
    assert_eq!(seen.lock().len(), 1);
}

#[tokio::test]
async fn redirect_to_a_disallowed_target_is_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let tier1 = load(tmp.path(), json!({"github": github_toolkit(json!({}))}));
    install_dns(&[("api.github.com", &[&[GITHUB_IP]])]);
    let seen = transport(Arc::new(parking_lot::Mutex::new(302))).await;

    let result = run_tool(tier1.toolkit("github").unwrap(), &tier1, json!({})).await;

    assert_eq!(result.outcome, OUTCOME_FAILED);
    assert!(result.stderr.contains("not followed"), "{}", result.stderr);
    assert_eq!(seen.lock().len(), 1);
}

#[tokio::test]
async fn cidrs_narrow_a_hostname_toolkit() {
    let tmp = tempfile::tempdir().unwrap();
    let tier1 = load(tmp.path(), json!({"github": github_toolkit(json!({"allowed_cidrs": ["140.82.112.0/20"]}))}));
    let _seen = ok_transport().await;

    install_dns(&[("api.github.com", &[&[GITHUB_IP]])]);
    let outside = run_tool(tier1.toolkit("github").unwrap(), &tier1, json!({})).await;
    assert_eq!(reason(&outside), Some(DenialReason::CidrNotAllowed.as_str()));

    install_dns(&[("api.github.com", &[&["140.82.121.6"]])]);
    let inside = run_tool(tier1.toolkit("github").unwrap(), &tier1, json!({})).await;
    assert_eq!(inside.outcome, OUTCOME_OK);
    assert_eq!(connected_hosts(), ["140.82.121.6"]);
}

#[tokio::test]
async fn cidrs_cannot_reopen_a_private_address_for_a_hostname() {
    let tmp = tempfile::tempdir().unwrap();
    let tier1 = load(tmp.path(), json!({"github": github_toolkit(json!({"allowed_cidrs": ["10.0.0.0/8"]}))}));
    install_dns(&[("api.github.com", &[&["10.1.2.3"]])]);
    let seen = ok_transport().await;

    let result = run_tool(tier1.toolkit("github").unwrap(), &tier1, json!({})).await;

    assert_eq!(reason(&result), Some(DenialReason::AddressNotPublic.as_str()));
    assert!(seen.lock().is_empty());
}

/// No allowed_hosts: any name, and a private LAN address inside the CIDR
/// list still connects -- exactly the pre-1.10.0 behaviour.
#[tokio::test]
async fn cidr_only_toolkit_is_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let tier1 = load(
        tmp.path(),
        json!({"sonarr": {
            "executor": "http",
            "base_url": "http://sonarr.lan:8989",
            "allowed_methods": ["GET"],
            "allowed_path_prefixes": ["/repos/"],
            "allowed_cidrs": ["192.168.1.42/32"],
        }}),
    );
    let toolkit = tier1.toolkit("sonarr").unwrap();
    assert!(toolkit.allowed_hosts.is_empty());
    let seen = ok_transport().await;

    install_dns(&[("sonarr.lan", &[&["192.168.1.42"]])]);
    let ok = run_tool(toolkit, &tier1, json!({"toolkit": "sonarr", "id": "sonarr.get"})).await;
    assert_eq!(ok.outcome, OUTCOME_OK);
    assert_eq!(connected_hosts(), ["192.168.1.42"]);
    assert_eq!(*seen.lock(), ["sonarr.lan:8989"]);

    install_dns(&[("sonarr.lan", &[&["192.168.1.43"]])]);
    let refused = run_tool(toolkit, &tier1, json!({"toolkit": "sonarr", "id": "sonarr.get"})).await;
    assert_eq!(reason(&refused), Some(DenialReason::CidrNotAllowed.as_str()));
}

#[tokio::test]
async fn resolve_and_check_raises_typed_denials() {
    let tmp = tempfile::tempdir().unwrap();
    let tier1 = load(tmp.path(), json!({"github": github_toolkit(json!({}))}));
    install_dns(&[("api.github.com", &[&["127.0.0.1"]])]);
    let exc = resolve_and_check("api.github.com", 443, tier1.toolkit("github").unwrap()).await.unwrap_err();
    assert_eq!(exc.reason, DenialReason::AddressNotPublic);
    // Case and a trailing root dot do not make a different host.
    install_dns(&[("API.GitHub.com.", &[&[GITHUB_IP]])]);
    let resolved = resolve_and_check("API.GitHub.com.", 443, tier1.toolkit("github").unwrap()).await.unwrap();
    assert_eq!(resolved.raw, GITHUB_IP);
}

// -- Audit ----------------------------------------------------------------------

fn identity() -> Identity {
    Identity {
        id: "agent".into(),
        role: "agent".into(),
        token_hash: hash_token("unused"),
        tools: BTreeSet::from(["github.ref_get".to_string()]),
        scopes: Vec::new(),
        password_hash: String::new(),
        token_lookup: String::new(),
    }
}

fn audit_records(dir: &Path) -> Vec<Value> {
    std::fs::read_to_string(dir.join("audit-logs").join("audit.jsonl"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn arguments() -> Map<String, Value> {
    json!({"name": "gatekeeper"}).as_object().unwrap().clone()
}

#[tokio::test]
async fn refusal_reason_is_in_the_audit_log() {
    for (answer, base_url, expected) in [
        ("10.0.0.1", None, "address_not_public"),
        (GITHUB_IP, Some("https://evil.example.com"), "host_not_allowed"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let mut tier1 = load(tmp.path(), json!({"github": github_toolkit(json!({}))}));
        let catalog = load_catalog_value(&json!({"tools": [tool_spec(json!({}))]}), &tier1, false).unwrap();
        if let Some(base_url) = base_url {
            // A toolkit pointed elsewhere by a hand edit after load: the
            // connect-time check is the authoritative one.
            tier1.toolkits.get_mut("github").unwrap().base_url = Some(base_url.into());
        }
        install_dns(&[("api.github.com", &[&[answer]]), ("evil.example.com", &[&[answer]])]);
        let _seen = ok_transport().await;
        let audit = Arc::new(AuditLog::new(tmp.path().join("audit-logs").to_str().unwrap()).unwrap());
        let service = Service::basic(tier1, catalog, audit);

        let result = service.call(&identity(), "github.ref_get", &arguments(), None).await.unwrap();

        assert_eq!(result.outcome, OUTCOME_FAILED);
        let calls: Vec<Value> =
            audit_records(tmp.path()).into_iter().filter(|r| r.get("kind") == Some(&json!("call"))).collect();
        let [record] = calls.try_into().unwrap();
        assert_eq!(record["denial_reason"], expected);
        assert!(record["detail"].as_str().is_some_and(|d| !d.is_empty()), "{record}");
    }
}

// -- Load-time validation ------------------------------------------------------

#[test]
fn allowed_hosts_accepts_exact_names_only() {
    for (host, message) in [
        ("*.github.com", "wildcard"),
        ("api.*.com", "wildcard"),
        ("20.250.119.72", "IP address"),
        ("::1", "IP address"),
        ("localhost", "fully qualified"),
        ("bad_host.example.com", "fully qualified"),
        ("https://api.github.com", "fully qualified"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_tier1(tmp.path(), json!({"github": github_toolkit(json!({"allowed_hosts": [host]}))}));
        let msg = err_text(load_tier1(&path));
        assert!(msg.contains(message), "{host}: {msg}");
    }
}

#[test]
fn allowed_hosts_are_normalized() {
    let tmp = tempfile::tempdir().unwrap();
    let tier1 = load(
        tmp.path(),
        json!({"github": github_toolkit(json!({"allowed_hosts": ["API.GitHub.com.", "api.github.com"]}))}),
    );
    assert_eq!(tier1.toolkit("github").unwrap().allowed_hosts, ["api.github.com"]);
}

#[test]
fn base_url_outside_allowed_hosts_is_refused_at_load() {
    let tmp = tempfile::tempdir().unwrap();
    let path = write_tier1(tmp.path(), json!({"github": github_toolkit(json!({"allowed_hosts": ["uploads.github.com"]}))}));
    let msg = err_text(load_tier1(&path));
    assert!(msg.contains("not in allowed_hosts"), "{msg}");
}

#[test]
fn toolkit_needs_cidrs_or_hosts() {
    let tmp = tempfile::tempdir().unwrap();
    let mut spec = github_toolkit(json!({}));
    spec.as_object_mut().unwrap().shift_remove("allowed_hosts");
    let msg = err_text(load_tier1(&write_tier1(tmp.path(), json!({"github": spec}))));
    assert!(msg.contains("allowed_cidrs' must not be empty"), "{msg}");
}

#[test]
fn allowed_hosts_refused_on_a_non_network_executor() {
    let tmp = tempfile::tempdir().unwrap();
    let path = write_tier1(
        tmp.path(),
        json!({"box": {"executor": "local", "binaries": ["/bin/true"], "allowed_hosts": ["api.github.com"]}}),
    );
    let msg = err_text(load_tier1(&path));
    assert!(msg.contains("only supported on an 'http', 'opencode' or 'kuma'"), "{msg}");
}

#[test]
fn tool_base_url_override_outside_allowed_hosts_is_disabled() {
    let tmp = tempfile::tempdir().unwrap();
    let tier1 = load(tmp.path(), json!({"github": github_toolkit(json!({}))}));
    let err = parse_tool_spec(&tool_spec(json!({"base_url": "https://evil.example.com"})), &tier1).unwrap_err();
    assert!(err.is_tier1_violation());
    assert!(err.to_string().contains("allowed_hosts"), "{err}");
}

// -- Changes through a proposal, live without a restart ------------------------

struct ProposalEnv {
    store: ToolkitProposalStore,
    service: Arc<Service>,
    toolkits_path: String,
}

fn proposal_env(dir: &Path, toolkit_spec: Value) -> ProposalEnv {
    let toolkits_path = write_tier1(dir, json!({"github": toolkit_spec}));
    let tools_path = dir.join("tools.yaml");
    std::fs::write(&tools_path, serde_json::to_string(&json!({"tools": [tool_spec(json!({}))]})).unwrap()).unwrap();
    let identities_path = dir.join("identities.yaml");
    std::fs::write(
        &identities_path,
        serde_json::to_string(&json!({"identities": [{
            "id": "root", "role": "admin", "token_hash": hash_token(&generate_token()),
            "password_hash": hash_token(&"x".repeat(20)), "tools": [], "scopes": [],
        }]}))
        .unwrap(),
    )
    .unwrap();
    let tier1 = load_tier1(&toolkits_path).unwrap();
    let catalog = load_catalog(tools_path.to_str().unwrap(), &tier1, false).unwrap();
    let audit = Arc::new(AuditLog::new(dir.join("audit-logs").to_str().unwrap()).unwrap());
    let service = Arc::new(Service::basic(tier1, catalog, audit.clone()));
    let store = ToolkitProposalStore::new(
        dir.join("toolkit_proposals.yaml").to_str().unwrap(),
        audit,
        service.clone(),
        &toolkits_path,
        tools_path.to_str().unwrap(),
        identities_path.to_str().unwrap(),
    );
    ProposalEnv { store, service, toolkits_path }
}

fn cidr_github() -> Value {
    let mut spec = github_toolkit(json!({"allowed_cidrs": ["140.82.112.0/20"]}));
    spec.as_object_mut().unwrap().shift_remove("allowed_hosts");
    spec
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[tokio::test]
async fn switch_to_hostname_via_proposal_is_live_after_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let e = proposal_env(tmp.path(), cidr_github());
    install_dns(&[("api.github.com", &[&[GITHUB_IP]])]);
    let _seen = ok_transport().await;

    let before = e.service.call(&identity(), "github.ref_get", &arguments(), None).await.unwrap();
    assert_eq!(before.outcome, OUTCOME_FAILED); // 20.250.119.72 is in no listed range

    let item = e
        .store
        .propose("github", obj(json!({"allowed_hosts": ["api.github.com"], "allowed_cidrs": null})), "hermes", "update")
        .unwrap();
    // Pending changes nothing.
    assert!(e.service.tier1().toolkit("github").unwrap().allowed_hosts.is_empty());
    let still = e.service.call(&identity(), "github.ref_get", &arguments(), None).await.unwrap();
    assert_eq!(still.outcome, OUTCOME_FAILED);

    e.store.deploy(&item.id, "root").unwrap();

    let tier1 = e.service.tier1();
    let live = tier1.toolkit("github").unwrap();
    assert_eq!(live.allowed_hosts, ["api.github.com"]);
    assert!(live.allowed_cidrs.is_empty());
    let on_disk = crate::yaml::load(&std::fs::read_to_string(&e.toolkits_path).unwrap()).unwrap();
    let on_disk = &on_disk["toolkits"]["github"];
    assert_eq!(on_disk["allowed_hosts"], json!(["api.github.com"]));
    assert!(on_disk.get("allowed_cidrs").is_none());

    let after = e.service.call(&identity(), "github.ref_get", &arguments(), None).await.unwrap();
    assert_eq!(after.outcome, OUTCOME_OK, "{}", after.stderr);
}

#[test]
fn wildcard_proposal_is_refused_at_submit() {
    let tmp = tempfile::tempdir().unwrap();
    let e = proposal_env(tmp.path(), cidr_github());
    let err = e.store.propose("github", obj(json!({"allowed_hosts": ["*.github.com"]})), "hermes", "update").unwrap_err();
    assert!(err.is_write_refused());
    assert!(err.to_string().contains("wildcard"), "{err}");
    assert!(e.store.list(None).unwrap().is_empty());
}

#[test]
fn network_fields_refused_on_a_non_network_toolkit() {
    let tmp = tempfile::tempdir().unwrap();
    let e = proposal_env(tmp.path(), cidr_github());
    let mut raw = crate::yaml::load(&std::fs::read_to_string(&e.toolkits_path).unwrap()).unwrap();
    raw["toolkits"]["box"] = json!({"executor": "local", "binaries": ["/bin/sh"]});
    std::fs::write(&e.toolkits_path, serde_json::to_string(&raw).unwrap()).unwrap();
    let item = e.store.propose("box", obj(json!({"allowed_cidrs": ["10.0.0.0/16"]})), "hermes", "update").unwrap();
    let err = e.store.deploy(&item.id, "root").unwrap_err();
    assert!(err.is_write_refused());
    assert!(err.to_string().contains("does not connect to a URL"), "{err}");
}

#[test]
fn removing_both_network_fields_is_refused_at_deploy() {
    let tmp = tempfile::tempdir().unwrap();
    let e = proposal_env(tmp.path(), cidr_github());
    let before = std::fs::read_to_string(&e.toolkits_path).unwrap();
    let item = e.store.propose("github", obj(json!({"allowed_cidrs": null})), "hermes", "update").unwrap();
    let err = e.store.deploy(&item.id, "root").unwrap_err();
    assert!(err.is_write_refused());
    assert!(err.to_string().contains("must not be empty"), "{err}");
    assert_eq!(std::fs::read_to_string(&e.toolkits_path).unwrap(), before);
    assert_eq!(e.service.tier1().toolkit("github").unwrap().allowed_cidrs, ["140.82.112.0/20"]);
}

/// What the SIGHUP handler calls (`Service::reload_config`) swaps the
/// toolkits the next call uses -- no restart.
#[tokio::test]
async fn sighup_reload_applies_a_hand_edited_toolkit() {
    let tmp = tempfile::tempdir().unwrap();
    let e = proposal_env(tmp.path(), cidr_github());
    install_dns(&[("api.github.com", &[&[GITHUB_IP]])]);
    let _seen = ok_transport().await;
    let mut raw = crate::yaml::load(&std::fs::read_to_string(&e.toolkits_path).unwrap()).unwrap();
    raw["toolkits"]["github"] = github_toolkit(json!({}));
    std::fs::write(&e.toolkits_path, serde_json::to_string(&raw).unwrap()).unwrap();

    let error = e.service.reload_config(&e.store.toolkits_path, &e.store.tools_path, &e.store.identities_path);

    assert_eq!(error, None);
    let result = e.service.call(&identity(), "github.ref_get", &arguments(), None).await.unwrap();
    assert_eq!(result.outcome, OUTCOME_OK, "{}", result.stderr);
}

/// `serve` wires SIGHUP to `Service::reload_config` -- the function the
/// test above shows swaps toolkits.
#[test]
fn sighup_handler_calls_reload_config() {
    let source = include_str!("../cli.rs");
    let start = source.find("SignalKind::hangup()").expect("SIGHUP handler");
    let handler = &source[start..start + source[start..].find("SIGHUP reload failed").unwrap()];
    assert!(handler.contains("service.reload_config("));
    assert!(handler.contains("paths.toolkits"));
}
