//! `admin.toolkit_update` for an http toolkit's methods, path prefixes and
//! limits, and the network policy on proposed `allowed_cidrs` (1.11.0) --
//! port of `tests/test_toolkit_update_fields.py`.
//!
//! - `allowed_methods`, `allowed_path_prefixes`, `max_timeout_seconds` and
//!   `max_output_bytes` are proposable, pending until a human deploys, then
//!   live without a restart; methods/prefixes only on an http toolkit.
//! - A CIDR wider than /16 (IPv4) or /48 (IPv6) needs `confirm_broad_cidrs`.
//! - A private range is refused on a toolkit whose target is public.
//! - Toolkits written by hand load unchanged: the policy is for proposals.
//!
//! DNS is pinned per test thread through `TEST_DNS` (Python monkeypatches
//! `_resolve_addresses`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{ToolkitProposal, ToolkitProposalStore, TEST_DNS};
use crate::audit::AuditLog;
use crate::catalog::load_catalog;
use crate::errors::{ConfigError, ConfigResult};
use crate::identity::{generate_token, hash_token};
use crate::service::Service;
use crate::tier1::load_tier1;

fn github(extra: Value) -> Value {
    let mut spec = json!({
        "executor": "http",
        "base_url": "https://api.github.com",
        "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/repos/"],
        "allowed_cidrs": ["140.82.112.0/20"],
    });
    for (k, v) in extra.as_object().unwrap() {
        spec[k] = v.clone();
    }
    spec
}

fn sonarr() -> Value {
    json!({
        "executor": "http",
        "base_url": "http://sonarr.lan:8989",
        "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/api/"],
        "allowed_cidrs": ["192.168.1.42/32"],
    })
}

fn set_dns(table: &[(&str, &[&str])]) {
    let map: HashMap<String, Vec<IpAddr>> = table
        .iter()
        .map(|(host, addrs)| (host.to_string(), addrs.iter().map(|a| a.parse().unwrap()).collect()))
        .collect();
    TEST_DNS.with(|t| *t.borrow_mut() = Some(map));
}

fn default_dns() {
    set_dns(&[("api.github.com", &["20.250.119.72"]), ("sonarr.lan", &["192.168.1.42"])]);
}

struct Env {
    _tmp: tempfile::TempDir,
    dir: std::path::PathBuf,
    store: ToolkitProposalStore,
    service: Arc<Service>,
    toolkits_path: String,
}

fn env() -> Env {
    default_dns();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let toolkits_path = dir.join("toolkits.yaml");
    std::fs::write(
        &toolkits_path,
        crate::yaml::dump(&json!({
            "toolkits": {"github": github(json!({})), "sonarr": sonarr(), "box": {
                "executor": "local", "binaries": ["/bin/true"],
            }},
            "audit": {"dir": dir.join("logs").to_str().unwrap()},
        })),
    )
    .unwrap();
    let tools_path = dir.join("tools.yaml");
    std::fs::write(&tools_path, crate::yaml::dump(&json!({"tools": []}))).unwrap();
    let identities_path = dir.join("identities.yaml");
    std::fs::write(
        &identities_path,
        crate::yaml::dump(&json!({"identities": [{
            "id": "root", "role": "admin", "token_hash": hash_token(&generate_token()),
            "password_hash": hash_token(&"x".repeat(20)), "tools": [], "scopes": [],
        }]})),
    )
    .unwrap();
    let toolkits_path = toolkits_path.to_str().unwrap().to_string();
    let tier1 = load_tier1(&toolkits_path).unwrap();
    let catalog = load_catalog(tools_path.to_str().unwrap(), &tier1, false).unwrap();
    let audit = Arc::new(AuditLog::new(dir.join("audit").to_str().unwrap()).unwrap());
    let service = Arc::new(Service::basic(tier1, catalog, audit.clone()));
    let store = ToolkitProposalStore::new(
        dir.join("toolkit_proposals.yaml").to_str().unwrap(),
        audit,
        service.clone(),
        &toolkits_path,
        tools_path.to_str().unwrap(),
        identities_path.to_str().unwrap(),
    );
    Env { _tmp: tmp, dir, store, service, toolkits_path }
}

fn obj(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn update(e: &Env, name: &str, spec: Value) -> ConfigResult<ToolkitProposal> {
    e.store.propose(name, obj(spec), "hermes", "update")
}

fn update_confirmed(e: &Env, name: &str, spec: Value) -> ConfigResult<ToolkitProposal> {
    e.store.propose_with(name, obj(spec), "hermes", "update", true)
}

fn refused(result: ConfigResult<impl std::fmt::Debug>, needle: &str) -> ConfigError {
    let err = result.unwrap_err();
    assert!(err.is_write_refused(), "{err}");
    assert!(err.to_string().contains(needle), "{needle:?} not in {err}");
    err
}

// -- New writable fields --------------------------------------------------------

#[test]
fn methods_prefixes_and_limits_are_live_after_deploy() {
    let e = env();
    let item = update(
        &e,
        "github",
        json!({
            "allowed_methods": ["GET", "POST"],
            "allowed_path_prefixes": ["/repos/davidsteg/", "/user/repos"],
            "max_timeout_seconds": 30,
            "max_output_bytes": 262144,
        }),
    )
    .unwrap();
    // Pending changes nothing.
    assert_eq!(e.service.tier1().toolkit("github").unwrap().allowed_methods, ["GET"]);

    e.store.deploy(&item.id, "root").unwrap();

    let tier1 = e.service.tier1();
    let live = tier1.toolkit("github").unwrap();
    assert_eq!(live.allowed_methods, ["GET", "POST"]);
    assert_eq!(live.allowed_path_prefixes, ["/repos/davidsteg/", "/user/repos"]);
    assert_eq!(live.max_timeout_seconds, 30);
    assert_eq!(live.max_output_bytes, 262144);
    let on_disk = crate::yaml::load(&std::fs::read_to_string(&e.toolkits_path).unwrap()).unwrap();
    assert_eq!(on_disk["toolkits"]["github"]["allowed_methods"], json!(["GET", "POST"]));
}

#[test]
fn deploy_audits_before_and_after() {
    let e = env();
    let item = update(&e, "github", json!({"allowed_methods": ["GET", "POST"]})).unwrap();
    e.store.deploy(&item.id, "root").unwrap();
    let text = std::fs::read_to_string(e.dir.join("audit").join("audit.jsonl")).unwrap();
    let records: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let deploys: Vec<&Value> = records.iter().filter(|r| r["action"] == "toolkit_update_deploy").collect();
    assert_eq!(deploys.len(), 1);
    assert_eq!(deploys[0]["before_fields"], json!({"allowed_methods": ["GET"]}));
    assert_eq!(deploys[0]["after_fields"], json!({"allowed_methods": ["GET", "POST"]}));
}

#[test]
fn limits_must_be_positive_integers() {
    let e = env();
    for (value, repr) in
        [(json!(0), "0"), (json!(-1), "-1"), (json!("30"), "'30'"), (json!(true), "True"), (json!(1.5), "1.5"), (json!(null), "None")]
    {
        let err = refused(update(&e, "github", json!({"max_timeout_seconds": value})), "positive integer");
        assert_eq!(err.message, format!("Cannot propose max_timeout_seconds={repr}: it must be a positive integer."));
    }
}

#[test]
fn unknown_method_is_refused_at_deploy() {
    let e = env();
    let before = std::fs::read_to_string(&e.toolkits_path).unwrap();
    let item = update(&e, "github", json!({"allowed_methods": ["GET", "FETCH"]})).unwrap();
    refused(e.store.deploy(&item.id, "root"), "not HTTP");
    assert_eq!(std::fs::read_to_string(&e.toolkits_path).unwrap(), before);
}

#[test]
fn http_fields_refused_on_another_executor() {
    let e = env();
    for (spec, field) in
        [(json!({"allowed_methods": ["GET"]}), "allowed_methods"), (json!({"allowed_path_prefixes": ["/x/"]}), "allowed_path_prefixes")]
    {
        let item = update(&e, "box", spec).unwrap();
        let err = refused(e.store.deploy(&item.id, "root"), "does not use it");
        assert_eq!(
            err.message,
            format!(
                "Cannot change '{field}' on toolkit 'box': its executor 'local' does not use it. Only an http \
                 toolkit has {field}."
            )
        );
    }
}

#[test]
fn network_field_on_another_executor_says_it_does_not_connect() {
    let e = env();
    let item = update(&e, "box", json!({"allowed_cidrs": ["10.0.0.0/16"]})).unwrap();
    let err = refused(e.store.deploy(&item.id, "root"), "does not connect to a URL");
    assert_eq!(
        err.message,
        "Cannot change 'allowed_cidrs' on toolkit 'box': its executor 'local' does not use it. Only an http or \
         kuma or opencode toolkit has allowed_cidrs. (It does not connect to a URL.)"
    );
}

#[test]
fn protected_resources_stays_redeploy_only_and_root_is_never_a_path_root() {
    let e = env();
    for field in ["path_roots", "protected_resources"] {
        let mut spec = Map::new();
        spec.insert(field.into(), json!(["/"]));
        refused(e.store.propose("box", spec, "hermes", "update"), field);
    }
}

// -- Broad CIDRs ------------------------------------------------------------------

#[test]
fn broad_cidr_needs_confirmation() {
    let e = env();
    for cidr in ["140.0.0.0/8", "0.0.0.0/0", "2001:db8::/32"] {
        let err = refused(update(&e, "github", json!({"allowed_cidrs": [cidr]})), "confirm_broad_cidrs");
        assert_eq!(
            err.message,
            format!(
                "toolkit 'github': allowed_cidrs ['{cidr}'] are wider than /16 (IPv4) or /48 (IPv6). Narrow them \
                 to the service's own range, or propose again with confirm_broad_cidrs: true if this width is \
                 intended -- the reviewer then sees it flagged."
            )
        );
        assert!(e.store.list(None).unwrap().is_empty());
    }
}

#[test]
fn confirmed_broad_cidr_is_queued_flagged_and_deploys() {
    let e = env();
    let item = update_confirmed(&e, "github", json!({"allowed_cidrs": ["20.0.0.0/8"]})).unwrap();
    assert!(item.confirm_broad_cidrs);
    assert!(e.store.get(&item.id).unwrap().unwrap().confirm_broad_cidrs);
    // The flag is on the queued entry and in the propose audit record.
    let text = std::fs::read_to_string(e.dir.join("audit").join("audit.jsonl")).unwrap();
    let propose: Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(propose["action"], "toolkit_update_propose");
    assert_eq!(propose["confirm_broad_cidrs"], true);
    e.store.deploy(&item.id, "root").unwrap();
    assert_eq!(e.service.tier1().toolkit("github").unwrap().allowed_cidrs, ["20.0.0.0/8"]);
}

#[test]
fn slash_16_is_not_broad() {
    let e = env();
    let item = update(&e, "github", json!({"allowed_cidrs": ["20.250.0.0/16"]})).unwrap();
    assert!(!item.confirm_broad_cidrs);
    assert_eq!(item.to_spec()["confirm_broad_cidrs"], false);
    let text = std::fs::read_to_string(e.dir.join("audit").join("audit.jsonl")).unwrap();
    let propose: Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert!(propose.get("confirm_broad_cidrs").is_none());
}

/// A proposal file edited by hand after submit gains nothing.
#[test]
fn deploy_rechecks_a_broad_cidr_without_confirmation() {
    let e = env();
    let item = update(&e, "github", json!({"allowed_cidrs": ["20.250.0.0/16"]})).unwrap();
    let mut raw = crate::yaml::load(&std::fs::read_to_string(&e.store.path).unwrap()).unwrap();
    raw["proposals"][0]["spec"]["allowed_cidrs"] = json!(["20.0.0.0/8"]);
    std::fs::write(&e.store.path, crate::yaml::dump(&raw)).unwrap();
    refused(e.store.deploy(&item.id, "root"), "confirm_broad_cidrs");
}

// -- Private ranges on an external target ---------------------------------------

#[test]
fn private_cidr_refused_for_public_target() {
    let e = env();
    for cidr in ["10.0.0.0/24", "192.168.1.0/24", "127.0.0.1/32", "fc00::/64"] {
        let err = refused(update(&e, "github", json!({"allowed_cidrs": ["140.82.112.0/20", cidr]})), "public address");
        assert_eq!(
            err.message,
            format!(
                "toolkit 'github': allowed_cidrs ['{cidr}'] are private or otherwise non-public networks, but \
                 this toolkit's target 'api.github.com' is a public address. A private range is only for a LAN \
                 service; for a public one, list its public range or use allowed_hosts."
            )
        );
    }
}

#[test]
fn private_cidr_allowed_for_lan_target() {
    let e = env();
    let item = update(&e, "sonarr", json!({"allowed_cidrs": ["192.168.1.40/29"]})).unwrap();
    e.store.deploy(&item.id, "root").unwrap();
    assert_eq!(e.service.tier1().toolkit("sonarr").unwrap().allowed_cidrs, ["192.168.1.40/29"]);
}

/// The name moved to a public address while the proposal waited.
#[test]
fn deploy_rechecks_resolution() {
    let e = env();
    let item = update(&e, "sonarr", json!({"allowed_cidrs": ["192.168.1.40/29"]})).unwrap();
    set_dns(&[("api.github.com", &["20.250.119.72"]), ("sonarr.lan", &["93.184.216.34"])]);
    refused(e.store.deploy(&item.id, "root"), "public address");
}

#[test]
fn create_proposal_gets_the_same_policy() {
    let e = env();
    refused(
        e.store.propose_with("gh2", obj(github(json!({"allowed_cidrs": ["10.0.0.0/8"]}))), "hermes", "create", true),
        "public address",
    );
}

/// The policy is for proposals; an existing toolkits.yaml loads as before.
#[test]
fn hand_written_toolkit_is_not_judged() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("toolkits.yaml");
    std::fs::write(
        &path,
        crate::yaml::dump(&json!({
            "toolkits": {"github": github(json!({"allowed_cidrs": ["10.0.0.0/8", "0.0.0.0/0"]}))},
            "audit": {"dir": Path::new(tmp.path()).join("logs").to_str().unwrap()},
        })),
    )
    .unwrap();
    let tier1 = load_tier1(path.to_str().unwrap()).unwrap();
    assert_eq!(tier1.toolkit("github").unwrap().allowed_cidrs, ["10.0.0.0/8", "0.0.0.0/0"]);
}

// -- `redirect_allowed_hosts` and `redact_secrets` (1.31.0) ----------------------

fn env_with_tools(tools: Vec<Value>) -> Env {
    default_dns();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let toolkits_path = dir.join("toolkits.yaml");
    std::fs::write(
        &toolkits_path,
        crate::yaml::dump(&json!({
            "toolkits": {"github": github(json!({})), "sonarr": sonarr(), "box": {
                "executor": "local", "binaries": ["/bin/true"],
            }},
            "audit": {"dir": dir.join("logs").to_str().unwrap()},
        })),
    )
    .unwrap();
    let tools_path = dir.join("tools.yaml");
    std::fs::write(&tools_path, crate::yaml::dump(&json!({"tools": tools}))).unwrap();
    let identities_path = dir.join("identities.yaml");
    std::fs::write(
        &identities_path,
        crate::yaml::dump(&json!({"identities": [{
            "id": "root", "role": "admin", "token_hash": hash_token(&generate_token()),
            "password_hash": hash_token(&"x".repeat(20)), "tools": [], "scopes": [],
        }]})),
    )
    .unwrap();
    let toolkits_path = toolkits_path.to_str().unwrap().to_string();
    let tier1 = load_tier1(&toolkits_path).unwrap();
    let catalog = load_catalog(tools_path.to_str().unwrap(), &tier1, false).unwrap();
    let audit = Arc::new(AuditLog::new(dir.join("audit").to_str().unwrap()).unwrap());
    let service = Arc::new(Service::basic(tier1, catalog, audit.clone()));
    let store = ToolkitProposalStore::new(
        dir.join("toolkit_proposals.yaml").to_str().unwrap(),
        audit,
        service.clone(),
        &toolkits_path,
        tools_path.to_str().unwrap(),
        identities_path.to_str().unwrap(),
    );
    Env { _tmp: tmp, dir, store, service, toolkits_path }
}

fn blob_hosts(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("productionresultssa{i}.blob.core.windows.net")).collect()
}

/// Acceptance: `toolkit_update` on `github` with `redact_secrets: true` and
/// 140 exact `redirect_allowed_hosts` entries queues `pending`, changes
/// nothing until approved, then is live (tier1 + on-disk toolkits.yaml)
/// without a file edit or SIGHUP.
#[test]
fn redirect_allowed_hosts_and_redact_secrets_are_live_after_deploy() {
    let e = env();
    let hosts = blob_hosts(140);
    let item = update(
        &e,
        "github",
        json!({"redact_secrets": true, "redirect_allowed_hosts": hosts.clone()}),
    )
    .unwrap();
    // Pending changes nothing.
    assert!(e.service.tier1().toolkit("github").unwrap().redirect_allowed_hosts.is_empty());
    assert!(!e.service.tier1().toolkit("github").unwrap().redact_secrets);

    e.store.deploy(&item.id, "root").unwrap();

    let tier1 = e.service.tier1();
    let live = tier1.toolkit("github").unwrap();
    assert_eq!(live.redirect_allowed_hosts, hosts);
    assert!(live.redact_secrets);
    let on_disk = crate::yaml::load(&std::fs::read_to_string(&e.toolkits_path).unwrap()).unwrap();
    assert_eq!(on_disk["toolkits"]["github"]["redirect_allowed_hosts"], json!(hosts));
    assert_eq!(on_disk["toolkits"]["github"]["redact_secrets"], json!(true));
}

#[test]
fn redirect_allowed_hosts_rejects_wildcard() {
    let e = env();
    refused(update(&e, "github", json!({"redirect_allowed_hosts": ["*"]})), "wildcard");
}

#[test]
fn redirect_allowed_hosts_rejects_ip_literal() {
    let e = env();
    refused(update(&e, "github", json!({"redirect_allowed_hosts": ["20.250.119.72"]})), "IP address");
}

#[test]
fn redirect_allowed_hosts_rejects_more_than_500() {
    let e = env();
    let hosts = blob_hosts(501);
    let err = refused(update(&e, "github", json!({"redirect_allowed_hosts": hosts})), "exceeds the cap of 500");
    assert!(err.to_string().contains("501"), "{err}");
}

#[test]
fn redirect_allowed_hosts_refused_on_another_executor() {
    let e = env();
    let item = update(&e, "box", json!({"redirect_allowed_hosts": ["example.com"]})).unwrap();
    refused(e.store.deploy(&item.id, "root"), "does not use it");
}

fn job_log_tool(id: &str, extra: Value) -> Value {
    let mut spec = json!({
        "id": id, "toolkit": "github", "version": 1,
        "title": "test", "description": "test", "category": "read", "enabled": true, "idempotent": true,
        "method": "GET", "path": "/repos/x/y/actions/jobs/{job_id}/logs",
        "parameters": {"job_id": {"type": "string", "pattern": "^[0-9]{1,20}$", "required": true}},
        "timeout_seconds": 20, "max_output_bytes": 65536,
    });
    for (k, v) in extra.as_object().unwrap() { spec[k] = v.clone(); }
    spec
}

/// `redact_secrets: false` is refused while a tool on the toolkit still
/// relies on it to mask a `follow_redirect` body or an `output_tail_lines`
/// tail -- the refusal names both tools and which feature each uses.
#[test]
fn redact_secrets_false_refused_while_log_tail_tools_exist() {
    let e = env_with_tools(vec![
        job_log_tool("github.job_log_tail", json!({"follow_redirect": {"max": 1, "allowed_hosts": ["blob.core.windows.net"]}})),
        job_log_tool("github.ci_status_tail", json!({"output_tail_lines": 5})),
    ]);
    let err = refused(update(&e, "github", json!({"redact_secrets": false})), "follow_redirect or");
    assert!(err.to_string().contains("github.job_log_tail"), "{err}");
    assert!(err.to_string().contains("github.ci_status_tail"), "{err}");
    assert!(err.to_string().contains("follow_redirect"), "{err}");
    assert!(err.to_string().contains("output_tail_lines"), "{err}");
}

/// A soft-deleted tool no longer counts against `redact_secrets: false`.
#[test]
fn redact_secrets_false_ignores_deleted_tools() {
    let e = env_with_tools(vec![job_log_tool(
        "github.job_log_tail",
        json!({"follow_redirect": {"max": 1, "allowed_hosts": ["blob.core.windows.net"]}, "deleted": true}),
    )]);
    let item = update(&e, "github", json!({"redact_secrets": false})).unwrap();
    e.store.deploy(&item.id, "root").unwrap();
    assert!(!e.service.tier1().toolkit("github").unwrap().redact_secrets);
}

#[test]
fn redact_secrets_false_allowed_without_log_tail_tools() {
    let e = env();
    let item = update(&e, "sonarr", json!({"redact_secrets": false})).unwrap();
    e.store.deploy(&item.id, "root").unwrap();
    assert!(!e.service.tier1().toolkit("sonarr").unwrap().redact_secrets);
}

// -- 140X: redact_secrets type strictness, the reverse tool-path lock, and --
// -- shrinking redirect_allowed_hosts out from under an existing tool ------

/// `null` must not silently become `false` via `load_tier1`'s per-executor
/// default (which is `false` for `http`) -- it is refused up front, before
/// `check_redact_secrets` even runs, exactly like any other malformed value.
#[test]
fn redact_secrets_null_is_refused_not_silently_false() {
    let e = env();
    let err = refused(update(&e, "github", json!({"redact_secrets": null})), "must be true or false");
    assert_eq!(err.message, "Cannot propose redact_secrets=None: it must be true or false.");
    assert!(e.store.list(None).unwrap().is_empty(), "no proposal should have been queued");
}

/// A merely Python-truthy non-bool (the string `"false"`) is refused at
/// propose time now, not deferred to `load_tier1`'s stricter deploy-time
/// type check.
#[test]
fn redact_secrets_string_false_is_refused_at_propose() {
    let e = env();
    let err = refused(update(&e, "github", json!({"redact_secrets": "false"})), "must be true or false");
    assert_eq!(err.message, "Cannot propose redact_secrets='false': it must be true or false.");
    assert!(e.store.list(None).unwrap().is_empty());
}

/// Same for a `create` proposal -- the bool check runs regardless of kind.
#[test]
fn redact_secrets_non_bool_is_refused_on_create_too() {
    let e = env();
    refused(
        e.store.propose("gh2", obj(github(json!({"redact_secrets": 1}))), "hermes", "create"),
        "must be true or false",
    );
}

/// Tool-path lock (catalog::validate_against_tier1): a toolkit whose
/// effective `redact_secrets` is `false` (http's unset default here)
/// refuses a tool that adds `follow_redirect` or `output_tail_lines` --
/// the direction `check_redact_secrets` on the toolkit side cannot close,
/// because the toolkit itself did not change.
fn load_one_tool_strict(e: &Env, spec: Value) -> ConfigResult<()> {
    let tools_path = e.dir.join("tools_probe.yaml");
    std::fs::write(&tools_path, crate::yaml::dump(&json!({"tools": [spec]}))).unwrap();
    let tier1 = load_tier1(&e.toolkits_path)?;
    load_catalog(tools_path.to_str().unwrap(), &tier1, true).map(|_| ())
}

#[test]
fn follow_redirect_tool_refused_when_toolkit_redact_secrets_is_false() {
    let e = env();
    let spec = job_log_tool(
        "github.job_log_tail",
        json!({"follow_redirect": {"max": 1, "allowed_hosts": ["blob.core.windows.net"]}}),
    );
    let err = load_one_tool_strict(&e, spec).unwrap_err();
    assert!(err.message.contains("redact_secrets=false"), "{}", err.message);
    assert!(err.message.contains("follow_redirect"), "{}", err.message);
    assert!(err.message.contains("github"), "{}", err.message);
}

#[test]
fn output_tail_lines_tool_refused_when_toolkit_redact_secrets_is_false() {
    let e = env();
    let spec = job_log_tool("github.ci_status_tail", json!({"output_tail_lines": 5}));
    let err = load_one_tool_strict(&e, spec).unwrap_err();
    assert!(err.message.contains("redact_secrets=false"), "{}", err.message);
    assert!(err.message.contains("output_tail_lines"), "{}", err.message);
}

/// The same tool loads fine once the toolkit's `redact_secrets` is on.
#[test]
fn follow_redirect_tool_allowed_when_toolkit_redact_secrets_is_true() {
    let e = env();
    let item = update(
        &e,
        "github",
        json!({"redact_secrets": true, "redirect_allowed_hosts": ["blob.core.windows.net"]}),
    )
    .unwrap();
    e.store.deploy(&item.id, "root").unwrap();
    let spec = job_log_tool(
        "github.job_log_tail",
        json!({"follow_redirect": {"max": 1, "allowed_hosts": ["blob.core.windows.net"]}}),
    );
    load_one_tool_strict(&e, spec).unwrap();
}

/// `redirect_allowed_hosts` normalization: mixed case and a trailing dot
/// fold to the same lowercase host a `follow_redirect` tool names, so a
/// tool using either spelling still loads against it.
#[test]
fn redirect_allowed_hosts_normalizes_case_and_trailing_dot() {
    let e = env();
    let item = update(
        &e,
        "github",
        json!({"redact_secrets": true, "redirect_allowed_hosts": ["Blob.Core.Windows.Net."]}),
    )
    .unwrap();
    e.store.deploy(&item.id, "root").unwrap();
    assert_eq!(e.service.tier1().toolkit("github").unwrap().redirect_allowed_hosts, ["blob.core.windows.net"]);
}

/// Port, scheme and path are not hostname syntax -- `redirect_allowed_hosts`
/// entries carrying any of them are refused at propose, like a wildcard or
/// an IP literal.
#[test]
fn redirect_allowed_hosts_rejects_port_scheme_and_path() {
    let e = env();
    for host in ["blob.core.windows.net:443", "https://blob.core.windows.net", "blob.core.windows.net/x"] {
        let err = refused(
            update(&e, "github", json!({"redirect_allowed_hosts": [host]})),
            "not a valid fully qualified hostname",
        );
        assert!(err.to_string().contains(host), "{err}");
    }
}

/// An IPv6 literal (bracketed, as a URL host would carry it) is refused
/// the same way an IPv4 literal is -- addresses belong in `allowed_cidrs`.
#[test]
fn redirect_allowed_hosts_rejects_ipv6_literal() {
    let e = env();
    refused(update(&e, "github", json!({"redirect_allowed_hosts": ["[2001:db8::1]"]})), "IP address");
}

/// Shrinking `redirect_allowed_hosts` below a host an existing
/// `follow_redirect` tool still names is refused, naming the tool --
/// the mirror of `check_redact_secrets`, but for the allowlist instead
/// of the mask.
#[test]
fn redirect_allowed_hosts_shrink_refused_while_a_tool_still_uses_the_host() {
    let e = env_with_tools(vec![job_log_tool(
        "github.job_log_tail",
        json!({"follow_redirect": {"max": 1, "allowed_hosts": ["blob.core.windows.net"]}}),
    )]);
    // Start wide enough to cover the tool, and deploy it live.
    let setup = update(
        &e,
        "github",
        json!({"redact_secrets": true, "redirect_allowed_hosts": ["blob.core.windows.net", "other.example.com"]}),
    )
    .unwrap();
    e.store.deploy(&setup.id, "root").unwrap();

    // Narrowing to just the other host drops the one the tool still names.
    let err = refused(
        update(&e, "github", json!({"redirect_allowed_hosts": ["other.example.com"]})),
        "no longer be allowed",
    );
    assert!(err.to_string().contains("github.job_log_tail"), "{err}");
    assert!(err.to_string().contains("blob.core.windows.net"), "{err}");
    // Live value is untouched.
    assert_eq!(
        e.service.tier1().toolkit("github").unwrap().redirect_allowed_hosts,
        ["blob.core.windows.net", "other.example.com"]
    );
}

/// Dropping `redirect_allowed_hosts` entirely (`null`) is exactly as much
/// of a shrink as narrowing it, and is refused the same way while a tool
/// still names one of the hosts that would be lost.
#[test]
fn redirect_allowed_hosts_null_refused_while_a_tool_still_uses_a_host() {
    let e = env_with_tools(vec![job_log_tool(
        "github.job_log_tail",
        json!({"follow_redirect": {"max": 1, "allowed_hosts": ["blob.core.windows.net"]}}),
    )]);
    let setup = update(
        &e,
        "github",
        json!({"redact_secrets": true, "redirect_allowed_hosts": ["blob.core.windows.net"]}),
    )
    .unwrap();
    e.store.deploy(&setup.id, "root").unwrap();

    let err = refused(update(&e, "github", json!({"redirect_allowed_hosts": null})), "no longer be allowed");
    assert!(err.to_string().contains("github.job_log_tail"), "{err}");
}

/// FR (140Z): the proposal/review surface shows a per-host diff of
/// `redirect_allowed_hosts` against the toolkit's current live value --
/// `+host` for an addition, `-host` for a removal -- instead of only the
/// proposed list in full. Two hosts added, one removed: exactly those
/// three lines, additions first.
#[test]
fn redirect_allowed_hosts_diff_shows_exactly_the_added_and_removed_hosts() {
    let e = env();
    let setup = update(
        &e,
        "github",
        json!({
            "redact_secrets": true,
            "redirect_allowed_hosts": ["a.example.com", "b.example.com", "c.example.com"],
        }),
    )
    .unwrap();
    e.store.deploy(&setup.id, "root").unwrap();

    let item = update(
        &e,
        "github",
        json!({"redirect_allowed_hosts": ["a.example.com", "c.example.com", "d.example.com", "e.example.com"]}),
    )
    .unwrap();
    let diff = e.store.redirect_allowed_hosts_diff(&item).unwrap().unwrap();
    assert_eq!(diff, vec!["+d.example.com", "+e.example.com", "-b.example.com"]);
}

/// A proposal that does not touch `redirect_allowed_hosts` -- or any
/// non-`update` proposal -- has nothing to diff.
#[test]
fn redirect_allowed_hosts_diff_is_none_when_the_field_is_not_proposed() {
    let e = env();
    let item = update(&e, "github", json!({"redact_secrets": true})).unwrap();
    assert_eq!(e.store.redirect_allowed_hosts_diff(&item).unwrap(), None);
}

/// A tool whose `follow_redirect.allowed_hosts` does not even parse as a
/// host list (here a wildcard) is reported as affected, not silently
/// skipped, when `redirect_allowed_hosts` is narrowed -- M4 (140Z). Such
/// a tool is rejected at catalog load time regardless, but a human
/// narrowing the allowlist deserves to be told it is there rather than
/// have the check pretend it does not exist.
#[test]
fn redirect_allowed_hosts_shrink_reports_a_tool_whose_allowed_hosts_does_not_parse() {
    let e = env();
    let setup = update(
        &e,
        "github",
        json!({"redact_secrets": true, "redirect_allowed_hosts": ["blob.core.windows.net", "other.example.com"]}),
    )
    .unwrap();
    e.store.deploy(&setup.id, "root").unwrap();

    // A hand-edited `tools.yaml` carrying a tool whose
    // `follow_redirect.allowed_hosts` does not parse (a wildcard): this
    // tool is rejected at catalog load time regardless (strict or not),
    // but the *file* still has it, which is all
    // `tools_outside_redirect_allowed_hosts` reads.
    std::fs::write(
        &e.store.tools_path,
        crate::yaml::dump(&json!({"tools": [job_log_tool(
            "github.bad_host_tool",
            json!({"follow_redirect": {"max": 1, "allowed_hosts": ["*"]}}),
        )]})),
    )
    .unwrap();

    let err = refused(
        update(&e, "github", json!({"redirect_allowed_hosts": ["other.example.com"]})),
        "no longer be allowed",
    );
    assert!(err.to_string().contains("github.bad_host_tool"), "{err}");
    assert!(err.to_string().contains("does not parse"), "{err}");
}

/// Shrinking is fine once no live tool still names the dropped host.
#[test]
fn redirect_allowed_hosts_shrink_allowed_without_a_matching_tool() {
    let e = env();
    let setup = update(
        &e,
        "github",
        json!({"redact_secrets": true, "redirect_allowed_hosts": ["blob.core.windows.net", "other.example.com"]}),
    )
    .unwrap();
    e.store.deploy(&setup.id, "root").unwrap();

    let item = update(&e, "github", json!({"redirect_allowed_hosts": ["other.example.com"]})).unwrap();
    e.store.deploy(&item.id, "root").unwrap();
    assert_eq!(e.service.tier1().toolkit("github").unwrap().redirect_allowed_hosts, ["other.example.com"]);
}
