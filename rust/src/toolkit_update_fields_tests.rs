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
