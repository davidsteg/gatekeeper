//! `/api/v1` parity with properties the legacy `/ui` tests pinned (port of
//! `tests/test_api_parity.py`). Each test names the `/ui` test it replaces.

mod api_env;
mod app_env;

use api_env::{api, make_env, make_env_with, ApiEnv, Client, Spec};
use gatekeeper::catalog::load_catalog;
use gatekeeper::pending::{PendingAction, STALE_TAKEN_REASON, STALE_VANISHED_REASON};
use gatekeeper::toolkit_reference::REFERENCES;
use serde_json::{json, Value};

const SECRET_VALUE: &str = "super-secret-sonarr-key-xyz";

fn h(csrf: &str) -> Vec<(&str, &str)> {
    vec![("x-csrf-token", csrf)]
}

/// The state a toolkit restructure leaves behind: the tool's entry is no
/// longer in tools.yaml at all (not a `delete_tool` tombstone).
fn remove_tool_entry(env: &ApiEnv, tool_id: &str) {
    let path = &env.env.tools_path;
    let doc = env.env.load_yaml(path);
    let kept: Vec<Value> =
        doc["tools"].as_array().unwrap().iter().filter(|s| s["id"] != tool_id).cloned().collect();
    std::fs::write(path, gatekeeper::yaml::dump(&json!({"tools": kept}))).unwrap();
    let catalog = load_catalog(path, &env.env.service.tier1(), false).unwrap();
    env.env.service.set_catalog(catalog);
}

fn propose(env: &ApiEnv, action: &str, payload: Value, base_rev: &str) -> PendingAction {
    env.env.pending.propose(action, "hermes", app_env::obj(payload), base_rev).unwrap()
}

fn propose_delete(env: &ApiEnv, tool_id: &str) -> PendingAction {
    propose(env, "tool_delete", json!({"id": tool_id}), &env.env.store.tool_revision(tool_id))
}

async fn pending_item(c: &mut Client, item_id: &str) -> Value {
    let items = c.get(&api("/requests/pending")).await.json();
    items.as_array().unwrap().iter().find(|i| i["id"] == item_id).unwrap().clone()
}

fn status_of(env: &ApiEnv, id: &str) -> PendingAction {
    env.env.pending.get(id).unwrap().unwrap()
}

// -- Review of a grant_set ------------------------------------------------------------

/// was test_pending_page_distinguishes_real_from_missing_tools_in_a_grant
#[tokio::test]
async fn review_tells_a_real_tool_from_a_missing_one_in_a_grant() {
    let env = make_env();
    let item = propose(
        &env,
        "grant_set",
        json!({"identity_id": "bot", "role": "agent", "tools": ["demo.show", "demo.ghost"], "scopes": ["stack:*"]}),
        &env.env.store.identities_revision(),
    );
    let mut c = env.client();
    c.login("eye").await;
    let review = pending_item(&mut c, &item.id).await["review"].clone();
    let mut states: Vec<(String, String)> = review["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| (t["id"].as_str().unwrap().into(), t["state"].as_str().unwrap().into()))
        .collect();
    states.sort();
    assert_eq!(states, [("demo.ghost".into(), "missing".into()), ("demo.show".into(), "enabled".into())]);
}

/// was test_pending_page_shows_only_the_delta_of_a_grant_set
#[tokio::test]
async fn review_lists_only_the_delta_of_a_grant_set() {
    let env = make_env();
    let store = &env.env.store;
    let tools = vec!["demo.show".to_string(), "demo.echo".to_string()];
    store
        .save_identity("bot", "agent", &tools, &["stack:*".to_string()], "root", &store.identities_revision(), Some("bot"), "")
        .unwrap();
    let item = propose(
        &env,
        "grant_set",
        json!({"identity_id": "bot", "role": "agent", "tools": ["demo.echo"], "scopes": ["stack:*"],
               "prev_tools": ["demo.echo", "demo.show"]}),
        &store.identities_revision(),
    );
    let mut c = env.client();
    c.login("eye").await;
    let review = pending_item(&mut c, &item.id).await["review"].clone();
    assert_eq!(review["headline"], "identity bot: +0 -1, 1 unchanged");
    assert_eq!(review["unchanged"], 1);
    // The unchanged, enabled demo.echo collapses into the count.
    let tools: Vec<(String, String)> = review["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| (t["id"].as_str().unwrap().into(), t["marker"].as_str().unwrap().into()))
        .collect();
    assert_eq!(tools, [("demo.show".to_string(), "-".to_string())]);
}

// -- Deciding a proposal whose target is gone --------------------------------------------

/// was test_reject_closes_a_tool_delete_whose_tool_is_gone: refusing never
/// needs a live target.
#[tokio::test]
async fn reject_closes_a_tool_delete_whose_tool_is_gone() {
    let env = make_env();
    let item = propose_delete(&env, "demo.show");
    remove_tool_entry(&env, "demo.show");
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let r = c
        .post(&api(&format!("/requests/pending/{}/reject", item.id)), json!({"reason": "toolkit restructured"}), &h(&admin))
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["status"], "rejected");
    // The closed item still lists; the missing target is flagged, not fatal.
    let listing = c.get(&api("/requests/pending?status=rejected")).await;
    assert_eq!(listing.status, 200);
    let got = listing.json();
    assert_eq!(got.as_array().unwrap().len(), 1);
    assert_eq!(got[0]["review"]["tools"][0]["state"], "missing");
    let decided = status_of(&env, &item.id);
    assert_eq!(decided.status, "rejected");
    assert_eq!(decided.reason.as_deref(), Some("toolkit restructured"));
}

/// was test_visiting_requests_self_heals_a_pending_whose_tool_is_gone
#[tokio::test]
async fn listing_requests_self_heals_a_pending_whose_tool_is_gone() {
    let env = make_env();
    let item = propose_delete(&env, "demo.show");
    remove_tool_entry(&env, "demo.show");
    let mut c = env.client();
    c.login("eye").await;
    let got = pending_item(&mut c, &item.id).await;
    let live = c.get(&api("/requests/pending?status=pending")).await.json();
    let healed = status_of(&env, &item.id);
    assert_eq!(healed.status, "stale");
    assert_eq!(healed.reason.as_deref(), Some(STALE_VANISHED_REASON));
    assert_eq!(got["status"], "stale");
    assert!(got["review"]["stale"].as_str().unwrap().contains("no longer exists"));
    assert_eq!(live, json!([]));
}

/// was test_visiting_requests_leaves_a_pending_with_a_live_target_alone
#[tokio::test]
async fn listing_requests_leaves_a_pending_with_a_live_target_alone() {
    let env = make_env();
    let item = propose_delete(&env, "demo.show");
    let mut c = env.client();
    c.login("eye").await;
    c.get(&api("/requests/pending")).await;
    let got = pending_item(&mut c, &item.id).await;
    assert_eq!(got["status"], "pending");
    assert_eq!(status_of(&env, &item.id).status, "pending");
}

// -- Approve-all ---------------------------------------------------------------------------

/// was test_approve_all_partial_failure_still_applies_rest
#[tokio::test]
async fn approve_all_partial_failure_still_applies_the_rest() {
    let env = make_env();
    let store = &env.env.store;
    store.set_tool_enabled("demo.show", false, "root", &store.tools_revision()).unwrap();
    let first = propose(&env, "tool_enable", json!({"id": "demo.show"}), &store.tool_revision("demo.show"));
    let second = propose(&env, "tool_enable", json!({"id": "demo.show"}), &store.tool_revision("demo.show"));
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let r = c.post(&api("/requests/pending/approve-all"), json!({"ids": [first.id, second.id]}), &h(&admin)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let body = r.json();
    assert_eq!(body["applied"], 1);
    let refused: Vec<&Value> = body["refused"].as_array().unwrap().iter().map(|x| &x["id"]).collect();
    assert_eq!(refused, [&json!(second.id)]);
    assert_eq!(status_of(&env, &first.id).status, "approved");
    assert!(["stale", "pending"].contains(&status_of(&env, &second.id).status.as_str()));
    assert!(env.env.service.catalog().tools["demo.show"].enabled);
}

fn propose_credential(env: &ApiEnv, name: &str) -> PendingAction {
    let credentials = env.env.credentials.as_ref().unwrap();
    propose(
        env,
        "cred_propose",
        json!({"name": name, "kind": "api_key_header", "header": "X-Api-Key"}),
        &credentials.revision(),
    )
}

/// was test_approve_all_excludes_credential_proposals: a credential needs a
/// value a human types, so it is never batched.
#[tokio::test]
async fn approve_all_excludes_credential_proposals() {
    let env = make_env();
    let items = [propose_credential(&env, "sonarr"), propose_credential(&env, "radarr")];
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let ids: Vec<&str> = items.iter().map(|i| i.id.as_str()).collect();
    let r = c.post(&api("/requests/pending/approve-all"), json!({"ids": ids}), &h(&admin)).await;
    assert_eq!(r.json(), json!({"applied": 0, "refused": []}));
    assert!(items.iter().all(|i| status_of(&env, &i.id).status == "pending"));
    assert!(env.env.credentials.as_ref().unwrap().names(None).unwrap().is_empty());
}

// -- Credential fill -------------------------------------------------------------------------

/// was test_credential_fill_approves_proposal_and_creates_credential and
/// test_credential_fill_never_echoes_the_value
#[tokio::test]
async fn credential_fill_creates_what_was_proposed_and_never_echoes() {
    let env = make_env();
    let item = propose_credential(&env, "sonarr");
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let filled =
        c.post(&api(&format!("/requests/pending/{}/credential", item.id)), json!({"value": SECRET_VALUE}), &h(&admin)).await;
    assert_eq!(filled.status, 200, "{}", filled.text());
    assert!(!filled.text().contains(SECRET_VALUE));
    assert!(!c.get(&api("/credentials")).await.text().contains(SECRET_VALUE));
    let metas = env.env.credentials.as_ref().unwrap().names(None).unwrap();
    let meta = metas.iter().find(|m| m.name == "sonarr").unwrap();
    assert_eq!(meta.kind, "api_key_header");
    assert_eq!(meta.header.as_deref(), Some("X-Api-Key"));
    assert_eq!(status_of(&env, &item.id).status, "approved");
    // The value never touched the pending queue's own file.
    let queue_file = std::fs::read_to_string(env.env.tmp.join("pending.yaml")).unwrap();
    assert!(!queue_file.contains(SECRET_VALUE));
}

/// was test_credential_fill_stale_when_name_taken_meanwhile: the fill must
/// neither create a second entry nor clobber the existing one.
#[tokio::test]
async fn credential_fill_stale_when_name_taken_meanwhile() {
    let env = make_env();
    let credentials = env.env.credentials.clone().unwrap();
    let item = propose_credential(&env, "sonarr");
    credentials.create("sonarr", "bearer", "typed-directly-in-the-meantime", None, None, None, "root", "").unwrap();
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let r = c.post(&api(&format!("/requests/pending/{}/credential", item.id)), json!({"value": SECRET_VALUE}), &h(&admin)).await;
    assert_eq!(r.status, 409, "{}", r.text());
    assert!(r.error().contains("exists now"));
    assert!(!r.text().contains(SECRET_VALUE));
    let metas = credentials.names(None).unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!((metas[0].name.as_str(), metas[0].kind.as_str()), ("sonarr", "bearer"));
    // Closed, not left pending: it could never be approved.
    let closed = status_of(&env, &item.id);
    assert_eq!(closed.status, "stale");
    assert_eq!(closed.reason.as_deref(), Some(STALE_TAKEN_REASON));
}

/// The read-path sweep closes it before anyone clicks, with a review that
/// says why. A proposal for a free name is left alone.
#[tokio::test]
async fn listing_closes_a_credential_proposal_whose_name_was_taken() {
    let env = make_env();
    let credentials = env.env.credentials.clone().unwrap();
    let taken = propose_credential(&env, "sonarr");
    let free = propose_credential(&env, "radarr");
    credentials.create("sonarr", "bearer", "x", None, None, None, "root", "").unwrap();
    let mut c = env.client();
    c.login("root").await;
    let item = pending_item(&mut c, &taken.id).await;
    let again = pending_item(&mut c, &taken.id).await;
    assert_eq!(item["status"], "stale");
    assert!(item["review"]["stale"].as_str().unwrap().contains("sonarr was created after"));
    assert_eq!(again["decided_at"], item["decided_at"]); // idempotent
    assert_eq!(status_of(&env, &free.id).status, "pending");
}

#[test]
fn admin_pending_list_closes_a_taken_credential_proposal() {
    use gatekeeper::admin_service::sweep_vanished_pendings;
    let env = make_env();
    let credentials = env.env.credentials.clone().unwrap();
    let item = propose_credential(&env, "sonarr");
    credentials.create("sonarr", "bearer", "x", None, None, None, "root", "").unwrap();
    sweep_vanished_pendings(&env.env.store, &env.env.pending, None, "system").unwrap();
    assert_eq!(status_of(&env, &item.id).status, "pending"); // no credentials passed
    sweep_vanished_pendings(&env.env.store, &env.env.pending, Some(&credentials), "system").unwrap();
    assert_eq!(status_of(&env, &item.id).status, "stale");
}

// -- Paging decided requests --------------------------------------------------------------

#[tokio::test]
async fn decided_requests_page_newest_first_without_repeats() {
    let env = make_env();
    let pending = &env.env.pending;
    let mut ids = Vec::new();
    for n in 0..5 {
        let item = propose(&env, "tool_enable", json!({"id": format!("demo.t{n}")}), "");
        pending.reject(&item.id, "root", &n.to_string()).unwrap();
        ids.push(item.id);
    }
    let open_item = propose(&env, "tool_enable", json!({"id": "demo.open"}), "");
    let mut c = env.client();
    c.login("eye").await;
    let first = c.get(&api("/requests/decided?limit=2")).await.json();
    // A decision between two pages must not shift the next one.
    let late = propose(&env, "tool_enable", json!({"id": "demo.late"}), "");
    pending.reject(&late.id, "root", "").unwrap();
    let mut seen: Vec<String> = first["entries"].as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap().into()).collect();
    let mut cursor = first["next_cursor"].as_str().map(str::to_string);
    while let Some(cur) = cursor {
        let page = c.get(&api(&format!("/requests/decided?limit=2&cursor={cur}"))).await.json();
        seen.extend(page["entries"].as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap().to_string()));
        cursor = page["next_cursor"].as_str().map(str::to_string);
    }
    let bad = c.get(&api("/requests/decided?cursor=not-a-cursor")).await;
    assert_eq!(first["total"], 5);
    assert_eq!(seen, ids.iter().rev().cloned().collect::<Vec<_>>());
    assert!(!seen.contains(&open_item.id));
    assert!(first["entries"].as_array().unwrap().iter().all(|e| e["review"]["headline"].as_str().is_some_and(|s| !s.is_empty())));
    assert_eq!(bad.status, 400);
}

// -- Credential metadata ------------------------------------------------------------------

/// was test_credentials_page_shows_probe_and_suspect_metadata_without_value
#[tokio::test]
async fn credentials_show_probe_and_suspect_metadata_without_value() {
    let env = make_env();
    let credentials = env.env.credentials.clone().unwrap();
    credentials
        .create("sonarr", "bearer", SECRET_VALUE, None, Some("https://service.test/me"), None, "root", "")
        .unwrap();
    credentials.mark_suspect("sonarr", "auth_failed").unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let listing = c.get(&api("/credentials")).await;
    let meta = listing.json()["credentials"][0].clone();
    assert_eq!(meta["probe_url"], "https://service.test/me");
    assert_eq!(meta["probe_status"], "no_probe_url");
    assert_eq!(meta["suspect_status"], "auth_failed");
    assert!(meta["suspect_at"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(!listing.text().contains(SECRET_VALUE));
}

/// A console whose one toolkit carries `credential: sonarr`.
fn bound_env(create_credential: bool) -> ApiEnv {
    let env = make_env_with(Spec {
        tier1: Some(json!({"toolkits": {"demo": {"executor": "local", "binaries": ["/bin/sh"], "credential": "sonarr"}}})),
        tools: Some(Vec::new()),
        ..Spec::default()
    });
    if create_credential {
        env.env
            .credentials
            .as_ref()
            .unwrap()
            .create("sonarr", "api_key_header", SECRET_VALUE, Some("X-Api-Key"), None, None, "test", "")
            .unwrap();
    }
    env
}

/// was test_used_by_toolkit_shown
#[tokio::test]
async fn credentials_name_the_toolkit_using_them() {
    let env = bound_env(true);
    let mut c = env.client();
    c.login("eye").await;
    let listing = c.get(&api("/credentials")).await;
    let body = listing.json();
    assert_eq!(body["credentials"][0]["name"], "sonarr");
    assert_eq!(body["credentials"][0]["used_by"], json!(["demo"]));
    assert_eq!(body["dangling"], json!([]));
    assert!(!listing.text().contains(SECRET_VALUE));
}

/// was test_dangling_binding_named_on_the_page
#[tokio::test]
async fn a_dangling_binding_is_reported() {
    let env = bound_env(false);
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/credentials")).await.json();
    let toolkits = c.get(&api("/toolkits")).await.json()["toolkits"].clone();
    assert_eq!(body["credentials"], json!([]));
    assert_eq!(body["dangling"], json!(["sonarr"]));
    // ... and what refers to it.
    assert_eq!(toolkits[0]["name"], "demo");
    assert_eq!(toolkits[0]["credential"], "sonarr");
    assert_eq!(toolkits.as_array().unwrap().len(), 1);
}

// -- Toolkit proposals: kind "bind" --------------------------------------------------------

/// was test_toolkits_bind_proposal_shows_bind_pill_and_the_credential_name,
/// test_toolkits_bind_deploy_over_http_writes_and_reloads and
/// test_toolkits_bind_to_a_credential_with_no_slot_still_deploys
#[tokio::test]
async fn bind_proposal_deploys_writes_and_reloads() {
    let env = make_env();
    let (queue, service) = (&env.env.proposals, &env.env.service);
    assert!(service.tier1().toolkit("demo").unwrap().credential.is_none());
    let item = queue.propose("demo", app_env::obj(json!({"credential": "sonarr-api-key"})), "hermes", "bind").unwrap();
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let listed = c.get(&api("/requests/toolkits")).await.json();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["kind"], "bind");
    assert_eq!(listed[0]["spec"], json!({"credential": "sonarr-api-key"}));
    // An unbound toolkit says so: today's credential is None.
    assert_eq!(listed[0]["current"]["credential"], Value::Null);
    let r = c.post(&api(&format!("/requests/toolkits/{}/deploy", item.id)), json!({"confirm": true}), &h(&admin)).await;
    assert_eq!(r.status, 200, "{}", r.text());
    // No slot behind the name: deployed anyway, reported as dangling (FR-8.3g).
    let credentials = c.get(&api("/credentials")).await.json();
    assert_eq!(credentials["dangling"], json!(["sonarr-api-key"]));
    let tier1 = service.tier1();
    assert_eq!(tier1.toolkit("demo").unwrap().credential.as_deref(), Some("sonarr-api-key"));
    let refs = tier1.credential_references();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs["sonarr-api-key"], ["demo"]);
    assert_eq!(queue.get(&item.id).unwrap().unwrap().status, "deployed");
    let on_disk = env.env.load_yaml(&queue.toolkits_path)["toolkits"]["demo"].clone();
    assert_eq!(on_disk["credential"], "sonarr-api-key");
    assert_eq!(on_disk["path_roots"], json!(tier1.toolkit("demo").unwrap().path_roots));
}

/// was test_toolkits_reject_leaves_toolkits_yaml_unchanged
#[tokio::test]
async fn toolkit_reject_leaves_toolkits_yaml_unchanged() {
    let env = make_env();
    let queue = &env.env.proposals;
    let before = env.env.read(&queue.toolkits_path);
    let item = queue.propose("zfs", app_env::obj(json!({"executor": "local", "binaries": ["/bin/sh"]})), "hermes", "create").unwrap();
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let r = c.post(&api(&format!("/requests/toolkits/{}/reject", item.id)), json!({"reason": "not now"}), &h(&admin)).await;
    assert_eq!(r.json()["status"], "rejected");
    assert!(!env.env.service.tier1().toolkits.contains_key("zfs"));
    assert_eq!(env.env.read(&queue.toolkits_path), before);
}

// -- Decided requests -----------------------------------------------------------------------

/// was test_requests_archive_is_opt_in_and_paged. `?status=` selects the
/// decided items, oldest first.
#[tokio::test]
async fn decided_requests_are_listed_by_status() {
    let env = make_env();
    let (approved, rejected) = (propose_delete(&env, "demo.show"), propose_delete(&env, "demo.echo"));
    let waiting = propose(&env, "tool_disable", json!({"id": "demo.echo"}), &env.env.store.tool_revision("demo.echo"));
    let mut c = env.client();
    let admin = c.csrf("root").await;
    c.post_empty(&api(&format!("/requests/pending/{}/approve", approved.id)), &h(&admin)).await;
    c.post(&api(&format!("/requests/pending/{}/reject", rejected.id)), json!({}), &h(&admin)).await;
    let ids = |query: &'static str| {
        let mut c = c.clone();
        async move {
            let items = c.get(&api(&format!("/requests/pending{query}"))).await.json();
            items.as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap().to_string()).collect::<Vec<_>>()
        }
    };
    assert_eq!(ids("?status=approved").await, [approved.id.clone()]);
    assert_eq!(ids("?status=rejected").await, [rejected.id.clone()]);
    assert_eq!(ids("?status=pending").await, [waiting.id.clone()]);
    assert_eq!(ids("").await, [approved.id, rejected.id, waiting.id]);
}

// -- Toolkit reference ----------------------------------------------------------------------

/// was test_reference_page_lists_all_toolkit_yaml_blocks; the http reference
/// block, pasted unedited, is the only toolkit.
#[tokio::test]
async fn reference_lists_one_toolkit_yaml_per_executor() {
    let http = REFERENCES.iter().find(|r| r.key == "http").unwrap();
    let doc = gatekeeper::yaml::load(&format!("toolkits:\n{}", http.toolkit_yaml)).unwrap();
    let env = make_env_with(Spec { tier1: Some(doc), tools: Some(Vec::new()), ..Spec::default() });
    let mut c = env.client();
    c.login("eye").await;
    let reference = c.get(&api("/toolkits/reference")).await.json();
    let keys: Vec<&str> = reference.as_array().unwrap().iter().map(|r| r["key"].as_str().unwrap()).collect();
    assert_eq!(keys, REFERENCES.iter().map(|r| r.key).collect::<Vec<_>>());
    let blocks: Vec<&str> = reference.as_array().unwrap().iter().map(|r| r["toolkit_yaml"].as_str().unwrap()).collect();
    let blocks = blocks.join("\n");
    assert!(blocks.contains("executor: http"));
    assert!(blocks.contains("executor: truenas"));
}

// -- Tools listing with non-mapping templates -----------------------------------------------

/// was test_tools_page_survives_non_mapping_templates: one tool with a
/// string `body` must not take the listing down.
///
/// PORT NOTE: Python also forces a string `query_template` into the parsed
/// catalog; the Rust catalog types `query_template` as a mapping, so that
/// state cannot exist here.
#[tokio::test]
async fn tools_listing_survives_non_mapping_templates() {
    let tier1 = json!({"toolkits": {"demo_http": {
        "executor": "http", "base_url": "http://127.0.0.1:9", "allowed_methods": ["GET", "POST"],
        "allowed_path_prefixes": ["/api/"], "allowed_cidrs": ["127.0.0.1/32"],
    }}});
    let param = json!({"name": {"type": "string", "required": true, "pattern": "^[a-z]+$", "description": "item name"}});
    let base = |extra: Value| {
        let mut spec = json!({"toolkit": "demo_http", "version": 1, "required_scopes": [], "parameters": param, "path": "/api/items"});
        for (k, v) in extra.as_object().unwrap() {
            spec[k] = v.clone();
        }
        spec
    };
    let specs = vec![
        base(json!({"id": "demo_http.normal", "title": "Normal", "description": "Mapping.", "category": "read",
                    "idempotent": true, "enabled": true, "method": "GET", "query": {"name": "{name}"}})),
        base(json!({"id": "demo_http.raw_body", "title": "Raw body", "description": "Raw.", "category": "write",
                    "idempotent": false, "enabled": true, "method": "POST", "body": "{name}"})),
    ];
    let env = make_env_with(Spec { tier1: Some(tier1), tools: Some(specs), ..Spec::default() });
    assert!(env.env.service.catalog().tools["demo_http.raw_body"].body_template.as_ref().is_some_and(Value::is_string));
    let mut c = env.client();
    c.login("eye").await;
    let listing = c.get(&api("/tools")).await;
    let detail = c.get(&api("/tools/demo_http.raw_body")).await;
    let overview = c.get(&api("/overview")).await;
    assert_eq!(listing.status, 200);
    let ids: Vec<Value> = listing.json()["tools"].as_array().unwrap().iter().map(|t| t["id"].clone()).collect();
    assert_eq!(ids, [json!("demo_http.normal"), json!("demo_http.raw_body")]);
    assert_eq!(detail.status, 200);
    assert_eq!(overview.status, 200);
}
