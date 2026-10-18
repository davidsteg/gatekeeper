//! `/api/v1` writes (port of `tests/test_api_write.py`): tools,
//! identities, credentials, own password, and request decisions -- each
//! behind the API's gate order: session, role, CSRF, If-Match.

mod api_env;
mod app_env;

use api_env::{api, make_env, password, read_only_env, ApiEnv, Payload};
use gatekeeper::tier1::load_tier1;
use serde_json::{json, Value};

const FILL: [(&str, &str); 6] = [
    ("{tool_id}", "demo.show"),
    ("{identity_id}", "bot"),
    ("{name}", "demo-key"),
    ("{key}", "sonarr"),
    ("{item_id}", "nope"),
    ("{proposal_id}", "nope"),
];

/// Every write route in the schema (but the login), path parameters filled.
fn write_routes() -> Vec<(String, String)> {
    let schema: Value = serde_json::from_str(&gatekeeper::api::openapi_json()).unwrap();
    let mut out = Vec::new();
    for (path, ops) in schema["paths"].as_object().unwrap() {
        for method in ops.as_object().unwrap().keys() {
            if ["post", "put", "patch", "delete"].contains(&method.as_str()) && path != "/session" {
                let mut filled = path.clone();
                for (key, value) in FILL {
                    filled = filled.replace(key, value);
                }
                out.push((method.to_uppercase(), filled));
            }
        }
    }
    out.sort();
    out
}

fn h<'a>(csrf: &'a str, etag: Option<&'a str>) -> Vec<(&'a str, &'a str)> {
    let mut headers = vec![("x-csrf-token", csrf)];
    if let Some(etag) = etag {
        headers.push(("if-match", etag));
    }
    headers
}

fn new_tool(env: &ApiEnv) -> String {
    let binary = env.env.service.tier1().toolkits["demo"].binaries[0].clone();
    format!(
        "id: demo.hello\ntoolkit: demo\nbinary: {binary}\nversion: 1\ntitle: Hello\ndescription: Says hello.\n\
category: read\nidempotent: true\nenabled: true\nargv: [\"-c\", \"print('hello')\"]\nparameters: {{}}\n\
required_scopes: []\ntimeout_seconds: 5\nmax_output_bytes: 1024\n"
    )
}

// -- The gate, on every write route -------------------------------------------------

#[test]
fn the_schema_lists_the_phase_3a_writes() {
    let routes = write_routes();
    for (method, path) in [
        ("POST", "/tools"), ("PUT", "/tools/demo.show"), ("PUT", "/tools/demo.show/enabled"),
        ("DELETE", "/tools/demo.show"), ("POST", "/identities"), ("PUT", "/identities/bot"),
        ("POST", "/identities/bot/token"), ("DELETE", "/identities/bot"), ("POST", "/credentials"),
        ("POST", "/credentials/demo-key/rotate"), ("DELETE", "/credentials/demo-key"),
        ("PUT", "/account/password"), ("POST", "/requests/pending/nope/approve"),
        ("POST", "/requests/pending/nope/reject"), ("POST", "/requests/pending/nope/credential"),
        ("POST", "/requests/pending/approve-all"), ("POST", "/requests/pending/reject-all"),
        ("POST", "/requests/toolkits/nope/deploy"), ("POST", "/requests/toolkits/nope/reject"),
    ] {
        assert!(routes.contains(&(method.to_string(), path.to_string())), "{method} {path}");
    }
}

/// No session 401; viewer 403 (except one's own password); no CSRF 403; no
/// If-Match 428. Nothing is written by any of these attempts.
#[tokio::test]
async fn every_write_is_gated_in_order() {
    let env = make_env();
    let tools_before = env.env.store.tools_revision();
    let identities_before = env.env.store.identities_revision();
    let mut c = env.client();
    for (method, path) in write_routes() {
        let response = c.send(&method, &api(&path), &[], Payload::Json(json!({}))).await;
        assert_eq!(response.status, 401, "{path}");
    }
    let viewer = c.csrf("eye").await;
    for (method, path) in write_routes() {
        if path == "/account/password" {
            continue;
        }
        let response = c.send(&method, &api(&path), &h(&viewer, None), Payload::Json(json!({}))).await;
        assert_eq!(response.status, 403, "{method} {path}");
    }
    c.delete(&api("/session"), &h(&viewer, None)).await;

    let admin = c.csrf("root").await;
    for (method, path) in write_routes() {
        let response = c.send(&method, &api(&path), &[], Payload::Json(json!({}))).await;
        assert_eq!(response.status, 403, "{method} {path}");
        assert!(response.error().contains("CSRF"));
    }
    for (method, path) in write_routes() {
        if method == "DELETE" || path.ends_with("/token") {
            let response = c.send(&method, &api(&path), &h(&admin, None), Payload::None).await;
            assert_eq!(response.status, 428, "{method} {path}");
        }
    }
    assert_eq!(env.env.store.tools_revision(), tools_before);
    assert_eq!(env.env.store.identities_revision(), identities_before);
}

#[tokio::test]
async fn read_only_mode_refuses_every_write() {
    let env = read_only_env();
    let mut c = env.client();
    let admin = c.csrf("root").await;
    for (method, path) in write_routes() {
        let response = c.send(&method, &api(&path), &h(&admin, Some("\"x\"")), Payload::Json(json!({}))).await;
        assert_eq!(response.status, 403, "{method} {path}");
    }
}

// -- Tools ----------------------------------------------------------------------------

#[tokio::test]
async fn tool_create_update_toggle_delete() {
    let env = make_env();
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let etag = c.etag(&api("/tools")).await;
    let created = c.post(&api("/tools"), json!({"yaml": new_tool(&env)}), &h(&admin, Some(&etag))).await;
    assert_eq!(created.status, 201, "{}", created.text());
    assert_eq!(created.json()["id"], "demo.hello");
    let etag = created.header("etag").unwrap();
    assert_eq!(etag, format!("\"{}\"", created.json()["revision"].as_str().unwrap()));
    assert!(env.env.service.catalog().tools.contains_key("demo.hello"));

    let edited = new_tool(&env).replace("title: Hello", "title: Hello again");
    let updated = c.put(&api("/tools/demo.hello"), json!({"yaml": edited}), &h(&admin, Some(&etag))).await;
    assert_eq!(updated.status, 200, "{}", updated.text());
    let detail = c.get(&api("/tools/demo.hello")).await.json();
    assert_eq!(detail["spec"]["title"], "Hello again");

    let etag = updated.header("etag").unwrap();
    let off = c.put(&api("/tools/demo.hello/enabled"), json!({"enabled": false}), &h(&admin, Some(&etag))).await;
    assert_eq!(off.status, 200);
    assert_eq!(c.get(&api("/tools/demo.hello")).await.json()["enabled"], false);

    let etag = off.header("etag").unwrap();
    let gone = c.delete(&api("/tools/demo.hello"), &h(&admin, Some(&etag))).await;
    assert_eq!(gone.status, 200);
    assert_eq!(c.get(&api("/tools/demo.hello")).await.status, 404);
    let changes = env.audit_records().iter().filter(|r| r["kind"] == "admin_change").count();
    assert!(changes >= 4);
}

#[tokio::test]
async fn a_stale_etag_is_a_412_and_writes_nothing() {
    let env = make_env();
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let stale = c.etag(&api("/tools")).await;
    let first = c.post(&api("/tools"), json!({"yaml": new_tool(&env)}), &h(&admin, Some(&stale))).await;
    assert_eq!(first.status, 201);
    let before = env.env.store.tools_revision();
    let again = c.put(&api("/tools/demo.show/enabled"), json!({"enabled": false}), &h(&admin, Some(&stale))).await;
    assert_eq!(again.status, 412);
    assert_eq!(env.env.store.tools_revision(), before);
}

/// An API save is the form's save: `parse_tool_spec` against Tier 1.
#[tokio::test]
async fn tier1_still_decides() {
    let env = make_env();
    let bad = new_tool(&env).replace("argv: [\"-c\", \"print('hello')\"]", "argv: [\"--dangerous\"]");
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let etag = c.etag(&api("/tools")).await;
    let response = c.post(&api("/tools"), json!({"yaml": bad}), &h(&admin, Some(&etag))).await;
    assert_eq!(response.status, 400);
    assert!(!response.error().is_empty());
    let broken = c.post(&api("/tools"), json!({"yaml": "a: [b"}), &h(&admin, Some(&etag))).await;
    assert_eq!(broken.status, 400);
    assert!(broken.error().contains("YAML"));
    let extra = c.post(&api("/tools"), json!({"yaml": new_tool(&env), "toolkit": "x"}), &h(&admin, Some(&etag))).await;
    assert_eq!(extra.status, 422);
    assert!(!env.env.service.catalog().tools.contains_key("demo.hello"));
}

#[tokio::test]
async fn scaffold_prefills_the_editor() {
    let env = make_env();
    let mut c = env.client();
    c.login("eye").await;
    let scaffold = c.get(&api("/tool-scaffold")).await.json()["yaml"].as_str().unwrap().to_string();
    assert_eq!(gatekeeper::yaml::load(&scaffold).unwrap()["toolkit"], "demo");
    assert_eq!(c.get(&api("/integrations")).await.status, 404);
}

// -- Identities --------------------------------------------------------------------------

#[tokio::test]
async fn identity_create_returns_the_token_once() {
    let env = make_env();
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let etag = c.etag(&api("/identities")).await;
    let response = c
        .post(
            &api("/identities"),
            json!({"id": "newbot", "role": "agent", "tools": ["demo.show"], "scopes": ["stack:a"]}),
            &h(&admin, Some(&etag)),
        )
        .await;
    assert_eq!(response.status, 201, "{}", response.text());
    let token = response.json()["token"].as_str().unwrap().to_string();
    assert_eq!(env.env.identities.read().authenticate(&token).unwrap().id, "newbot");
    assert!(!c.get(&api("/identities")).await.text().contains(&token));
    assert!(!env.env.audit_text().contains(&token));
}

#[tokio::test]
async fn identity_update_with_a_password_ends_that_identitys_sessions() {
    let env = make_env();
    let mut admin_c = env.client();
    let mut eye_c = env.client();
    let admin = admin_c.csrf("root").await;
    eye_c.login("eye").await;
    let etag = admin_c.etag(&api("/identities")).await;
    let response = admin_c
        .put(
            &api("/identities/eye"),
            json!({"id": "eye", "role": "viewer", "password": "a-brand-new-password-1"}),
            &h(&admin, Some(&etag)),
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.text());
    assert_eq!(eye_c.get(&api("/session")).await.status, 401);
    assert_eq!(admin_c.get(&api("/session")).await.status, 200);
}

#[tokio::test]
async fn identity_rotate_and_delete() {
    let env = make_env();
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let etag = c.etag(&api("/identities")).await;
    let old = env.tokens["bot"].clone();
    let rotated = c.post_empty(&api("/identities/bot/token"), &h(&admin, Some(&etag))).await;
    assert_eq!(rotated.status, 200);
    let new = rotated.json()["token"].as_str().unwrap().to_string();
    assert!(env.env.identities.read().authenticate(&old).is_none());
    assert_eq!(env.env.identities.read().authenticate(&new).unwrap().id, "bot");

    let etag = rotated.header("etag").unwrap();
    let gone = c.delete(&api("/identities/bot"), &h(&admin, Some(&etag))).await;
    assert_eq!(gone.status, 200);
    assert!(env.env.identities.read().authenticate(&new).is_none());
}

#[tokio::test]
async fn deleting_yourself_ends_your_session() {
    let env = make_env();
    let mut c = env.client();
    // A second admin, so the store's last-admin guard does not refuse.
    let admin = c.csrf("root").await;
    let etag = c.etag(&api("/identities")).await;
    c.put(&api("/identities/eye"), json!({"id": "eye", "role": "admin"}), &h(&admin, Some(&etag))).await;
    let etag = c.etag(&api("/identities")).await;
    let response = c.delete(&api("/identities/root"), &h(&admin, Some(&etag))).await;
    assert_eq!(response.status, 200, "{}", response.text());
    assert_eq!(c.get(&api("/session")).await.status, 401);
}

// -- Credentials -------------------------------------------------------------------------

#[tokio::test]
async fn credential_values_go_in_and_never_come_out() {
    let env = make_env();
    let (first, second) = ("sk-first-secret-000111222", "sk-second-secret-333444555");
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let etag = c.etag(&api("/credentials")).await;
    let created = c
        .post(&api("/credentials"), json!({"name": "demo-key", "kind": "bearer", "value": first}), &h(&admin, Some(&etag)))
        .await;
    assert_eq!(created.status, 201, "{}", created.text());
    let etag = created.header("etag").unwrap();
    let rotated = c
        .post(&api("/credentials/demo-key/rotate"), json!({"value": second, "overlap_seconds": 60}), &h(&admin, Some(&etag)))
        .await;
    assert_eq!(rotated.status, 200, "{}", rotated.text());
    let listing = c.get(&api("/credentials")).await;
    let metas = listing.json()["credentials"].clone();
    assert_eq!(metas.as_array().unwrap().len(), 1);
    assert_eq!(metas[0]["in_overlap"], true);
    let bodies = created.text() + &rotated.text() + &listing.text();
    assert!(!bodies.contains(first) && !bodies.contains(second));

    let etag = listing.header("etag").unwrap();
    let bad = c.post(&api("/credentials"), json!({"name": "x", "kind": "nope", "value": "v"}), &h(&admin, Some(&etag))).await;
    assert_eq!(bad.status, 400);

    let gone = c.delete(&api("/credentials/demo-key"), &h(&admin, Some(&etag))).await;
    assert_eq!(gone.status, 200);
    assert_eq!(c.get(&api("/credentials")).await.json()["credentials"], json!([]));
    let log = env.env.audit_text();
    assert!(!log.contains(first) && !log.contains(second));
}

// -- Account -----------------------------------------------------------------------------

#[tokio::test]
async fn own_password_change() {
    let env = make_env();
    let mut c = env.client();
    let mut other = env.client();
    let me = c.csrf("eye").await;
    other.login("eye").await;
    let etag = c.etag(&api("/account")).await;
    let wrong = c
        .put(&api("/account/password"), json!({"current": "not-it", "password": "a-new-viewer-password"}), &h(&me, Some(&etag)))
        .await;
    assert_eq!(wrong.status, 400);
    assert!(env.audit_records().iter().any(|r| r["reason"] == "ui_password_change_failed"));
    let ok = c
        .put(
            &api("/account/password"),
            json!({"current": password("eye"), "password": "a-new-viewer-password"}),
            &h(&me, Some(&etag)),
        )
        .await;
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert_eq!(c.get(&api("/session")).await.status, 200);
    assert_eq!(other.get(&api("/session")).await.status, 401);
    assert!(env.env.identities.read().authenticate_console("eye", "a-new-viewer-password").is_some());
}

// -- Request decisions (phase 3b) -------------------------------------------------------

fn propose_delete(env: &ApiEnv, tool_id: &str) -> gatekeeper::pending::PendingAction {
    env.env
        .pending
        .propose("tool_delete", "hermes", app_env::obj(json!({"id": tool_id})), &env.env.store.tool_revision(tool_id))
        .unwrap()
}

#[tokio::test]
async fn pending_items_carry_a_review() {
    let env = make_env();
    let store = &env.env.store;
    env.env
        .pending
        .propose(
            "grant_set",
            "hermes",
            app_env::obj(json!({"identity_id": "bot", "tools": ["demo.show", "demo.ghost"], "prev_tools": ["demo.show"]})),
            &store.identity_revision("bot"),
        )
        .unwrap();
    propose_delete(&env, "demo.show");
    let mut c = env.client();
    c.login("eye").await;
    let items = c.get(&api("/requests/pending")).await.json();
    let review = |action: &str| items.as_array().unwrap().iter().find(|i| i["action"] == action).unwrap()["review"].clone();
    let grant = review("grant_set");
    assert_eq!(grant["headline"], "identity bot: +1 -0, 1 unchanged");
    assert_eq!(grant["tools"], json!([{"id": "demo.ghost", "marker": "+", "state": "missing", "title": "", "category": ""}]));
    assert_eq!(review("tool_delete")["tools"][0]["state"], "enabled");
}

/// A reviewer approves from the headline, so it names the fields a tool
/// update changes, the scopes a grant adds, and where a credential probe
/// sends the secret.
#[tokio::test]
async fn review_headlines_show_what_an_approval_changes() {
    let env = make_env();
    let store = &env.env.store;
    let pending = &env.env.pending;
    let prev_spec = Value::Object(store.service.catalog().raw_of("demo.show").unwrap().clone());
    let mut spec = prev_spec.clone();
    spec["argv"] = json!(["-c", "print(2)"]);
    pending
        .propose(
            "tool_update",
            "hermes",
            app_env::obj(json!({"spec": spec, "replaces": "demo.show", "prev_spec": prev_spec})),
            &store.tool_revision("demo.show"),
        )
        .unwrap();
    pending
        .propose(
            "grant_set",
            "hermes",
            app_env::obj(json!({"identity_id": "bot", "tools": ["demo.show"], "prev_tools": ["demo.show"],
                                "scopes": ["*"], "prev_scopes": ["stack:*"]})),
            &store.identity_revision("bot"),
        )
        .unwrap();
    pending
        .propose(
            "cred_propose",
            "hermes",
            app_env::obj(json!({"name": "nas", "kind": "bearer", "probe_url": "https://probe.example/x"})),
            "",
        )
        .unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let items = c.get(&api("/requests/pending")).await.json();
    let headline = |action: &str| {
        items.as_array().unwrap().iter().find(|i| i["action"] == action).unwrap()["review"]["headline"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert!(headline("tool_update").ends_with(", changes argv"), "{}", headline("tool_update"));
    assert_eq!(headline("grant_set"), "identity bot: +0 -0, 1 unchanged, scopes added: *, scopes removed: stack:*");
    assert_eq!(
        headline("cred_propose"),
        "credential nas: kind bearer (no value: typed by a human on approval, then sent to https://probe.example/x to test it)"
    );
}

#[tokio::test]
async fn approve_and_reject_a_proposal() {
    let env = make_env();
    let (first, second) = (propose_delete(&env, "demo.show"), propose_delete(&env, "demo.echo"));
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let approved = c.post_empty(&api(&format!("/requests/pending/{}/approve", first.id)), &h(&admin, None)).await;
    assert_eq!(approved.status, 200, "{}", approved.text());
    assert_eq!(approved.json(), json!({"id": first.id, "status": "approved"}));
    assert!(env.env.service.catalog().flat_spec_of("demo.show").is_none());

    let rejected = c
        .post(&api(&format!("/requests/pending/{}/reject", second.id)), json!({"reason": "not now"}), &h(&admin, None))
        .await;
    assert_eq!(rejected.json()["status"], "rejected");
    assert_eq!(env.env.pending.get(&second.id).unwrap().unwrap().reason.as_deref(), Some("not now"));

    let again = c.post_empty(&api(&format!("/requests/pending/{}/approve", first.id)), &h(&admin, None)).await;
    assert_eq!(again.status, 400);
    let missing = c.post_empty(&api("/requests/pending/nope/approve"), &h(&admin, None)).await;
    assert_eq!(missing.status, 404);
}

#[tokio::test]
async fn approve_all_applies_only_the_listed_ids() {
    let env = make_env();
    let (first, second) = (propose_delete(&env, "demo.show"), propose_delete(&env, "demo.echo"));
    let late = env
        .env
        .pending
        .propose("tool_enable", "hermes", app_env::obj(json!({"id": "demo.show"})), &env.env.store.tool_revision("demo.show"))
        .unwrap();
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let result = c.post(&api("/requests/pending/approve-all"), json!({"ids": [first.id, second.id]}), &h(&admin, None)).await;
    assert_eq!(result.status, 200);
    assert_eq!(result.json(), json!({"applied": 2, "refused": []}));
    let status = env.env.pending.get(&late.id).unwrap().unwrap().status;
    assert!(["pending", "stale"].contains(&status.as_str()));
}

#[tokio::test]
async fn reject_all_rejects_only_the_listed_ids_with_one_reason() {
    let env = make_env();
    let (first, second) = (propose_delete(&env, "demo.show"), propose_delete(&env, "demo.echo"));
    let credentials = env.env.credentials.clone().unwrap();
    let cred = env
        .env
        .pending
        .propose(
            "cred_propose",
            "hermes",
            app_env::obj(json!({"name": "sonarr-key", "kind": "bearer", "header": null, "probe_url": null})),
            &credentials.revision(),
        )
        .unwrap();
    let late = env
        .env
        .pending
        .propose("tool_enable", "hermes", app_env::obj(json!({"id": "demo.show"})), &env.env.store.tool_revision("demo.show"))
        .unwrap();
    let tools_before = env.env.store.tools_revision();
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let result = c
        .post(
            &api("/requests/pending/reject-all"),
            json!({"ids": [first.id, second.id, cred.id], "reason": "not this week"}),
            &h(&admin, None),
        )
        .await;
    let again = c.post(&api("/requests/pending/reject-all"), json!({"ids": [first.id]}), &h(&admin, None)).await;
    assert_eq!(result.status, 200);
    assert_eq!(result.json(), json!({"rejected": 3, "refused": []}));
    for item in [&first, &second, &cred] {
        let decided = env.env.pending.get(&item.id).unwrap().unwrap();
        assert_eq!(decided.status, "rejected");
        assert_eq!(decided.reason.as_deref(), Some("not this week"));
        assert_eq!(decided.decided_by.as_deref(), Some("root"));
    }
    assert_eq!(env.env.pending.get(&late.id).unwrap().unwrap().status, "pending");
    assert_eq!(env.env.store.tools_revision(), tools_before);
    // Already decided: skipped, not an error.
    assert_eq!(again.json(), json!({"rejected": 0, "refused": []}));
}

#[tokio::test]
async fn a_credential_proposal_is_approved_only_with_a_typed_value() {
    let env = make_env();
    let credentials = env.env.credentials.clone().unwrap();
    let item = env
        .env
        .pending
        .propose(
            "cred_propose",
            "hermes",
            app_env::obj(json!({"name": "sonarr-key", "kind": "bearer", "header": null, "probe_url": null})),
            &credentials.revision(),
        )
        .unwrap();
    let secret = "sk-typed-by-a-human-42";
    let mut c = env.client();
    let admin = c.csrf("root").await;
    let plain = c.post_empty(&api(&format!("/requests/pending/{}/approve", item.id)), &h(&admin, None)).await;
    assert_eq!(plain.status, 400);
    let filled = c
        .post(&api(&format!("/requests/pending/{}/credential", item.id)), json!({"value": secret}), &h(&admin, None))
        .await;
    assert_eq!(filled.status, 200, "{}", filled.text());
    assert_eq!(filled.json()["status"], "approved");
    assert!(!c.get(&api("/requests/pending")).await.text().contains(secret));
    let names: Vec<String> = credentials.names(None).unwrap().into_iter().map(|m| m.name).collect();
    assert_eq!(names, ["sonarr-key"]);
    assert!(!env.env.audit_text().contains(secret));
}

#[tokio::test]
async fn toolkit_deploy_needs_confirm_and_reloads_tier1() {
    let env = make_env();
    let queue = &env.env.proposals;
    let binary = env.env.service.tier1().toolkits["demo"].binaries[0].clone();
    let spec = || app_env::obj(json!({"executor": "local", "binaries": [binary]}));
    let item = queue.propose("extra", spec(), "hermes", "create").unwrap();
    let other = queue.propose("other", spec(), "hermes", "create").unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let listing = c.get(&api("/requests/toolkits")).await.json();
    let entry = listing.as_array().unwrap().iter().find(|p| p["id"] == item.id.as_str()).unwrap().clone();
    assert!(entry["spec_yaml"].as_str().unwrap().contains("extra:"));
    c.delete(&api("/session"), &[]).await;
    let admin = c.csrf("root").await;
    let unconfirmed = c.post(&api(&format!("/requests/toolkits/{}/deploy", item.id)), json!({}), &h(&admin, None)).await;
    assert_eq!(unconfirmed.status, 422);
    assert_eq!(queue.get(&item.id).unwrap().unwrap().status, "pending");
    let deployed = c
        .post(&api(&format!("/requests/toolkits/{}/deploy", item.id)), json!({"confirm": true}), &h(&admin, None))
        .await;
    assert_eq!(deployed.status, 200, "{}", deployed.text());
    assert_eq!(deployed.json()["status"], "deployed");
    assert!(env.env.service.tier1().toolkits.contains_key("extra"));
    let rejected = c
        .post(&api(&format!("/requests/toolkits/{}/reject", other.id)), json!({"reason": "no"}), &h(&admin, None))
        .await;
    assert_eq!(rejected.json()["status"], "rejected");
    // Written to the file too, so a restart keeps it.
    assert!(load_tier1(&queue.toolkits_path).unwrap().toolkits.contains_key("extra"));
}
