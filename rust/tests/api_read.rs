//! `/api/v1` reads (port of `tests/test_api_read.py`).
//!
//! Beyond "the numbers match": a credential value never leaves the process
//! on any route (FR-10.2), and neither does a token or password hash. Both
//! are checked by scanning every response for the known plaintext/hash.

mod api_env;
mod app_env;

use std::collections::HashSet;

use api_env::{api, get_paths, make_env, now_ts, read_only_env, write_audit};
use gatekeeper::identity::load_identities;
use serde_json::{json, Value};

#[tokio::test]
async fn overview() {
    let env = make_env();
    write_audit(&env, &[
        json!({"ts": now_ts(), "kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "ok"}),
        json!({"ts": now_ts(), "kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "denied"}),
    ]);
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/overview")).await.json();
    assert_eq!(body["stats"], json!({"tools_active": 2, "identities": 3, "protected_resources": 2, "tools_disabled": 0}));
    assert_eq!(body["outcomes"]["ok"], 1);
    assert_eq!(body["outcomes"]["denied"], 1);
    assert_eq!(body["outcomes"]["success_pct"], 50);
    let activity = body["activity"].as_array().unwrap();
    assert_eq!(activity.len(), 12);
    assert_eq!(activity[11]["ok"], 1);
    assert_eq!(activity[11]["not_ok"], 1);
    assert_eq!(body["notices"]["pending_changes"], 0);
    let rows = body["access"]["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["identity"], "bot");
    assert_eq!(
        rows[0]["cells"],
        json!([{"toolkit": "demo", "granted": ["demo.show"], "calls": {"ok": 1, "denied": 1, "failed": 0, "total": 2}}])
    );
    // Newest first; the sign-in that opened this session is newer still.
    let calls: Vec<&Value> = body["recent"].as_array().unwrap().iter().filter(|r| r["kind"] == "call").collect();
    assert_eq!(calls.iter().map(|r| r["outcome"].as_str().unwrap()).collect::<Vec<_>>(), ["denied", "ok"]);
}

#[tokio::test]
async fn tools_list_and_detail() {
    let env = make_env();
    let mut c = env.client();
    c.login("eye").await;
    let response = c.get(&api("/tools")).await;
    assert_eq!(response.header("etag").unwrap(), format!("\"{}\"", env.env.store.tools_revision()));
    let body = response.json();
    let ids: Vec<&str> = body["tools"].as_array().unwrap().iter().map(|t| t["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["demo.echo", "demo.show"]);
    let show = &body["tools"][1];
    assert_eq!(show["grantees"], json!(["bot"]));
    let params = show["parameters"].as_array().unwrap();
    let param = |name: &str| params.iter().find(|p| p["name"] == name).unwrap().clone();
    assert!(param("compose_path")["derived"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(param("stack")["pattern"], "^[a-z0-9][a-z0-9_-]{0,62}$");

    let detail = c.get(&api("/tools/demo.show")).await.json();
    assert_eq!(detail["id"], "demo.show");
    assert!(detail["yaml"].as_str().unwrap().contains("id: demo.show"));
    assert_eq!(detail["current_version"], 1);
    assert_eq!(detail["tools"].as_array().unwrap().iter().map(|t| t["id"].clone()).collect::<Vec<_>>(), [json!("demo.show")]);

    let missing = c.get(&api("/tools/demo.nope")).await;
    assert_eq!(missing.status, 404);
    assert!(missing.error().contains("demo.nope"));
}

#[tokio::test]
async fn identities_never_carry_a_hash() {
    let env = make_env();
    let mut c = env.client();
    c.login("eye").await;
    let response = c.get(&api("/identities")).await;
    assert_eq!(response.header("etag").unwrap(), format!("\"{}\"", env.env.store.identities_revision()));
    let body = response.json();
    let rows: Vec<(String, String, String)> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|i| (i["id"].as_str().unwrap().into(), i["role"].as_str().unwrap().into(), i["console"].as_str().unwrap().into()))
        .collect();
    let want = [("bot", "agent", "api_only"), ("eye", "viewer", "access"), ("root", "admin", "access")];
    assert_eq!(rows, want.map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string())));
    let text = response.text();
    for ident in env.env.identities.read().identities.values() {
        for secret in [&ident.token_hash, &ident.password_hash, &ident.token_lookup] {
            if !secret.is_empty() {
                assert!(!text.contains(secret.as_str()));
            }
        }
    }
    assert!(!text.contains("hash"));
}

#[tokio::test]
async fn unknown_grants_are_flagged() {
    let env = make_env();
    let path = env.env.identities_path.clone();
    let mut data = env.env.load_yaml(&path);
    data["identities"][2]["tools"].as_array_mut().unwrap().push(json!("demo.ghost"));
    std::fs::write(&path, gatekeeper::yaml::dump(&data)).unwrap();
    env.env.identities.write().identities = load_identities(&path).unwrap().identities;
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/identities")).await.json();
    let bot = body.as_array().unwrap().iter().find(|i| i["id"] == "bot").unwrap();
    assert_eq!(bot["unknown_tools"], json!(["demo.ghost"]));
}

/// FR-10.2, as a negative test over the whole read surface: create a
/// credential with a known plaintext and look for it in every response.
#[tokio::test]
async fn no_route_ever_returns_a_credential_value() {
    let env = make_env();
    let plaintext = "sk-very-secret-value-0123456789";
    let credentials = env.env.credentials.clone().unwrap();
    credentials.create("demo-key", "bearer", plaintext, None, None, None, "root", &credentials.revision()).unwrap();
    let mut c = env.client();
    c.login("root").await;
    let listing = c.get(&api("/credentials")).await;
    assert_eq!(listing.status, 200);
    let body = listing.json();
    assert_eq!(body["configured"], true);
    let metas = body["credentials"].as_array().unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0]["name"], "demo-key");
    assert_eq!(metas[0]["kind"], "bearer");
    assert!(metas[0].get("value").is_none());
    assert_eq!(listing.header("etag").unwrap(), format!("\"{}\"", credentials.revision()));
    let raw = std::fs::read_to_string(&credentials.path).unwrap();
    let mut paths = get_paths(false);
    paths.push("/openapi.json".into());
    for path in paths {
        let response = c.get(&api(&path)).await;
        assert_eq!(response.status, 200, "{path}");
        let text = response.text();
        assert!(!text.contains(plaintext), "{path}");
        // Nor any of the ciphertext, which is one key away from it.
        for line in raw.lines() {
            let token = line.split_once(':').map_or(line, |(_, t)| t).trim();
            if token.starts_with("gAAAA") {
                assert!(!text.contains(token), "{path}");
            }
        }
    }
}

#[tokio::test]
async fn credentials_report_dangling_references() {
    let env = make_env();
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/credentials")).await.json();
    assert_eq!(body, json!({"configured": true, "credentials": [], "dangling": []}));
}

#[tokio::test]
async fn toolkits_are_readable() {
    let env = make_env();
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/toolkits")).await.json();
    let toolkits = body["toolkits"].as_array().unwrap();
    assert_eq!(toolkits.len(), 1);
    assert_eq!(toolkits[0]["name"], "demo");
    assert_eq!(toolkits[0]["executor"], "local");
    assert_eq!(toolkits[0]["protected_resources"], json!(["gatekeeper", "dockhand"]));
    let reference = c.get(&api("/toolkits/reference")).await.json();
    let reference = reference.as_array().unwrap();
    assert!(!reference.is_empty());
    assert!(reference.iter().all(|r| !r["key"].as_str().unwrap().contains("toolkits")));
    assert!(reference.iter().all(|r| r["toolkit_yaml"].as_str().is_some_and(|s| !s.is_empty())));
}

#[tokio::test]
async fn pending_requests() {
    let env = make_env();
    let pending = &env.env.pending;
    let payload = app_env::obj(json!({"id": "demo.echo", "enabled": false}));
    let item = pending.propose("tool_enable", "root", payload, &env.env.store.tools_revision()).unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let response = c.get(&api("/requests/pending")).await;
    assert_eq!(response.header("etag").unwrap(), format!("\"{}\"", pending.revision()));
    let got = response.json();
    assert_eq!(got.as_array().unwrap().len(), 1);
    assert_eq!(got[0]["id"], item.id.as_str());
    assert_eq!(got[0]["status"], "pending");
    assert_eq!(c.get(&api("/requests/pending?status=approved")).await.json(), json!([]));
    let overview = c.get(&api("/overview")).await.json();
    assert_eq!(overview["notices"]["pending_changes"], 1);
}

/// A proposal comes with the live toolkit it would change, for the
/// reviewer's diff.
#[tokio::test]
async fn toolkit_proposals() {
    let env = make_env();
    let proposals = &env.env.proposals;
    let spec = app_env::obj(json!({"denied_args": ["--dangerous", "rm", "--force"]}));
    let update = proposals.propose("demo", spec, "root", "update").unwrap();
    let mut c = env.client();
    c.login("eye").await;
    let response = c.get(&api("/requests/toolkits")).await;
    assert_eq!(response.header("etag").unwrap(), format!("\"{}\"", proposals.revision()));
    let items = response.json();
    assert_eq!(items.as_array().unwrap().len(), 1);
    let item = &items[0];
    assert_eq!(item["id"], update.id.as_str());
    assert_eq!(item["kind"], "update");
    assert_eq!(item["spec"], json!({"denied_args": ["--dangerous", "rm", "--force"]}));
    assert_eq!(item["current"]["name"], "demo");
    assert_eq!(item["current"]["denied_args"], json!(["--dangerous", "rm"]));
}

#[tokio::test]
async fn audit_pagination() {
    let env = make_env();
    let records: Vec<Value> = (0..25)
        .map(|i| {
            json!({"ts": now_ts(), "kind": "call", "identity": "bot", "tool": "demo.show",
                   "outcome": if i % 2 == 1 { "ok" } else { "denied" }, "n": i})
        })
        .collect();
    write_audit(&env, &records);
    let mut c = env.client();
    c.login("eye").await;
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut url = api("/audit?limit=10&tool=demo.show");
        if let Some(cursor) = &cursor {
            url.push_str(&format!("&cursor={cursor}"));
        }
        let page = c.get(&url).await.json();
        seen.extend(page["entries"].as_array().unwrap().iter().map(|r| r["n"].as_i64().unwrap()));
        cursor = page["next_cursor"].as_str().map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen, (0..25).rev().collect::<Vec<i64>>());

    let denied = c.get(&api("/audit?outcome=denied&limit=500")).await.json();
    let entries = denied["entries"].as_array().unwrap();
    let outcomes: HashSet<&str> = entries.iter().map(|r| r["outcome"].as_str().unwrap()).collect();
    assert_eq!(outcomes, HashSet::from(["denied"]));
    assert_eq!(entries.len(), 13);

    assert_eq!(c.get(&api("/audit?cursor=not-a-cursor")).await.status, 400);
    assert_eq!(c.get(&api("/audit?outcome=bogus")).await.status, 422);
    assert_eq!(c.get(&api("/audit?limit=0")).await.status, 422);
}

#[tokio::test]
async fn release_notes() {
    let env = make_env();
    let mut c = env.client();
    c.login("eye").await;
    let body = c.get(&api("/release-notes?limit=1")).await.json();
    assert_eq!(body["version"], gatekeeper::VERSION);
    assert_eq!(body["releases"].as_array().unwrap().len(), 1);
    assert_eq!(body["releases"][0]["version"], gatekeeper::VERSION);
}

#[tokio::test]
async fn reads_work_in_read_only_mode() {
    let env = read_only_env();
    let mut c = env.client();
    c.login("eye").await;
    for path in get_paths(false) {
        assert_eq!(c.get(&api(&path)).await.status, 200, "{path}");
    }
    let account = c.get(&api("/account")).await.json();
    assert_eq!(account["can_change_password"], false);
}

/// Only the login and the session itself may be logged by a read.
#[tokio::test]
async fn reads_write_no_audit_records() {
    let env = make_env();
    let mut c = env.client();
    c.login("root").await;
    let before = env.audit_records().len();
    for path in get_paths(false) {
        c.get(&api(&path)).await;
    }
    assert_eq!(env.audit_records().len(), before);
}
