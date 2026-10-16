//! `admin.cred_update` / `cred_propose` through the console's request
//! routes (port of the route parts of `tests/test_cred_update.py`; the
//! proposal logic itself is pinned in the admin-service tests).

mod api_env;
mod app_env;

use api_env::{api, make_env_with, ApiEnv, Spec};
use serde_json::{json, Value};

const SECRET: &str = "jellyfin-token-0123456789abcdef";

fn make() -> ApiEnv {
    let tier1 = json!({"toolkits": {"jellyfin": {
        "executor": "http", "base_url": "https://jellyfin.lan", "allowed_methods": ["GET", "POST"],
        "allowed_path_prefixes": ["/Library/"], "allowed_cidrs": ["10.0.0.0/8"],
        "max_timeout_seconds": 10, "max_output_bytes": 65536, "credential": "jellyfin",
    }}});
    let env = make_env_with(Spec { tier1: Some(tier1), tools: Some(Vec::new()), ..Spec::default() });
    env.env
        .credentials
        .as_ref()
        .unwrap()
        .create("jellyfin", "api_key_header", SECRET, Some("X-Emby-Token"), None, None, "root", "")
        .unwrap();
    env
}

async fn item_of(c: &mut api_env::Client, id: &str) -> Value {
    let items = c.get(&api("/requests/pending")).await.json();
    let matching: Vec<Value> = items.as_array().unwrap().iter().filter(|i| i["id"] == id).cloned().collect();
    assert_eq!(matching.len(), 1);
    matching[0].clone()
}

#[tokio::test]
async fn console_approves_it_and_shows_the_diff() {
    let env = make();
    let result = env.env.admin().cred_update("hermes", &app_env::obj(json!({"name": "jellyfin", "header": "Authorization"}))).unwrap();
    let id = result["pending_id"].as_str().unwrap();
    let mut c = env.client();
    let csrf = c.csrf("root").await;
    let item = item_of(&mut c, id).await;
    assert_eq!(item["review"]["headline"], "credential jellyfin: header X-Emby-Token -> Authorization (stored value kept)");
    let r = c.post_empty(&api(&format!("/requests/pending/{id}/approve")), &[("x-csrf-token", &csrf)]).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["status"], "approved");
    assert!(!r.text().contains(SECRET));
    let metas = env.env.credentials.as_ref().unwrap().names(None).unwrap();
    let meta = metas.iter().find(|m| m.name == "jellyfin").unwrap();
    assert_eq!(meta.header.as_deref(), Some("Authorization"));
}

#[tokio::test]
async fn console_fill_creates_the_slot_with_its_header_format() {
    let env = make();
    let result = env
        .env
        .admin()
        .cred_propose(
            "hermes",
            &app_env::obj(json!({"name": "emby", "kind": "api_key_header", "header": "Authorization",
                                 "header_format": "MediaBrowser Token=\"{value}\""})),
        )
        .unwrap();
    let id = result["pending_id"].as_str().unwrap();
    let mut c = env.client();
    let csrf = c.csrf("root").await;
    let item = item_of(&mut c, id).await;
    assert!(item["review"]["headline"].as_str().unwrap().contains("value format MediaBrowser Token=\"{value}\""));
    let r = c
        .post(&api(&format!("/requests/pending/{id}/credential")), json!({"value": "emby-secret"}), &[("x-csrf-token", &csrf)])
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let listed = c.get(&api("/credentials")).await.json();
    let emby: Vec<&Value> = listed["credentials"].as_array().unwrap().iter().filter(|m| m["name"] == "emby").collect();
    assert_eq!(emby[0]["header_format"], "MediaBrowser Token=\"{value}\"");
    assert!(!listed.to_string().contains("emby-secret"));
}
