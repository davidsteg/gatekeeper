//! `GET /api/v1/events` over HTTP (port of the HTTP half of
//! `tests/test_api_events.py`; the topic, stream and hub units live in
//! `src/api/events.rs`).
//!
//! A stream never ends, so the end-to-end cases serve the router on a
//! loopback port and read the body as it arrives.

mod api_env;
mod app_env;

use std::time::Duration;

use api_env::{api, make_env, make_env_with, password, ApiEnv, Spec};
use futures::StreamExt;
use gatekeeper::api::events::StreamTimings;
use gatekeeper::api::ConsoleOptions;
use serde_json::{json, Value};

#[tokio::test]
async fn needs_a_console_session() {
    let env = make_env();
    let mut c = env.client();
    assert_eq!(c.get(&api("/events")).await.status, 401);
    let bearer = format!("Bearer {}", env.tokens["bot"]);
    assert_eq!(c.get_h(&api("/events"), &[("authorization", &bearer)]).await.status, 401);
}

/// Serves the env's router on a loopback port; returns the base URL.
async fn served(env: &ApiEnv) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = env.router.clone();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    base
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(30)).build().unwrap()
}

/// Signs in; returns the cookie header value and the CSRF token.
async fn signed_in(base: &str, identity: &str) -> (String, String) {
    let response = http()
        .post(format!("{base}{}", api("/session")))
        .json(&json!({"identity": identity, "password": password(identity)}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let cookie = response.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    let info: Value = response.json().await.unwrap();
    (cookie, info["csrf"].as_str().unwrap().to_string())
}

/// Lines of a streamed body.
struct Lines {
    body: futures::stream::BoxStream<'static, reqwest::Result<bytes::Bytes>>,
    buffer: String,
}

impl Lines {
    async fn next(&mut self) -> Option<String> {
        loop {
            if let Some(pos) = self.buffer.find('\n') {
                let line = self.buffer[..pos].to_string();
                self.buffer.drain(..=pos);
                return Some(line);
            }
            match self.body.next().await {
                Some(Ok(chunk)) => self.buffer.push_str(&String::from_utf8_lossy(&chunk)),
                _ => return None,
            }
        }
    }

    async fn next_event(&mut self, name: &str) -> Value {
        let mut current = None;
        while let Some(line) = self.next().await {
            if let Some(event) = line.strip_prefix("event: ") {
                current = Some(event.to_string());
            } else if let Some(data) = line.strip_prefix("data: ") {
                if current.as_deref() == Some(name) {
                    return serde_json::from_str(data).unwrap();
                }
            }
        }
        panic!("stream ended before a {name:?} event");
    }
}

async fn open_stream(base: &str, cookie: &str) -> (reqwest::header::HeaderMap, Lines) {
    let response = http().get(format!("{base}{}", api("/events"))).header("cookie", cookie).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let headers = response.headers().clone();
    (headers, Lines { body: response.bytes_stream().boxed(), buffer: String::new() })
}

#[tokio::test]
async fn a_proposal_reaches_an_open_console() {
    let env = make_env();
    let base = served(&env).await;
    let (cookie, _) = signed_in(&base, "eye").await;
    let (headers, mut lines) = open_stream(&base, &cookie).await;
    assert!(headers["content-type"].to_str().unwrap().starts_with("text/event-stream"));
    assert_eq!(headers["x-accel-buffering"], "no");
    tokio::time::timeout(Duration::from_secs(5), lines.next_event("ready")).await.unwrap();
    // What `admin.tool_enable` does for a write-category tool, from a
    // worker thread as the MCP handler would.
    let pending = env.env.pending.clone();
    let rev = env.env.store.tool_revision("demo.echo");
    tokio::task::spawn_blocking(move || {
        pending.propose("tool_enable", "root", app_env::obj(json!({"id": "demo.echo"})), &rev).unwrap();
    })
    .await
    .unwrap();
    let data = tokio::time::timeout(Duration::from_secs(5), lines.next_event("change")).await.unwrap();
    assert!(data["topics"].as_array().unwrap().contains(&json!("requests")));
}

#[tokio::test]
async fn signing_out_ends_the_stream() {
    let options = ConsoleOptions {
        stream: StreamTimings { heartbeat: Duration::from_millis(100), ..StreamTimings::default() },
        ..ConsoleOptions::default()
    };
    let env = make_env_with(Spec { options: Some(options), ..Spec::default() });
    let base = served(&env).await;
    let (cookie, csrf) = signed_in(&base, "eye").await;
    let (_, mut lines) = open_stream(&base, &cookie).await;
    tokio::time::timeout(Duration::from_secs(5), lines.next_event("ready")).await.unwrap();
    // Sign out on a second connection with the same cookie.
    let gone = http()
        .delete(format!("{base}{}", api("/session")))
        .header("cookie", &cookie)
        .header("x-csrf-token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(gone.status(), 204);
    tokio::time::timeout(Duration::from_secs(5), async { while lines.next().await.is_some() {} }).await.unwrap();
}

/// The hub drops a closed stream's subscription, so the cap frees up.
#[tokio::test]
async fn a_closed_stream_frees_its_slot() {
    let options = ConsoleOptions { max_subscribers: 1, ..ConsoleOptions::default() };
    let env = make_env_with(Spec { options: Some(options), ..Spec::default() });
    let base = served(&env).await;
    let (cookie, _) = signed_in(&base, "eye").await;
    let (_, mut lines) = open_stream(&base, &cookie).await;
    tokio::time::timeout(Duration::from_secs(5), lines.next_event("ready")).await.unwrap();
    let busy = http().get(format!("{base}{}", api("/events"))).header("cookie", &cookie).send().await.unwrap();
    assert_eq!(busy.status(), 503);
    let body: Value = busy.json().await.unwrap();
    assert_eq!(body["error"], "Too many live-update streams are open; the console falls back to polling.");
    drop(lines);
    let mut freed = false;
    for _ in 0..50 {
        let again = http().get(format!("{base}{}", api("/events"))).header("cookie", &cookie).send().await.unwrap();
        if again.status() == 200 {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(freed);
}
