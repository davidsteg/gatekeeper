//! Live updates for the console: `GET /api/v1/events`, a Server-Sent
//! Events stream that tells an open `/app` page *that* something changed,
//! so it can refetch at once instead of waiting for its next poll (port of
//! `api/events.py`).
//!
//! Every change gatekeeper makes is written to the audit log first, so
//! `AuditLog::write` is the one place to hear about all of them.
//! [`EventHub`] listens there and turns each record into *topics*
//! (`requests`, `audit`, `tools`, ...), never the record itself: the stream
//! carries no agent-supplied text, no IDs and no values.
//!
//! What the stream may not do: outlive its session (it re-checks the
//! session on every heartbeat and before every event), run forever (it
//! closes after `STREAM_SECONDS`), or grow without bound (at most
//! `MAX_SUBSCRIBERS` streams, and a subscriber that does not keep up gets
//! "everything changed" once instead of an ever longer queue).

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use futures::Stream;
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::sync::Notify;
use tokio::time::Instant;

/// Seconds between heartbeats.
pub const HEARTBEAT_SECONDS: f64 = 15.0;
/// A stream closes after this long and the browser reconnects.
pub const STREAM_SECONDS: f64 = 10.0 * 60.0;
/// Changes arriving within this window go out as one event.
pub const COALESCE_SECONDS: f64 = 0.5;
pub const MAX_SUBSCRIBERS: usize = 64;
/// The browser's reconnect delay after a dropped stream, in milliseconds.
pub const RETRY_MS: u64 = 3000;
/// Every topic the console knows; "everything changed" is all of them.
pub const ALL_TOPICS: [&str; 8] = ["audit", "overview", "stats", "requests", "tools", "identities", "credentials", "toolkits"];
pub const QUEUE_LIMIT: usize = 64;

pub type Topics = BTreeSet<&'static str>;

pub fn all_topics() -> Topics {
    ALL_TOPICS.iter().copied().collect()
}

/// Which console queries an audit record makes stale.
pub fn topics_for(record: &Value) -> Topics {
    let mut base: Topics = ["audit", "overview"].into_iter().collect();
    let kind = record.get("kind").and_then(Value::as_str);
    let action = match record.get("action") {
        Some(v) if super::service::truthy(Some(v)) => crate::pyfmt::str_value(v),
        _ => String::new(),
    };
    match kind {
        Some("call") => {
            base.insert("stats");
            return base;
        }
        Some("ui_oauth") => {
            base.insert("credentials");
            return base;
        }
        Some("admin_change") => {}
        _ => return base,
    }
    base.insert("stats");
    if action == "pending_approve" || action.ends_with("_deploy") {
        return all_topics();
    }
    let add = |mut set: Topics, extra: &[&'static str]| {
        set.extend(extra.iter().copied());
        set
    };
    if action.starts_with("pending_") || action.ends_with("_propose") || action == "toolkit_reject" {
        return add(base, &["requests"]);
    }
    if action.starts_with("tool_") || action == "dangling_grant" {
        return add(base, &["tools", "identities"]);
    }
    if ["identity_", "token_", "password_"].iter().any(|p| action.starts_with(p)) {
        return add(base, &["identities", "tools"]);
    }
    if action.starts_with("credential_") {
        return add(base, &["credentials", "toolkits"]);
    }
    all_topics()
}

/// One open stream's queue.
#[derive(Debug)]
pub struct Subscriber {
    queue: Mutex<VecDeque<Topics>>,
    notify: Notify,
    limit: usize,
}

impl Subscriber {
    fn new(limit: usize) -> Subscriber {
        Subscriber { queue: Mutex::new(VecDeque::new()), notify: Notify::new(), limit }
    }

    /// Queues a change; behind by a whole queue, drop it and say
    /// "everything" once.
    pub fn offer(&self, topics: Topics) {
        {
            let mut queue = self.queue.lock();
            if queue.len() >= self.limit {
                queue.clear();
                queue.push_back(all_topics());
            } else {
                queue.push_back(topics);
            }
        }
        self.notify.notify_one();
    }

    pub fn try_recv(&self) -> Option<Topics> {
        self.queue.lock().pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The next change, or `None` after `timeout`.
    async fn recv_timeout(&self, timeout: Duration) -> Option<Topics> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(topics) = self.try_recv() {
                return Some(topics);
            }
            if tokio::time::timeout_at(deadline, self.notify.notified()).await.is_err() {
                return self.try_recv();
            }
        }
    }
}

/// Fans audit records out to open streams, from whatever thread wrote them.
#[derive(Debug)]
pub struct EventHub {
    subscribers: Mutex<Vec<Arc<Subscriber>>>,
    max_subscribers: usize,
    queue_limit: usize,
}

impl Default for EventHub {
    fn default() -> Self {
        EventHub::new(MAX_SUBSCRIBERS, QUEUE_LIMIT)
    }
}

impl EventHub {
    pub fn new(max_subscribers: usize, queue_limit: usize) -> EventHub {
        EventHub { subscribers: Mutex::new(Vec::new()), max_subscribers, queue_limit }
    }

    pub fn count(&self) -> usize {
        self.subscribers.lock().len()
    }

    /// `AuditLog` listener. Never fails the write that was being audited.
    pub fn publish(&self, record: &Value) {
        let topics = topics_for(record);
        let targets: Vec<Arc<Subscriber>> = self.subscribers.lock().clone();
        for sub in targets {
            sub.offer(topics.clone());
        }
    }

    pub fn subscribe(&self) -> Option<Arc<Subscriber>> {
        let mut subscribers = self.subscribers.lock();
        if subscribers.len() >= self.max_subscribers {
            return None;
        }
        let sub = Arc::new(Subscriber::new(self.queue_limit));
        subscribers.push(sub.clone());
        Some(sub)
    }

    pub fn unsubscribe(&self, sub: &Arc<Subscriber>) {
        self.subscribers.lock().retain(|s| !Arc::ptr_eq(s, sub));
    }
}

/// Stream timings (the module constants; tests shorten them).
#[derive(Debug, Clone, Copy)]
pub struct StreamTimings {
    pub heartbeat: Duration,
    pub lifetime: Duration,
    pub coalesce: Duration,
}

impl Default for StreamTimings {
    fn default() -> Self {
        StreamTimings {
            heartbeat: Duration::from_secs_f64(HEARTBEAT_SECONDS),
            lifetime: Duration::from_secs_f64(STREAM_SECONDS),
            coalesce: Duration::from_secs_f64(COALESCE_SECONDS),
        }
    }
}

fn event(name: &str, data: &Value) -> String {
    format!("event: {name}\ndata: {}\n\n", crate::pyjson::dumps_with(data, &crate::pyjson::Opts::compact()))
}

/// Unsubscribes when the stream is dropped -- finished, or the browser
/// went away and the server dropped the body.
struct Unsubscribe {
    hub: Arc<EventHub>,
    sub: Arc<Subscriber>,
}

impl Drop for Unsubscribe {
    fn drop(&mut self) {
        self.hub.unsubscribe(&self.sub);
    }
}

/// The body of one stream. `still_signed_in()` re-checks the session.
pub fn stream<F>(hub: Arc<EventHub>, sub: Arc<Subscriber>, still_signed_in: F, timings: StreamTimings) -> impl Stream<Item = String> + Send
where
    F: Fn() -> bool + Send + Sync + 'static,
{
    async_stream::stream! {
        let _guard = Unsubscribe { hub, sub: sub.clone() };
        let deadline = Instant::now() + timings.lifetime;
        yield format!("retry: {RETRY_MS}\n\n");
        yield event("ready", &json!({}));
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let wait = timings.heartbeat.min(deadline - now);
            let Some(first) = sub.recv_timeout(wait).await else {
                if !still_signed_in() {
                    break;
                }
                yield ": ping\n\n".to_string();
                continue;
            };
            let mut topics = first;
            // Gather whatever else lands in the next moment into one event.
            tokio::time::sleep(timings.coalesce).await;
            while let Some(more) = sub.try_recv() {
                topics.extend(more);
            }
            if !still_signed_in() {
                break;
            }
            yield event("change", &json!({"topics": topics.iter().collect::<Vec<_>>()}));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn set(items: &[&'static str]) -> Topics {
        items.iter().copied().collect()
    }

    #[test]
    fn topics_for_each_kind_of_record() {
        let cases: Vec<(Value, Topics)> = vec![
            (json!({"kind": "call", "tool": "demo.show"}), set(&["audit", "overview", "stats"])),
            (json!({"kind": "ui_login"}), set(&["audit", "overview"])),
            (json!({"kind": "admin_change", "action": "pending_propose"}), set(&["audit", "overview", "stats", "requests"])),
            (json!({"kind": "admin_change", "action": "toolkit_propose"}), set(&["audit", "overview", "stats", "requests"])),
            (json!({"kind": "admin_change", "action": "pending_reject"}), set(&["audit", "overview", "stats", "requests"])),
            (
                json!({"kind": "admin_change", "action": "tool_update"}),
                set(&["audit", "overview", "stats", "tools", "identities"]),
            ),
            (
                json!({"kind": "admin_change", "action": "credential_rotate"}),
                set(&["audit", "overview", "stats", "credentials", "toolkits"]),
            ),
            (json!({"kind": "admin_change", "action": "pending_approve"}), all_topics()),
            (json!({"kind": "admin_change", "action": "toolkit_deploy"}), all_topics()),
            // An action the table does not know refreshes everything.
            (json!({"kind": "admin_change", "action": "something_new"}), all_topics()),
        ];
        for (record, expected) in cases {
            assert_eq!(topics_for(&record), expected, "{record}");
        }
    }

    async fn collect<S: Stream<Item = String> + Unpin>(s: &mut S, n: usize) -> Vec<String> {
        let mut out = Vec::new();
        while out.len() < n {
            match s.next().await {
                Some(chunk) => out.push(chunk),
                None => break,
            }
        }
        out
    }

    fn fast(heartbeat: f64, lifetime: f64, coalesce: f64) -> StreamTimings {
        StreamTimings {
            heartbeat: Duration::from_secs_f64(heartbeat),
            lifetime: Duration::from_secs_f64(lifetime),
            coalesce: Duration::from_secs_f64(coalesce),
        }
    }

    #[tokio::test]
    async fn a_burst_from_another_thread_becomes_one_event() {
        let hub = Arc::new(EventHub::default());
        let sub = hub.subscribe().unwrap();
        let mut s = Box::pin(stream(hub.clone(), sub, || true, fast(15.0, 600.0, 0.05)));
        let first = collect(&mut s, 2).await;
        assert!(first[0].starts_with("retry:") && first[1].starts_with("event: ready"));
        let publisher = hub.clone();
        std::thread::spawn(move || {
            publisher.publish(&json!({"kind": "call", "tool": "demo.show", "identity": "bot", "argv": ["secret-ish"]}));
            for _ in 0..20 {
                publisher.publish(&json!({"kind": "admin_change", "action": "pending_propose", "target": "abc"}));
            }
        })
        .join()
        .unwrap();
        let change = collect(&mut s, 1).await.remove(0);
        assert!(change.starts_with("event: change\n"));
        let data: Value = serde_json::from_str(change.split("data: ").nth(1).unwrap().trim()).unwrap();
        assert_eq!(data, json!({"topics": ["audit", "overview", "requests", "stats"]}));
        // Topic names only: nothing from the record itself.
        assert!(!change.contains("demo.show") && !change.contains("bot") && !change.contains("abc"));
        drop(s);
        assert_eq!(hub.count(), 0);
    }

    #[tokio::test]
    async fn the_stream_ends_when_the_session_does() {
        let hub = Arc::new(EventHub::default());
        let sub = hub.subscribe().unwrap();
        let signed_in = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let flag = signed_in.clone();
        let mut s = Box::pin(stream(hub, sub, move || flag.load(std::sync::atomic::Ordering::SeqCst), fast(0.05, 600.0, 0.5)));
        collect(&mut s, 2).await;
        assert_eq!(collect(&mut s, 1).await, vec![": ping\n\n".to_string()]);
        signed_in.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(collect(&mut s, 1).await.is_empty());
    }

    #[tokio::test]
    async fn the_stream_has_a_lifetime() {
        let hub = Arc::new(EventHub::default());
        let sub = hub.subscribe().unwrap();
        let chunks: Vec<String> = stream(hub, sub, || true, fast(0.05, 0.2, 0.5)).collect().await;
        assert!(chunks[0].starts_with("retry:"));
        assert!(chunks[2..].iter().all(|c| c == ": ping\n\n"));
    }

    #[test]
    fn a_slow_subscriber_gets_everything_once_instead_of_a_backlog() {
        let hub = EventHub::new(MAX_SUBSCRIBERS, 3);
        let sub = hub.subscribe().unwrap();
        for _ in 0..10 {
            sub.offer(set(&["audit"]));
        }
        let mut queued = Vec::new();
        while let Some(t) = sub.try_recv() {
            queued.push(t);
        }
        assert!(queued.len() <= 3 && queued.contains(&all_topics()));
    }

    #[test]
    fn subscribers_are_capped() {
        let hub = EventHub::new(2, QUEUE_LIMIT);
        let first = hub.subscribe().unwrap();
        let _second = hub.subscribe().unwrap();
        assert!(hub.subscribe().is_none());
        hub.unsubscribe(&first);
        assert!(hub.subscribe().is_some());
    }
}
