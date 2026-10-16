//! Telling already-connected clients that the tool catalog changed
//! (`gatekeeper/notifications.py` plus the SDK's subscription bus and
//! `ListenHandler`).
//!
//! Two routes, one call ([`CatalogNotifier::tool_catalog_changed`]):
//!
//! * **2026-07-28.** A client opts in with `subscriptions/listen`, whose
//!   response is the stream; changes fan out on the subscription bus.
//!   Serving the method is what makes `tools.listChanged` true in
//!   `server/discover`.
//! * **2025-11-25 and earlier.** The notification rides the standalone SSE
//!   stream the client opened with `GET`, which needs a retained session.
//!   Sessions are tracked by the `Mcp-Session-Id` header (see
//!   [`CatalogNotifier::track`]) so a change reaches every live session.
//!
//! Delivery is best-effort: a vanished client never turns a write into an
//! error. The notification carries no payload.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Map, Value};
use tokio::sync::mpsc;

use super::handler::{RequestContext, SessionChannel};
use super::jsonrpc;
use super::kernel::Sink;
use super::types::{McpError, INTERNAL_ERROR, INVALID_REQUEST, SUBSCRIPTION_ID_META_KEY};

/// Upper bound on tracked handshake-era sessions. The map is an LRU: every
/// tracked message moves its session to the front, so the entries evicted
/// first are the ones silent longest; an evicted-but-live session
/// re-registers on its next message.
pub const MAX_TRACKED_SESSIONS: usize = 512;
/// The session id header of the handshake-era transport.
pub const SESSION_ID_HEADER: &str = "mcp-session-id";
/// `ListenHandler(max_subscriptions=...)`.
pub const MAX_SUBSCRIPTIONS: usize = 1024;
/// `ListenHandler(max_buffered_events=...)`.
pub const MAX_BUFFERED_EVENTS: usize = 1024;

/// What a listen stream can be told (`mcp.shared.subscriptions`).
#[derive(Debug, Clone, PartialEq)]
pub enum ServerEvent {
    ToolsListChanged,
    PromptsListChanged,
    ResourcesListChanged,
    ResourceUpdated { uri: String },
}

/// The honored subset of a listen request's `notifications` filter.
#[derive(Debug, Clone, Default, PartialEq)]
struct Honored {
    tools: bool,
    prompts: bool,
    resources: bool,
    uris: Vec<String>,
}

impl Honored {
    fn from_filter(filter: &Value) -> Self {
        let flag = |k: &str| filter.get(k).and_then(Value::as_bool).unwrap_or(false);
        Honored {
            tools: flag("toolsListChanged"),
            prompts: flag("promptsListChanged"),
            resources: flag("resourcesListChanged"),
            uris: filter
                .get("resourceSubscriptions")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|u| u.as_str().map(String::from)).collect())
                .unwrap_or_default(),
        }
    }

    /// The ack's `notifications`: non-true flags and an empty URI list
    /// are dropped rather than echoed (`SubscriptionFilter` field order).
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        if self.prompts {
            m.insert("promptsListChanged".into(), Value::Bool(true));
        }
        if !self.uris.is_empty() {
            m.insert("resourceSubscriptions".into(), Value::from(self.uris.clone()));
        }
        if self.resources {
            m.insert("resourcesListChanged".into(), Value::Bool(true));
        }
        if self.tools {
            m.insert("toolsListChanged".into(), Value::Bool(true));
        }
        Value::Object(m)
    }

    fn matches(&self, event: &ServerEvent) -> bool {
        match event {
            ServerEvent::ToolsListChanged => self.tools,
            ServerEvent::PromptsListChanged => self.prompts,
            ServerEvent::ResourcesListChanged => self.resources,
            ServerEvent::ResourceUpdated { uri } => self.uris.contains(uri),
        }
    }
}

fn event_to_notification(event: &ServerEvent, meta: &Map<String, Value>) -> Value {
    let mut params = Map::new();
    params.insert("_meta".into(), Value::Object(meta.clone()));
    let method = match event {
        ServerEvent::ToolsListChanged => "notifications/tools/list_changed",
        ServerEvent::PromptsListChanged => "notifications/prompts/list_changed",
        ServerEvent::ResourcesListChanged => "notifications/resources/list_changed",
        ServerEvent::ResourceUpdated { uri } => {
            params.insert("uri".into(), Value::from(uri.clone()));
            "notifications/resources/updated"
        }
    };
    jsonrpc::notification(method, Some(Value::Object(params)))
}

struct Listener {
    honored: Honored,
    tx: mpsc::Sender<ServerEvent>,
}

#[derive(Default)]
struct Bus {
    next: u64,
    /// Subscription order (`InMemorySubscriptionBus` delivers in it).
    listeners: BTreeMap<u64, Listener>,
}

#[derive(Default)]
struct Inner {
    /// Front = most recently active.
    sessions: Mutex<VecDeque<(String, Arc<dyn SessionChannel>)>>,
    bus: Mutex<Bus>,
    runtime: Mutex<Option<tokio::runtime::Handle>>,
}

/// Fans `notifications/tools/list_changed` out to every live connection of
/// one MCP mount. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct CatalogNotifier {
    inner: Arc<Inner>,
}

impl CatalogNotifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Capture the tokio runtime the transports run on. `mcp::router`
    /// calls this when built inside a runtime; without a bound runtime
    /// [`tool_catalog_changed`](Self::tool_catalog_changed) only logs.
    pub fn bind_runtime(&self, handle: tokio::runtime::Handle) {
        *self.inner.runtime.lock() = Some(handle);
    }

    /// [`bind_runtime`](Self::bind_runtime) with the current runtime, if any.
    pub fn bind_current(&self) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            self.bind_runtime(handle);
        }
    }

    // -- Session tracking (handshake era) -----------------------------------

    /// Remember the session this request arrived on, if it has one. Called
    /// from the application's `tools/list` handler and from
    /// `on_initialized`. Requests without an `Mcp-Session-Id` (stateless
    /// mounts, the 2026-07-28 wire) are skipped: they have no standalone
    /// channel.
    pub fn track(&self, ctx: &RequestContext) {
        let Some(session_id) = ctx.session_header() else { return };
        let Some(channel) = ctx.channel.clone() else { return };
        self.track_channel(session_id, channel);
    }

    /// [`track`](Self::track) with an explicit key and channel.
    pub fn track_channel(&self, session_id: &str, channel: Arc<dyn SessionChannel>) {
        let mut sessions = self.inner.sessions.lock();
        sessions.retain(|(id, _)| id != session_id);
        sessions.push_front((session_id.to_string(), channel));
        while sessions.len() > MAX_TRACKED_SESSIONS {
            if let Some((evicted, _)) = sessions.pop_back() {
                tracing::debug!("Forgetting least recently active MCP session {}", prefix8(&evicted));
            }
        }
    }

    /// Drop a session the client terminated (`DELETE`).
    pub fn forget(&self, session_id: &str) {
        self.inner.sessions.lock().retain(|(id, _)| id != session_id);
    }

    /// How many handshake-era sessions are currently tracked.
    pub fn tracked_sessions(&self) -> usize {
        self.inner.sessions.lock().len()
    }

    /// Whether `session_id` is tracked (tests).
    pub fn is_tracked(&self, session_id: &str) -> bool {
        self.inner.sessions.lock().iter().any(|(id, _)| id == session_id)
    }

    // -- Sending ---------------------------------------------------------------

    /// Announce a catalog change. Safe to call from any thread, sync by
    /// design: the send is scheduled on the bound runtime and never awaited.
    pub fn tool_catalog_changed(&self) {
        let handle = self.inner.runtime.lock().clone();
        let Some(handle) = handle else {
            tracing::debug!("Tool catalog changed before the event loop was bound; no clients yet");
            return;
        };
        let this = self.clone();
        // A runtime that has shut down drops the task; nothing to notify then.
        drop(handle.spawn(async move { this.broadcast().await }));
    }

    /// Deliver the notification on both routes. Never fails.
    pub async fn broadcast(&self) {
        self.publish(ServerEvent::ToolsListChanged);
        let sessions: Vec<(String, Arc<dyn SessionChannel>)> = self.inner.sessions.lock().iter().cloned().collect();
        for (session_id, channel) in sessions {
            if channel.send_tool_list_changed().is_err() {
                tracing::debug!("Dropping MCP session {}: notify failed", prefix8(&session_id));
                self.forget(&session_id);
            }
        }
    }

    /// Publish an event to every open listen stream whose filter admits it.
    pub fn publish(&self, event: ServerEvent) {
        let mut bus = self.inner.bus.lock();
        let mut ended = Vec::new();
        for (token, listener) in bus.listeners.iter() {
            if !listener.honored.matches(&event) {
                continue;
            }
            match listener.tx.try_send(event.clone()) {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!("listen stream {token} backlog full; ending the stream");
                    ended.push(*token);
                }
            }
        }
        for token in ended {
            bus.listeners.remove(&token);
        }
    }

    /// End every open listen stream gracefully: each drains its backlog and
    /// answers with its `SubscriptionsListenResult`.
    pub fn close_listen_streams(&self) {
        self.inner.bus.lock().listeners.clear();
    }

    /// Open listen streams.
    pub fn listen_streams(&self) -> usize {
        self.inner.bus.lock().listeners.len()
    }

    /// Serve one `subscriptions/listen` request (already surface-validated).
    pub(crate) async fn listen(&self, request_id: Option<&Value>, filter: &Value, sink: &Sink) -> Result<Value, McpError> {
        let Some(subscription_id) = request_id else {
            return Err(McpError::rpc(INVALID_REQUEST, "subscriptions/listen requires a request id"));
        };
        let honored = Honored::from_filter(filter);
        let mut meta = Map::new();
        meta.insert(SUBSCRIPTION_ID_META_KEY.into(), subscription_id.clone());
        let (tx, mut rx) = mpsc::channel(MAX_BUFFERED_EVENTS);
        let token = {
            let mut bus = self.inner.bus.lock();
            if bus.listeners.len() >= MAX_SUBSCRIPTIONS {
                return Err(McpError::rpc(INTERNAL_ERROR, "Subscription limit reached"));
            }
            bus.next += 1;
            let token = bus.next;
            bus.listeners.insert(token, Listener { honored: honored.clone(), tx });
            token
        };
        let _guard = Unsubscribe { inner: self.inner.clone(), token };
        let mut ack = Map::new();
        ack.insert("_meta".into(), Value::Object(meta.clone()));
        ack.insert("notifications".into(), honored.to_value());
        super::kernel::notify(sink, jsonrpc::notification("notifications/subscriptions/acknowledged", Some(Value::Object(ack))))
            .await;
        while let Some(event) = rx.recv().await {
            super::kernel::notify(sink, event_to_notification(&event, &meta)).await;
        }
        let mut result = Map::new();
        result.insert("_meta".into(), Value::Object(meta));
        result.insert("resultType".into(), Value::from("complete"));
        Ok(Value::Object(result))
    }
}

struct Unsubscribe {
    inner: Arc<Inner>,
    token: u64,
}

impl Drop for Unsubscribe {
    fn drop(&mut self) {
        self.inner.bus.lock().listeners.remove(&self.token);
    }
}

fn prefix8(s: &str) -> &str {
    match s.char_indices().nth(8) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct FakeSession {
        sent: AtomicUsize,
        broken: bool,
    }

    impl SessionChannel for FakeSession {
        fn send_tool_list_changed(&self) -> Result<(), ()> {
            if self.broken {
                return Err(());
            }
            self.sent.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn ctx(session_id: Option<&str>, session: Arc<FakeSession>) -> RequestContext {
        let mut c = RequestContext::detached("tools/list", "2025-11-25").with_channel(session);
        if let Some(id) = session_id {
            c.headers.insert(SESSION_ID_HEADER, id.parse().unwrap());
        }
        c
    }

    #[test]
    fn a_request_without_a_session_id_is_not_tracked() {
        let n = CatalogNotifier::new();
        n.track(&ctx(None, Arc::default()));
        n.track(&ctx(Some(""), Arc::default()));
        assert_eq!(n.tracked_sessions(), 0);
    }

    #[test]
    fn tracking_is_deduplicated_per_session() {
        let n = CatalogNotifier::new();
        let s = Arc::new(FakeSession::default());
        n.track(&ctx(Some("abc"), s.clone()));
        n.track(&ctx(Some("abc"), s));
        assert_eq!(n.tracked_sessions(), 1);
    }

    #[test]
    fn forget_drops_a_session() {
        let n = CatalogNotifier::new();
        n.track(&ctx(Some("abc"), Arc::default()));
        n.forget("abc");
        n.forget("never-seen");
        assert_eq!(n.tracked_sessions(), 0);
    }

    #[test]
    fn the_tracked_map_is_bounded_and_evicts_least_recent() {
        let n = CatalogNotifier::new();
        for i in 0..MAX_TRACKED_SESSIONS + 10 {
            n.track(&ctx(Some(&format!("s{i}")), Arc::default()));
        }
        assert_eq!(n.tracked_sessions(), MAX_TRACKED_SESSIONS);
        assert!(!n.is_tracked("s0"));
        assert!(n.is_tracked(&format!("s{}", MAX_TRACKED_SESSIONS + 9)));

        // Activity moves a session to the front, so it survives eviction.
        let n = CatalogNotifier::new();
        n.track(&ctx(Some("old"), Arc::default()));
        for i in 0..MAX_TRACKED_SESSIONS - 1 {
            n.track(&ctx(Some(&format!("s{i}")), Arc::default()));
        }
        n.track(&ctx(Some("old"), Arc::default()));
        n.track(&ctx(Some("new"), Arc::default()));
        assert!(n.is_tracked("old"));
        assert!(!n.is_tracked("s0"));
    }

    #[tokio::test]
    async fn broadcast_reaches_every_session_and_drops_broken_ones() {
        let n = CatalogNotifier::new();
        let a = Arc::new(FakeSession::default());
        let b = Arc::new(FakeSession::default());
        let broken = Arc::new(FakeSession { broken: true, ..Default::default() });
        n.track(&ctx(Some("a"), a.clone()));
        n.track(&ctx(Some("b"), b.clone()));
        n.track(&ctx(Some("x"), broken));
        n.broadcast().await;
        assert_eq!(a.sent.load(Ordering::SeqCst), 1);
        assert_eq!(b.sent.load(Ordering::SeqCst), 1);
        assert_eq!(n.tracked_sessions(), 2);
    }

    #[test]
    fn a_change_before_binding_is_not_an_error() {
        let n = CatalogNotifier::new();
        let s = Arc::new(FakeSession::default());
        n.track(&ctx(Some("a"), s.clone()));
        n.tool_catalog_changed();
        assert_eq!(s.sent.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_change_is_delivered_once_bound() {
        let n = CatalogNotifier::new();
        n.bind_current();
        let s = Arc::new(FakeSession::default());
        n.track(&ctx(Some("a"), s.clone()));
        n.tool_catalog_changed();
        for _ in 0..100 {
            if s.sent.load(Ordering::SeqCst) == 1 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("notification not delivered");
    }

    #[tokio::test]
    async fn listen_acks_then_streams_filtered_events_then_closes() {
        let n = CatalogNotifier::new();
        let (tx, mut rx) = mpsc::channel(16);
        let sink: Sink = Some(tx);
        let filter = serde_json::json!({"toolsListChanged": true, "promptsListChanged": false, "resourceSubscriptions": []});
        let n2 = n.clone();
        let task = tokio::spawn(async move { n2.listen(Some(&Value::from(40)), &filter, &sink).await });
        let ack = rx.recv().await.unwrap();
        assert_eq!(
            ack,
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
                               "params": {"_meta": {"io.modelcontextprotocol/subscriptionId": 40},
                                          "notifications": {"toolsListChanged": true}}})
        );
        n.publish(ServerEvent::PromptsListChanged);
        n.publish(ServerEvent::ToolsListChanged);
        let event = rx.recv().await.unwrap();
        assert_eq!(
            event,
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed",
                               "params": {"_meta": {"io.modelcontextprotocol/subscriptionId": 40}}})
        );
        assert_eq!(n.listen_streams(), 1);
        n.close_listen_streams();
        let result = task.await.unwrap().unwrap();
        assert_eq!(
            result,
            serde_json::json!({"_meta": {"io.modelcontextprotocol/subscriptionId": 40}, "resultType": "complete"})
        );
        assert_eq!(n.listen_streams(), 0);
    }

    #[tokio::test]
    async fn listen_needs_a_request_id() {
        let n = CatalogNotifier::new();
        let err = n.listen(None, &serde_json::json!({}), &None).await.unwrap_err();
        assert_eq!(err, McpError::rpc(INVALID_REQUEST, "subscriptions/listen requires a request id"));
    }
}
