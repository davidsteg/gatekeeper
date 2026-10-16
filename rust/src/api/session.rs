//! Console sessions for the JSON API (port of `api/session.py`).
//!
//! One in-memory store, built once per console router: a password change
//! or an identity deletion that calls `drop_identity` signs that identity
//! out everywhere, and there is exactly one place that decides what a
//! session is. The session never applies to `/mcp` or `/admin/mcp` -- the
//! bearer middleware does not read cookies.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::identity::{token_urlsafe, ADMIN_ROLE};

pub const SESSION_COOKIE: &str = "gatekeeper_ui";
pub const SESSION_TTL_SECONDS: u64 = 8 * 3600;

/// One signed-in console user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub identity: String,
    pub role: String,
    pub csrf: String,
}

impl Session {
    pub fn can_write(&self) -> bool {
        self.role == ADMIN_ROLE
    }
}

/// Sessions in memory.
///
/// Deliberately not persisted: a restart signs out everyone. The loss is a
/// re-login, the gain is that a session token does not survive a restart
/// and never lands on disk.
#[derive(Debug)]
pub struct SessionStore {
    ttl: u64,
    sessions: Mutex<HashMap<String, (Session, Instant)>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        SessionStore::new(SESSION_TTL_SECONDS)
    }
}

impl SessionStore {
    pub fn new(ttl_seconds: u64) -> SessionStore {
        SessionStore { ttl: ttl_seconds, sessions: Mutex::new(HashMap::new()) }
    }

    /// Lifetime in seconds (the cookie's `Max-Age`).
    pub fn ttl(&self) -> u64 {
        self.ttl
    }

    pub fn create(&self, identity_id: &str, role: &str) -> String {
        let mut sessions = self.sessions.lock();
        prune(&mut sessions);
        let sid = token_urlsafe(32);
        let session = Session { identity: identity_id.to_string(), role: role.to_string(), csrf: token_urlsafe(24) };
        sessions.insert(sid.clone(), (session, Instant::now() + Duration::from_secs(self.ttl)));
        sid
    }

    pub fn resolve(&self, sid: Option<&str>) -> Option<Session> {
        let sid = sid.filter(|s| !s.is_empty())?;
        let mut sessions = self.sessions.lock();
        let (session, expires) = sessions.get(sid)?.clone();
        if Instant::now() >= expires {
            sessions.remove(sid);
            return None;
        }
        Some(session)
    }

    pub fn destroy(&self, sid: Option<&str>) {
        if let Some(sid) = sid.filter(|s| !s.is_empty()) {
            self.sessions.lock().remove(sid);
        }
    }

    /// Signs out all sessions of an identity, except `keep` -- the session
    /// that initiated the change itself.
    pub fn drop_identity(&self, identity_id: &str, keep: Option<&str>) {
        self.sessions
            .lock()
            .retain(|sid, (session, _)| session.identity != identity_id || Some(sid.as_str()) == keep);
    }

    /// Number of live entries (tests).
    pub fn len(&self) -> usize {
        self.sessions.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn prune(sessions: &mut HashMap<String, (Session, Instant)>) {
    let now = Instant::now();
    sessions.retain(|_, (_, expires)| now < *expires);
}

/// Thwarts rate attacks against the login: a hard limit of failures per
/// source address within a window.
#[derive(Debug)]
pub struct LoginThrottle {
    pub max_failures: usize,
    pub window_seconds: u64,
    failures: Mutex<HashMap<String, Vec<Instant>>>,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        LoginThrottle::new(10, 300)
    }
}

impl LoginThrottle {
    pub fn new(max_failures: usize, window_seconds: u64) -> LoginThrottle {
        LoginThrottle { max_failures, window_seconds, failures: Mutex::new(HashMap::new()) }
    }

    pub fn blocked(&self, client: &str) -> bool {
        let mut failures = self.failures.lock();
        self.recent(&mut failures, client).len() >= self.max_failures
    }

    pub fn record_failure(&self, client: &str) {
        let mut failures = self.failures.lock();
        self.recent(&mut failures, client).push(Instant::now());
    }

    pub fn reset(&self, client: &str) {
        self.failures.lock().remove(client);
    }

    fn recent<'a>(&self, failures: &'a mut HashMap<String, Vec<Instant>>, client: &str) -> &'a mut Vec<Instant> {
        let cutoff = Instant::now().checked_sub(Duration::from_secs(self.window_seconds));
        let entry = failures.entry(client.to_string()).or_default();
        if let Some(cutoff) = cutoff {
            entry.retain(|t| *t >= cutoff);
        }
        entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_expire() {
        let store = SessionStore::new(0);
        let sid = store.create("root", "admin");
        assert!(store.resolve(Some(&sid)).is_none());
    }

    #[test]
    fn session_ids_are_unguessable() {
        let store = SessionStore::default();
        let ids: std::collections::HashSet<String> = (0..50).map(|_| store.create("root", "admin")).collect();
        assert_eq!(ids.len(), 50);
        assert!(ids.iter().all(|i| i.len() >= 40));
    }

    #[test]
    fn each_session_gets_its_own_csrf_token() {
        let store = SessionStore::default();
        let first = store.resolve(Some(&store.create("root", "admin"))).unwrap();
        let second = store.resolve(Some(&store.create("root", "admin"))).unwrap();
        assert_ne!(first.csrf, second.csrf);
        assert!(first.csrf.len() >= 24);
    }

    #[test]
    fn only_admin_may_write() {
        let store = SessionStore::default();
        assert!(store.resolve(Some(&store.create("root", "admin"))).unwrap().can_write());
        assert!(!store.resolve(Some(&store.create("eye", "viewer"))).unwrap().can_write());
    }

    #[test]
    fn dropping_an_identity_ends_only_its_sessions() {
        let store = SessionStore::default();
        let doomed = store.create("gone", "admin");
        let other = store.create("stays", "admin");
        store.drop_identity("gone", None);
        assert!(store.resolve(Some(&doomed)).is_none());
        assert!(store.resolve(Some(&other)).is_some());
    }

    #[test]
    fn drop_identity_keeps_the_initiating_session() {
        let store = SessionStore::default();
        let mine = store.create("eye", "viewer");
        let other = store.create("eye", "viewer");
        store.drop_identity("eye", Some(&mine));
        assert!(store.resolve(Some(&mine)).is_some());
        assert!(store.resolve(Some(&other)).is_none());
        assert!(store.resolve(None).is_none());
        assert!(store.resolve(Some("")).is_none());
    }

    #[test]
    fn the_throttle_is_per_address_and_resets() {
        let throttle = LoginThrottle::new(3, 300);
        for _ in 0..3 {
            assert!(!throttle.blocked("10.0.0.1"));
            throttle.record_failure("10.0.0.1");
        }
        assert!(throttle.blocked("10.0.0.1"));
        assert!(!throttle.blocked("10.0.0.2"));
        throttle.reset("10.0.0.1");
        assert!(!throttle.blocked("10.0.0.1"));
    }
}
