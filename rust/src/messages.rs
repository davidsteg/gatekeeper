//! The agent mailbox (`messages.yaml`) behind the `agent` executor (port of
//! `messages.py`).
//!
//! **Why a mailbox and not a push.** An MCP server cannot hand a running
//! client an unsolicited payload; the one notification a client like Hermes
//! acts on (`notifications/tools/list_changed`) carries nothing. So A's
//! message is persisted, addressed to a gatekeeper identity, and B receives
//! it the next time B calls `agent.read_messages`: delivery is "on B's next
//! call", but reliable, restart-proof and needs no client change.
//!
//! **The store is plaintext.** `messages.yaml` holds subject and body as
//! written. Known credential values are scrubbed on the way in by the
//! caller (`audit.Redactor`, FR-10.6); messages are for coordination, not
//! for handing over secrets.
//!
//! Written with the same atomic-write primitives as `pending.yaml` and
//! `tools.yaml` ([`crate::atomic`]): no half-written file, and the temp file
//! is created 0600, so the mailbox never exists world-readable.

use std::fmt;

use base64::Engine;
use parking_lot::Mutex;
use rand::RngCore;
use serde_json::{json, Map, Value};

use crate::atomic::{atomic_write, dump, safe_load};

/// `tier1.DEFAULT_MAILBOX_LIMIT`.
// PORT NOTE: stand-in until tier1 lands; tier1 should own this constant and
// this module should re-export / import it from there.
pub const DEFAULT_MAILBOX_LIMIT: usize = 200;

/// `catalog.now_iso()`: UTC, `%Y-%m-%dT%H:%M:%S%z`.
fn now_iso() -> String {
    crate::timeutil::now_utc_iso()
}

/// What can go wrong in the store. `MailboxFull` is Python's `MailboxFull`;
/// `Io` is an `OSError` (the executor reports it as "Mailbox is not
/// writable/readable: ..."); `Store` is any other `GatekeeperError` or a
/// file that does not parse.
#[derive(Debug)]
pub enum MessageError {
    /// The recipient holds as many unread messages as it may.
    ///
    /// Deliberately an error rather than a silent drop of the oldest unread
    /// one: an unread message is the only copy of something another agent
    /// meant to say. What gets pruned is read messages, never something
    /// nobody has seen.
    MailboxFull(String),
    /// An `OSError`, with the path for Python's `str(exc)` text.
    Io { error: std::io::Error, path: String },
    /// `GatekeeperError` (bad file shape) or a YAML / decode error.
    Store(String),
}

impl MessageError {
    pub fn is_mailbox_full(&self) -> bool {
        matches!(self, MessageError::MailboxFull(_))
    }
    pub fn is_os_error(&self) -> bool {
        matches!(self, MessageError::Io { .. })
    }
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageError::MailboxFull(m) | MessageError::Store(m) => f.write_str(m),
            MessageError::Io { error, path } => f.write_str(&crate::pyfmt::os_error(error, path)),
        }
    }
}

impl std::error::Error for MessageError {}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub id: String,
    /// The gatekeeper identity this is addressed to. `read_messages`
    /// filters on exactly this field (FR-1.4's per-identity isolation).
    pub to: String,
    /// The identity that sent it. Never a parameter: the service passes the
    /// *authenticated* identity. `from` on disk.
    pub sender: String,
    pub subject: String,
    pub body: String,
    pub created_at: String,
    /// The raw `read_at` value; `None` means unread (missing or null).
    pub read_at: Option<Value>,
}

impl Message {
    pub fn to_spec(&self) -> Value {
        json!({
            "id": self.id,
            "to": self.to,
            "from": self.sender,
            "subject": self.subject,
            "body": self.body,
            "created_at": self.created_at,
            "read_at": self.read_at.clone().unwrap_or(Value::Null),
        })
    }

    /// What the agent sees. Same shape minus the read bookkeeping.
    pub fn to_payload(&self) -> Value {
        json!({
            "id": self.id,
            "from": self.sender,
            "to": self.to,
            "subject": self.subject,
            "body": self.body,
            "created_at": self.created_at,
        })
    }

    fn is_unread(&self) -> bool {
        self.read_at.is_none()
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

/// `str(spec.get(key) or "")`.
fn field(spec: &Map<String, Value>, key: &str) -> String {
    match spec.get(key) {
        Some(v) if truthy(v) => crate::pyfmt::str_value(v),
        _ => String::new(),
    }
}

/// `entry.get("read_at")`, with `None` for missing or null.
fn read_at(spec: &Map<String, Value>) -> Option<Value> {
    match spec.get("read_at") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.clone()),
    }
}

fn from_spec(spec: &Map<String, Value>) -> Message {
    Message {
        id: field(spec, "id"),
        to: field(spec, "to"),
        sender: field(spec, "from"),
        subject: field(spec, "subject"),
        body: field(spec, "body"),
        created_at: field(spec, "created_at"),
        read_at: read_at(spec),
    }
}

/// `secrets.token_urlsafe(9)`.
fn token_urlsafe(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Owns one `messages.yaml`.
///
/// Reloads from disk on every operation instead of caching: the file is
/// small, the write path is the same lock, and a store that re-reads is the
/// one that survives a hand-edit and a restart identically.
#[derive(Debug)]
pub struct MessageStore {
    pub path: String,
    lock: Mutex<()>,
}

impl MessageStore {
    pub fn new(path: impl Into<String>) -> Self {
        MessageStore { path: path.into(), lock: Mutex::new(()) }
    }

    // -- Disk ---------------------------------------------------------------

    fn io(&self, error: std::io::Error) -> MessageError {
        MessageError::Io { error, path: self.path.clone() }
    }

    fn load(&self) -> Result<Vec<Map<String, Value>>, MessageError> {
        if !std::path::Path::new(&self.path).exists() {
            return Ok(Vec::new());
        }
        let bytes = std::fs::read(&self.path).map_err(|e| self.io(e))?;
        let text = String::from_utf8(bytes).map_err(|e| MessageError::Store(format!("{}: {e}", self.path)))?;
        let mut raw = safe_load(&text).map_err(|e| MessageError::Store(e.to_string()))?;
        if !truthy(&raw) {
            raw = Value::Object(Map::new());
        }
        let Value::Object(mut raw) = raw else {
            // PORT NOTE: Python raised AttributeError ("'list' object has no
            // attribute 'get'") on a non-mapping top level; this reports it
            // as a store error naming the file instead.
            return Err(MessageError::Store(format!("{}: top level must be a mapping", self.path)));
        };
        let entries = match raw.remove("messages") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items,
            Some(_) => {
                return Err(MessageError::Store(format!(
                    "{}: section 'messages' must be a list",
                    self.path
                )))
            }
        };
        Ok(entries
            .into_iter()
            .filter_map(|e| match e {
                Value::Object(m) => Some(m),
                _ => None,
            })
            .collect())
    }

    fn write(&self, entries: Vec<Map<String, Value>>) -> Result<(), MessageError> {
        let payload = json!({ "messages": entries.into_iter().map(Value::Object).collect::<Vec<_>>() });
        atomic_write(&self.path, &dump(&payload)).map_err(|e| self.io(e))
    }

    // -- Reads ----------------------------------------------------------------

    /// Every message addressed to `recipient`, oldest first.
    ///
    /// The filter is the isolation: a caller never sees an entry whose `to`
    /// is not its own identity. Ordering is `(created_at, position in the
    /// file)` -- `created_at` has second granularity, so the position keeps
    /// the mailbox FIFO for messages sent within the same second.
    pub fn inbox(&self, recipient: &str, unread_only: bool) -> Result<Vec<Message>, MessageError> {
        let mut items: Vec<(usize, Message)> = self
            .load()?
            .iter()
            .map(from_spec)
            .enumerate()
            .filter(|(_, m)| m.to == recipient)
            .collect();
        if unread_only {
            items.retain(|(_, m)| m.is_unread());
        }
        items.sort_by(|a, b| (&a.1.created_at, a.0).cmp(&(&b.1.created_at, b.0)));
        Ok(items.into_iter().map(|(_, m)| m).collect())
    }

    pub fn unread_count(&self, recipient: &str) -> Result<usize, MessageError> {
        Ok(self.inbox(recipient, true)?.len())
    }

    // -- Writes ---------------------------------------------------------------

    /// Appends one message to `to`'s mailbox.
    ///
    /// Refuses once `to` holds `max_messages` **unread** messages -- the cap
    /// is enforced by refusing the new one, not by discarding an old one.
    /// Already-read messages are pruned oldest-first to keep the
    /// recipient's total at the cap. Pass [`DEFAULT_MAILBOX_LIMIT`] for
    /// Python's default.
    pub fn deliver(
        &self,
        to: &str,
        sender: &str,
        subject: &str,
        body: &str,
        max_messages: usize,
    ) -> Result<Message, MessageError> {
        let _guard = self.lock.lock();
        let mut entries = self.load()?;
        let mine: Vec<(usize, Message)> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| field(e, "to") == to)
            .map(|(i, e)| (i, from_spec(e)))
            .collect();
        let unread = mine.iter().filter(|(_, m)| m.is_unread()).count();
        if unread >= max_messages {
            return Err(MessageError::MailboxFull(format!(
                "Mailbox of {} holds {unread} unread messages, the maximum is {max_messages}. \
                 It has to read them before it can receive more.",
                crate::pyfmt::repr_str(to)
            )));
        }

        let message = Message {
            id: format!("msg_{}", token_urlsafe(9)),
            to: to.to_string(),
            sender: sender.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
            created_at: now_iso(),
            read_at: None,
        };
        let Value::Object(spec) = message.to_spec() else { unreachable!() };
        entries.push(spec);

        // Prune read messages oldest-first until the recipient is back at
        // the cap. `mine` was collected before the append, so the new
        // message is never a pruning candidate.
        let overflow = (mine.len() + 1) as i64 - max_messages as i64;
        if overflow > 0 {
            let mut read: Vec<&(usize, Message)> = mine.iter().filter(|(_, m)| !m.is_unread()).collect();
            read.sort_by(|a, b| (&a.1.created_at, a.0).cmp(&(&b.1.created_at, b.0)));
            let drop: std::collections::HashSet<usize> =
                read.iter().take(overflow as usize).map(|(i, _)| *i).collect();
            entries = entries
                .into_iter()
                .enumerate()
                .filter(|(i, _)| !drop.contains(i))
                .map(|(_, e)| e)
                .collect();
        }

        self.write(entries)?;
        Ok(message)
    }

    /// Returns up to `limit` unread messages for `recipient` and, unless
    /// `peek`, marks exactly those read.
    ///
    /// `fits` is the output budget: the batch is shrunk from the end until
    /// it says yes (never below one message). Marking read follows the
    /// *returned* list, so a message trimmed for size stays unread. The
    /// count returned alongside is how many unread ones are still waiting.
    pub fn collect(
        &self,
        recipient: &str,
        limit: usize,
        peek: bool,
        fits: Option<&dyn Fn(&[Message]) -> bool>,
    ) -> Result<(Vec<Message>, usize), MessageError> {
        let _guard = self.lock.lock();
        let mut entries = self.load()?;
        let mut pending: Vec<(usize, Message)> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| field(e, "to") == recipient && read_at(e).is_none())
            .map(|(i, e)| (i, from_spec(e)))
            .collect();
        pending.sort_by(|a, b| (&a.1.created_at, a.0).cmp(&(&b.1.created_at, b.0)));
        let total = pending.len();
        let mut taken: Vec<(usize, Message)> = pending.into_iter().take(limit).collect();
        if let Some(fits) = fits {
            // Never shrink below one message: a single message that blows
            // the budget on its own is the executor's to truncate and
            // report, not the store's to withhold forever.
            while taken.len() > 1 {
                let batch: Vec<Message> = taken.iter().map(|(_, m)| m.clone()).collect();
                if fits(&batch) {
                    break;
                }
                taken.pop();
            }
        }
        let remaining = total - taken.len();
        if !taken.is_empty() && !peek {
            let stamp = now_iso();
            for (index, _) in &taken {
                entries[*index].insert("read_at".into(), Value::String(stamp.clone()));
            }
            self.write(entries)?;
        }
        Ok((taken.into_iter().map(|(_, m)| m).collect(), remaining))
    }

    /// How many unread messages are waiting for `recipient`.
    ///
    /// Read-only in the strict sense: nothing is marked read, nothing is
    /// written. Under the lock anyway, so the load and the count are one
    /// snapshot.
    pub fn count_unread(&self, recipient: &str) -> Result<usize, MessageError> {
        let _guard = self.lock.lock();
        Ok(self
            .load()?
            .iter()
            .filter(|e| field(e, "to") == recipient && read_at(e).is_none())
            .count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, MessageStore) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.yaml");
        let s = MessageStore::new(path.to_str().unwrap());
        (dir, s)
    }

    fn send(s: &MessageStore, to: &str, subject: &str, max: usize) -> Result<Message, MessageError> {
        s.deliver(to, "dev", subject, "b", max)
    }

    #[test]
    fn store_round_trip() {
        let (_d, s) = store();
        s.deliver("homelab", "dev", "hi", "restart done", DEFAULT_MAILBOX_LIMIT).unwrap();
        let (messages, remaining) = s.collect("homelab", 10, false, None).unwrap();
        assert_eq!(remaining, 0);
        assert_eq!(messages.iter().map(|m| m.subject.as_str()).collect::<Vec<_>>(), ["hi"]);
        assert_eq!(messages[0].sender, "dev");
        assert!(messages[0].id.starts_with("msg_") && messages[0].id.len() == 16);
    }

    #[test]
    fn store_survives_a_restart() {
        let (_d, s) = store();
        s.deliver("homelab", "dev", "s", "b", DEFAULT_MAILBOX_LIMIT).unwrap();
        let fresh = MessageStore::new(s.path.clone());
        let bodies: Vec<String> = fresh.inbox("homelab", true).unwrap().into_iter().map(|m| m.body).collect();
        assert_eq!(bodies, ["b"]);
    }

    #[test]
    fn store_isolates_recipients() {
        let (_d, s) = store();
        send(&s, "homelab", "for homelab", 200).unwrap();
        send(&s, "media", "for media", 200).unwrap();
        assert_eq!(s.inbox("homelab", true).unwrap()[0].subject, "for homelab");
        assert_eq!(s.inbox("homelab", true).unwrap().len(), 1);
        assert_eq!(s.inbox("media", true).unwrap()[0].subject, "for media");
        assert!(s.inbox("personal", true).unwrap().is_empty());
    }

    #[test]
    fn collect_marks_read_once() {
        let (_d, s) = store();
        send(&s, "homelab", "s", 200).unwrap();
        let (first, _) = s.collect("homelab", 10, false, None).unwrap();
        let (second, _) = s.collect("homelab", 10, false, None).unwrap();
        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
        // Read, not deleted: the record stays for the audit trail.
        assert_eq!(s.inbox("homelab", false).unwrap().len(), 1);
    }

    #[test]
    fn peek_leaves_messages_unread() {
        let (_d, s) = store();
        send(&s, "homelab", "s", 200).unwrap();
        let (peeked, _) = s.collect("homelab", 10, true, None).unwrap();
        assert_eq!(peeked.len(), 1);
        assert_eq!(s.unread_count("homelab").unwrap(), 1);
    }

    #[test]
    fn limit_reports_what_is_left() {
        let (_d, s) = store();
        for i in 0..5 {
            send(&s, "homelab", &format!("s{i}"), 200).unwrap();
        }
        let (taken, remaining) = s.collect("homelab", 2, false, None).unwrap();
        assert_eq!(taken.len(), 2);
        assert_eq!(remaining, 3);
        // FIFO within the same second: file position breaks the tie.
        assert_eq!(taken[0].subject, "s0");
        assert_eq!(taken[1].subject, "s1");
    }

    #[test]
    fn unread_messages_are_never_dropped_for_a_new_one() {
        let (_d, s) = store();
        for i in 0..3 {
            send(&s, "homelab", &format!("s{i}"), 3).unwrap();
        }
        let err = send(&s, "homelab", "overflow", 3).unwrap_err();
        assert!(err.is_mailbox_full());
        assert_eq!(
            err.to_string(),
            "Mailbox of 'homelab' holds 3 unread messages, the maximum is 3. It has to read them before it can receive more."
        );
        assert_eq!(s.unread_count("homelab").unwrap(), 3);
    }

    #[test]
    fn read_messages_are_pruned_to_make_room() {
        let (_d, s) = store();
        for i in 0..3 {
            send(&s, "homelab", &format!("s{i}"), 3).unwrap();
        }
        s.collect("homelab", 3, false, None).unwrap();
        send(&s, "homelab", "fresh", 3).unwrap();
        let kept = s.inbox("homelab", false).unwrap();
        assert_eq!(kept.len(), 3);
        assert_eq!(kept.last().unwrap().subject, "fresh");
        assert!(!kept.iter().any(|m| m.subject == "s0"));
    }

    #[test]
    fn a_full_mailbox_does_not_block_a_different_recipient() {
        let (_d, s) = store();
        send(&s, "homelab", "s", 1).unwrap();
        assert!(send(&s, "homelab", "s2", 1).unwrap_err().is_mailbox_full());
        send(&s, "media", "s", 1).unwrap();
        assert_eq!(s.unread_count("media").unwrap(), 1);
    }

    #[test]
    fn count_unread_is_per_recipient_and_skips_read() {
        let (_d, s) = store();
        send(&s, "homelab", "s1", 200).unwrap();
        send(&s, "homelab", "s2", 200).unwrap();
        send(&s, "media", "s3", 200).unwrap();
        assert_eq!(s.count_unread("homelab").unwrap(), 2);
        assert_eq!(s.count_unread("media").unwrap(), 1);
        assert_eq!(s.count_unread("personal").unwrap(), 0);
        s.collect("homelab", 1, false, None).unwrap();
        assert_eq!(s.count_unread("homelab").unwrap(), 1);
        s.collect("homelab", 1, false, None).unwrap();
        assert_eq!(s.count_unread("homelab").unwrap(), 0);
        assert_eq!(s.inbox("homelab", false).unwrap().len(), 2);
    }

    #[test]
    fn count_unread_does_not_write_the_file() {
        let (_d, s) = store();
        send(&s, "homelab", "s", 200).unwrap();
        let before = std::fs::read(&s.path).unwrap();
        s.count_unread("homelab").unwrap();
        assert_eq!(std::fs::read(&s.path).unwrap(), before);
    }

    #[test]
    fn fits_shrinks_the_batch_but_never_below_one() {
        let (_d, s) = store();
        for i in 0..4 {
            send(&s, "homelab", &format!("s{i}"), 200).unwrap();
        }
        let two: &dyn Fn(&[Message]) -> bool = &|batch| batch.len() <= 2;
        let (taken, remaining) = s.collect("homelab", 10, false, Some(two)).unwrap();
        assert_eq!(taken.len(), 2);
        assert_eq!(remaining, 2);
        // The trimmed ones stay unread.
        assert_eq!(s.count_unread("homelab").unwrap(), 2);
        let never: &dyn Fn(&[Message]) -> bool = &|_| false;
        let (taken, remaining) = s.collect("homelab", 10, true, Some(never)).unwrap();
        assert_eq!((taken.len(), remaining), (1, 1));
    }

    #[test]
    fn file_format_and_unknown_keys_survive() {
        let (_d, s) = store();
        std::fs::write(
            &s.path,
            "messages:\n- id: msg_x\n  to: homelab\n  from: dev\n  subject: old\n  body: b\n  created_at: '2020-01-01T00:00:00+0000'\n  read_at: null\n  extra: kept\n- not a mapping\n",
        )
        .unwrap();
        assert_eq!(s.inbox("homelab", true).unwrap()[0].subject, "old");
        s.collect("homelab", 10, false, None).unwrap();
        let reloaded = crate::yaml::load(&std::fs::read_to_string(&s.path).unwrap()).unwrap();
        let entries = reloaded["messages"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["extra"], "kept");
        assert!(entries[0]["read_at"].is_string());
        // The file carries the managed-file header.
        assert!(std::fs::read_to_string(&s.path).unwrap().starts_with(crate::atomic::HEADER));
    }

    #[test]
    fn messages_section_must_be_a_list() {
        let (_d, s) = store();
        std::fs::write(&s.path, "messages: {a: 1}\n").unwrap();
        let err = s.inbox("x", true).unwrap_err();
        assert_eq!(err.to_string(), format!("{}: section 'messages' must be a list", s.path));
        std::fs::write(&s.path, "").unwrap();
        assert!(s.inbox("x", true).unwrap().is_empty());
    }
}
