//! The `ssh` executor (port of `execute_ssh.py`; REQUIREMENTS.md §17).
//!
//! A tool on an `ssh` toolkit is shaped exactly like a `docker`/`local`
//! one -- `validate::build_argv` already builds and Tier-1-checks its argv,
//! so this module's only job is to run that same resolved argv on a remote
//! host instead of a local subprocess.
//!
//! SSH's exec channel (RFC 4254 §6.5) sends the server a single command
//! *string*, which the server hands to the remote user's login shell. So
//! unlike every other executor, this one runs through a shell, structurally
//! -- the mitigation is that each argv element is quoted exactly as Python's
//! `shlex.quote` does ([`shlex_quote`]) before being joined into that string.
//!
//! Host-key verification is mandatory, not optional: the pinned
//! `ssh_known_hosts` text is the only source of trust ([`KnownHosts`], a
//! port of asyncssh's matching), and a key it does not list is refused.
//!
//! PORT NOTE: Python used asyncssh; the port uses russh. Kept from asyncssh:
//! the known_hosts matching rules (plain, wildcard, negated, CIDR and hashed
//! `|1|` patterns, `[host]:port` entries with the fallback to the bare host,
//! `@revoked`), restricting the negotiated host key algorithms to those of
//! the pinned keys, an initial `none` auth request followed by exactly one
//! method (password, or the one private key -- never a key from `~/.ssh`),
//! and the error texts (`Host key is not trusted for host ...`, `Permission
//! denied for user ... on host ...`). Not available in russh and therefore
//! failing closed: `@cert-authority` entries (a host certificate is never
//! accepted through a CA line) and X.509 entries are ignored.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use russh::client;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelMsg, Disconnect, Preferred};

use super::http::{asyncio_connect, fmt_seconds, seconds};
use super::{elapsed_ms, ExecResult, Redact, OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN};
use crate::catalog::ToolDef;
use crate::credentials::{CredentialStore, ResolvedCredential};
use crate::errors::{ConfigError, DenialReason, Denied};
use crate::pyfmt::repr_str;
use crate::tier1::{ip_network, Toolkit};

// -- shlex ------------------------------------------------------------------

/// Python's `shlex.quote`.
pub fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    if s.chars().all(safe) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// Python's `shlex.split(s)` (POSIX mode, no comments, whitespace split).
/// The error is the `ValueError` text: `No closing quotation` or `No
/// escaped character`.
pub fn shlex_split(s: &str) -> Result<Vec<String>, String> {
    const WS: &[char] = &[' ', '\t', '\r', '\n'];
    let chars: Vec<char> = s.chars().collect();
    let mut pos = 0;
    let mut out = Vec::new();
    loop {
        // One `read_token` call.
        let mut state: Option<char> = Some(' ');
        let mut token = String::new();
        let mut quoted = false;
        let mut escapedstate = ' ';
        loop {
            let next = chars.get(pos).copied();
            pos += 1;
            match state {
                None => break,
                Some(' ') => match next {
                    None => {
                        state = None;
                        break;
                    }
                    Some(c) if WS.contains(&c) => {
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some('\\') => {
                        escapedstate = 'a';
                        state = Some('\\');
                    }
                    Some(c) if c == '\'' || c == '"' => state = Some(c),
                    Some(c) => {
                        token.push(c);
                        state = Some('a');
                    }
                },
                Some(q) if q == '\'' || q == '"' => {
                    quoted = true;
                    match next {
                        None => return Err("No closing quotation".into()),
                        Some(c) if c == q => state = Some('a'),
                        Some('\\') if q == '"' => {
                            escapedstate = q;
                            state = Some('\\');
                        }
                        Some(c) => token.push(c),
                    }
                }
                Some('\\') => {
                    let Some(c) = next else { return Err("No escaped character".into()) };
                    if (escapedstate == '\'' || escapedstate == '"') && c != '\\' && c != escapedstate {
                        token.push('\\');
                    }
                    token.push(c);
                    state = Some(escapedstate);
                }
                Some(_) => match next {
                    // state 'a'
                    None => {
                        state = None;
                        break;
                    }
                    Some(c) if WS.contains(&c) => {
                        state = Some(' ');
                        if !token.is_empty() || quoted {
                            break;
                        }
                    }
                    Some(c) if c == '\'' || c == '"' => state = Some(c),
                    Some('\\') => {
                        escapedstate = 'a';
                        state = Some('\\');
                    }
                    Some(c) => token.push(c),
                },
            }
        }
        if !quoted && token.is_empty() {
            if state.is_none() {
                return Ok(out);
            }
            continue;
        }
        out.push(token);
        if state.is_none() && pos > chars.len() {
            return Ok(out);
        }
    }
}

/// Python's `str.split(None, maxsplit)`.
fn py_split_ws(s: &str, maxsplit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s.trim_start_matches(py_isspace);
    while !rest.is_empty() {
        if out.len() == maxsplit {
            out.push(rest.to_string());
            break;
        }
        match rest.find(py_isspace) {
            Some(i) => {
                out.push(rest[..i].to_string());
                rest = rest[i..].trim_start_matches(py_isspace);
            }
            None => {
                out.push(rest.to_string());
                break;
            }
        }
    }
    out
}

/// Python's `str.isspace()` for `strip()`.
fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// An `{args}` element is a shell-like token string, not one token.
///
/// A template element that is *only* `{args}` is split with `shlex.split`
/// semantics (an empty/blank value contributes no element at all); every
/// other element stays one literal token. Only applies to a `build_argv`
/// product (`[binary, *one element per template]`).
pub fn split_args_elements(argv: &[String], tool: Option<&ToolDef>) -> Result<Vec<String>, Denied> {
    let templates: &[String] = tool.map(|t| t.argv.as_slice()).unwrap_or(&[]);
    if argv.len() != templates.len() + 1 {
        return Ok(argv.to_vec());
    }
    let mut out = vec![argv[0].clone()];
    for (template, element) in templates.iter().zip(&argv[1..]) {
        if template != "{args}" {
            out.push(element.clone());
            continue;
        }
        let tokens = if !element.is_empty() && !element.trim_matches(py_isspace).is_empty() {
            shlex_split(element).map_err(|exc| {
                Denied::new(
                    DenialReason::ParamInvalid,
                    format!("args {} is not a parseable argument string: {exc}", repr_str(element)),
                )
            })?
        } else {
            Vec::new()
        };
        out.extend(tokens);
    }
    Ok(out)
}

/// The remote command string: every element `shlex.quote`d, and the
/// `ssh_dispatch` wrap when the tool asks for it.
pub fn build_command(argv: &[String], ssh_dispatch: bool) -> String {
    let command = argv.iter().map(|p| shlex_quote(p)).collect::<Vec<_>>().join(" ");
    if !ssh_dispatch {
        return command;
    }
    // setsid, not bare nohup: a new session detaches the dispatched process
    // from the sshd session's process group; the inner `nohup sh -c`
    // re-applies SIGHUP immunity; `--wait` health-gates the beacon.
    if argv.iter().any(|part| part == "compose") {
        let beacon = shlex_quote(&format!("{command} --wait"))
            + " </dev/null >>/tmp/gatekeeper-recreate.log 2>&1; echo EXIT=$? >>/tmp/gatekeeper-recreate.log";
        format!("setsid nohup sh -c {} & echo dispatched", shlex_quote(&format!("nohup sh -c {}", shlex_quote(&beacon))))
    } else {
        format!("setsid nohup {command} </dev/null >>/tmp/gatekeeper-dispatch.log 2>&1 & echo dispatched")
    }
}

// -- known_hosts ------------------------------------------------------------

/// One `*`/`?` wildcard or CIDR pattern of a host pattern list.
#[derive(Debug, Clone)]
enum HostPattern {
    Cidr(ipnet::IpNet),
    Wildcard(String),
}

impl HostPattern {
    fn build(pattern: &str) -> HostPattern {
        match ip_network(pattern) {
            Ok(net) => HostPattern::Cidr(net),
            Err(_) => HostPattern::Wildcard(pattern.to_string()),
        }
    }

    fn matches(&self, host: &str, addr: &str, ip: Option<std::net::IpAddr>) -> bool {
        match self {
            HostPattern::Cidr(net) => ip.is_some_and(|ip| net.contains(&ip)),
            HostPattern::Wildcard(p) => {
                (!host.is_empty() && wildcard_match(p, host)) || (!addr.is_empty() && wildcard_match(p, addr))
            }
        }
    }
}

/// fnmatch with only `*` and `?` special (asyncssh escapes brackets).
fn wildcard_match(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    let (mut pi, mut vi) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while vi < v.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = vi;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            vi = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[derive(Debug, Clone)]
enum HostMatcher {
    Exact(Vec<String>),
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
    Patterns { pos: Vec<HostPattern>, neg: Vec<HostPattern> },
}

#[derive(Debug, Clone)]
struct KnownHostEntry {
    matcher: HostMatcher,
    marker: Option<String>,
    key: KeyData,
}

/// asyncssh's `SSHKnownHosts`: the pinned `known_hosts` text.
#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    entries: Vec<KnownHostEntry>,
}

/// What matched for one host: the keys to trust and the revoked ones.
#[derive(Debug, Clone, Default)]
pub struct HostKeys {
    pub trusted: Vec<KeyData>,
    pub revoked: Vec<KeyData>,
}

fn a2b_base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(cleaned.trim_end_matches('=')))
        .ok()
}

impl KnownHosts {
    /// `import_known_hosts(text)`; the error is asyncssh's `ValueError` text.
    pub fn parse(text: &str) -> Result<KnownHosts, String> {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim_matches(py_isspace);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (marker, pattern, data) = if let Some(rest) = line.strip_prefix('@') {
                let parts = py_split_ws(rest, 2);
                if parts.len() != 3 {
                    return Err(format!("Invalid known hosts entry: {line}"));
                }
                (Some(parts[0].clone()), parts[1].clone(), parts[2].clone())
            } else {
                let parts = py_split_ws(line, 1);
                if parts.len() != 2 {
                    return Err(format!("Invalid known hosts entry: {line}"));
                }
                (None, parts[0].clone(), parts[1].clone())
            };
            if let Some(m) = &marker {
                if m != "cert-authority" && m != "revoked" {
                    return Err(format!("Invalid known hosts marker: {m}"));
                }
            }
            // Keys that cannot be parsed are ignored, like asyncssh does.
            let Ok(key) = PublicKey::from_openssh(&data) else { continue };
            let matcher = if pattern.contains(['*', '?', '|', '/', '!']) {
                if let Some(rest) = pattern.strip_prefix('|') {
                    let parts: Vec<&str> = rest.split('|').collect();
                    if parts.len() != 3 {
                        return Err(format!("Invalid known hosts hash entry: {pattern}"));
                    }
                    let (Some(salt), Some(hash)) = (a2b_base64(parts[1]), a2b_base64(parts[2])) else {
                        return Err(format!("Invalid known hosts hash entry: {pattern}"));
                    };
                    if parts[0] != "1" {
                        return Err(format!("Invalid known hosts hash type: {}", parts[0]));
                    }
                    HostMatcher::Hashed { salt, hash }
                } else {
                    let mut pos = Vec::new();
                    let mut neg = Vec::new();
                    for part in pattern.split(',') {
                        match part.strip_prefix('!') {
                            Some(p) => neg.push(HostPattern::build(p)),
                            None => pos.push(HostPattern::build(part)),
                        }
                    }
                    HostMatcher::Patterns { pos, neg }
                }
            } else {
                HostMatcher::Exact(pattern.split(',').map(str::to_string).collect())
            };
            entries.push(KnownHostEntry { matcher, marker, key: key.key_data().clone() });
        }
        Ok(KnownHosts { entries })
    }

    fn match_once(&self, host: &str, addr: &str, port: Option<u16>) -> (HostKeys, bool) {
        let ip = if !addr.is_empty() {
            addr.split('%').next().and_then(|a| a.parse().ok())
        } else {
            host.parse().ok()
        };
        let (host, addr) = match port {
            Some(p) => (
                if host.is_empty() { String::new() } else { format!("[{host}]:{p}") },
                if addr.is_empty() { String::new() } else { format!("[{addr}]:{p}") },
            ),
            None => (host.to_string(), addr.to_string()),
        };
        let mut matched: Vec<&KnownHostEntry> = Vec::new();
        // Exact host entries, exact address entries, then patterns.
        for e in &self.entries {
            if let HostMatcher::Exact(names) = &e.matcher {
                if names.iter().any(|n| *n == host) {
                    matched.push(e);
                }
            }
        }
        for e in &self.entries {
            if let HostMatcher::Exact(names) = &e.matcher {
                if names.iter().any(|n| *n == addr) {
                    matched.push(e);
                }
            }
        }
        for e in &self.entries {
            let hit = match &e.matcher {
                HostMatcher::Exact(_) => false,
                HostMatcher::Hashed { salt, hash } => {
                    let check = |value: &str| {
                        let mut mac = <Hmac<sha1::Sha1> as Mac>::new_from_slice(salt).expect("any key length");
                        mac.update(value.as_bytes());
                        mac.finalize().into_bytes().as_slice() == hash.as_slice()
                    };
                    check(&host) || check(&addr)
                }
                HostMatcher::Patterns { pos, neg } => {
                    pos.iter().any(|p| p.matches(&host, &addr, ip)) && !neg.iter().any(|p| p.matches(&host, &addr, ip))
                }
            };
            if hit {
                matched.push(e);
            }
        }
        let mut keys = HostKeys::default();
        let mut any_ca = false;
        for e in matched {
            match e.marker.as_deref() {
                Some("revoked") => keys.revoked.push(e.key.clone()),
                // PORT NOTE: CA keys only vouch for host certificates,
                // which this port never accepts; they still count as a
                // match for the port fallback below, as in asyncssh.
                Some("cert-authority") => any_ca = true,
                _ => keys.trusted.push(e.key.clone()),
            }
        }
        (keys, any_ca)
    }

    /// asyncssh's `match(host, addr, port)`: with the port first (`port`
    /// is `None` for 22), then without it if nothing matched.
    pub fn host_keys(&self, host: &str, addr: &str, port: Option<u16>) -> HostKeys {
        let (keys, any_ca) = self.match_once(host, addr, port);
        if port.is_some() && keys.trusted.is_empty() && !any_ca {
            return self.match_once(host, addr, None).0;
        }
        keys
    }
}

/// Host key algorithms for the pinned keys, in pin order (asyncssh's
/// `_trusted_host_key_algs`); empty means russh's default list.
fn host_key_algorithms(keys: &[KeyData]) -> Vec<Algorithm> {
    let mut algs: Vec<Algorithm> = Vec::new();
    for key in keys {
        let candidates = match key.algorithm() {
            Algorithm::Rsa { .. } => vec![
                Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
                Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
                Algorithm::Rsa { hash: None },
            ],
            other => vec![other],
        };
        for alg in candidates {
            if Preferred::DEFAULT.key.contains(&alg) && !algs.contains(&alg) {
                algs.push(alg);
            }
        }
    }
    algs
}

// -- The client -------------------------------------------------------------

/// The auth material that leaves the process, decided from the credential
/// alone (asyncssh's `client_keys`/`password`/`preferred_auth`).
#[derive(Debug)]
pub enum AuthPlan {
    /// `ssh_password`: `preferred_auth=["password"]`, no client keys.
    Password(String),
    /// `ssh_private_key`: `preferred_auth=["publickey"]`, exactly this key.
    PublicKey(Box<PrivateKey>),
    /// No credential: `preferred_auth=["none"]`.
    None,
}

impl AuthPlan {
    pub fn preferred_auth(&self) -> &'static str {
        match self {
            AuthPlan::Password(_) => "password",
            AuthPlan::PublicKey(_) => "publickey",
            AuthPlan::None => "none",
        }
    }
}

/// `import_private_key(value)` for a key credential. No interactive
/// prompts exist in this process: an encrypted key fails here.
pub fn auth_plan(credential: Option<&ResolvedCredential>) -> Result<AuthPlan, String> {
    match credential {
        None => Ok(AuthPlan::None),
        Some(c) if c.kind == "ssh_password" => Ok(AuthPlan::Password(c.value.clone())),
        Some(c) => russh::keys::decode_secret_key(&c.value, None)
            .map(|k| AuthPlan::PublicKey(Box::new(k)))
            .map_err(|e| e.to_string()),
    }
}

struct Client {
    trusted: Vec<KeyData>,
    revoked: Vec<KeyData>,
    refusal: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error> {
        let key = server_public_key.key_data();
        if self.revoked.contains(key) {
            *self.refusal.lock() = Some("Host key is revoked".into());
            return Ok(false);
        }
        if !self.trusted.contains(key) {
            *self.refusal.lock() = Some("Host key is not trusted".into());
            return Ok(false);
        }
        Ok(true)
    }
}

enum ConnectError {
    HostKey(String),
    Other(String),
}

/// asyncssh's `connect()`: TCP, key exchange with pinned host keys, then
/// authentication with exactly the credential's material.
async fn connect(toolkit: &Toolkit, plan: AuthPlan, known_hosts: &KnownHosts) -> Result<client::Handle<Client>, ConnectError> {
    let host = toolkit.ssh_host.as_deref().expect("ssh toolkit without ssh_host");
    let port = u16::try_from(toolkit.ssh_port).unwrap_or(22);
    let user = toolkit.ssh_user.clone().unwrap_or_else(local_username);

    let stream = asyncio_connect(host, port).await.map_err(ConnectError::Other)?;
    let addr = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let keys = known_hosts.host_keys(host, &addr, if port == 22 { None } else { Some(port) });
    let algs = host_key_algorithms(&keys.trusted);
    let mut config = client::Config::default();
    if !algs.is_empty() {
        config.preferred = Preferred { key: algs.into(), ..Preferred::DEFAULT };
    }
    let refusal = Arc::new(Mutex::new(None));
    let handler = Client { trusted: keys.trusted, revoked: keys.revoked, refusal: refusal.clone() };
    let mut handle = match client::connect_stream(Arc::new(config), stream, handler).await {
        Ok(h) => h,
        Err(e) => {
            if let Some(reason) = refusal.lock().take() {
                return Err(ConnectError::HostKey(format!("{reason} for host {host}")));
            }
            return Err(ConnectError::Other(e.to_string()));
        }
    };

    let denied = || ConnectError::Other(format!("Permission denied for user {user} on host {host}"));
    let other = |e: russh::Error| ConnectError::Other(e.to_string());
    // The initial `none` request every SSH client starts with.
    if handle.authenticate_none(user.clone()).await.map_err(other)?.success() {
        return Ok(handle);
    }
    let ok = match plan {
        AuthPlan::None => false,
        AuthPlan::Password(password) => handle.authenticate_password(user.clone(), password).await.map_err(other)?.success(),
        AuthPlan::PublicKey(key) => {
            let hash = if key.algorithm().is_rsa() {
                handle.best_supported_rsa_hash().await.map_err(other)?.flatten()
            } else {
                None
            };
            handle
                .authenticate_publickey(user.clone(), PrivateKeyWithHashAlg::new(Arc::new(*key), hash))
                .await
                .map_err(other)?
                .success()
        }
    };
    if !ok {
        return Err(denied());
    }
    Ok(handle)
}

/// `getpass.getuser()`, asyncssh's default username.
fn local_username() -> String {
    for var in ["LOGNAME", "USER", "LNAME", "USERNAME"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if pw.is_null() {
            return String::new();
        }
        std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned()
    }
}

/// What `conn.run(command)` collected. Output is kept up to one byte past
/// the cap -- enough to know it was exceeded.
struct Completed {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<i64>,
}

async fn run_command(handle: &client::Handle<Client>, command: &str, keep: usize) -> Result<Completed, String> {
    let mut channel = handle.channel_open_session().await.map_err(|e| e.to_string())?;
    channel.exec(true, command.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut done = Completed { stdout: Vec::new(), stderr: Vec::new(), exit_status: None };
    let mut signalled = false;
    let push = |buf: &mut Vec<u8>, data: &[u8]| {
        let room = keep.saturating_sub(buf.len());
        buf.extend_from_slice(&data[..room.min(data.len())]);
    };
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => push(&mut done.stdout, &data),
            ChannelMsg::ExtendedData { data, ext } if ext == 1 => push(&mut done.stderr, &data),
            ChannelMsg::ExitStatus { exit_status } => done.exit_status = Some((exit_status & 0xff) as i64),
            ChannelMsg::ExitSignal { .. } => signalled = true,
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    if done.exit_status.is_none() && signalled {
        done.exit_status = Some(-1);
    }
    Ok(done)
}

/// Caps one output stream the way Python did (UTF-8 bytes, cut, decoded
/// with replacement). PORT NOTE: asyncssh decoded strictly and raised on
/// invalid UTF-8; the port replaces it.
fn cap(bytes: &[u8], max: usize) -> (String, bool) {
    if bytes.len() > max {
        (String::from_utf8_lossy(&bytes[..max]).into_owned(), true)
    } else {
        (String::from_utf8_lossy(bytes).into_owned(), false)
    }
}

/// One remote command.
///
/// `Err` only for a credential store that cannot be read or decrypted --
/// what escaped Python's `run()` as an exception.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    argv: &[String],
    toolkit: &Toolkit,
    credentials: Option<&CredentialStore>,
    timeout_seconds: f64,
    max_output_bytes: i64,
    idempotent: bool,
    redact: Option<&Redact>,
    tool: Option<&ToolDef>,
) -> Result<ExecResult, ConfigError> {
    let started = Instant::now();
    let denied = |denial: Denied| -> ExecResult {
        ExecResult::new(OUTCOME_FAILED, None, "", denial.agent_message(), false, elapsed_ms(started))
    };
    let failed = |msg: String| -> ExecResult {
        ExecResult::new(OUTCOME_FAILED, None, "", format!("SSH connection failed: {msg}"), false, elapsed_ms(started))
    };

    let mut credential: Option<ResolvedCredential> = None;
    if let Some(name) = toolkit.credential.as_deref().filter(|n| !n.is_empty()) {
        let Some(store) = credentials else {
            return Ok(denied(Denied::new(
                DenialReason::CredentialUnavailable,
                "No credential store is configured, but this toolkit needs one.",
            )));
        };
        credential = store.resolve(name)?;
        let Some(c) = &credential else {
            return Ok(denied(Denied::new(
                DenialReason::CredentialUnavailable,
                format!("Credential {} is not configured yet.", repr_str(name)),
            )));
        };
        if c.kind != "ssh_private_key" && c.kind != "ssh_password" {
            return Ok(denied(Denied::new(
                DenialReason::CredentialUnavailable,
                format!(
                    "Credential {} is not an ssh_private_key or ssh_password credential.",
                    repr_str(name)
                ),
            )));
        }
    }

    let argv = match split_args_elements(argv, tool) {
        Ok(a) => a,
        Err(denial) => return Ok(denied(denial)),
    };
    // The split can create argv elements Tier 1 never saw, so a denied flag
    // hidden inside `{args}` is caught here before anything is sent.
    if let Some(denied_arg) = toolkit.check_args(&argv) {
        return Ok(denied(Denied::new(
            DenialReason::Tier1Violation,
            format!("Argument {} is denied for this toolkit.", repr_str(&denied_arg)),
        )));
    }
    let command = build_command(&argv, tool.is_some_and(|t| t.ssh_dispatch));

    let timeout_result = || -> ExecResult {
        ExecResult::new(
            if idempotent { OUTCOME_FAILED } else { OUTCOME_UNKNOWN },
            None,
            "",
            if idempotent {
                format!("Timeout of {}s exceeded.", fmt_seconds(timeout_seconds))
            } else {
                format!(
                    "Timeout of {}s exceeded. The outcome is UNKNOWN: the command may have run on the remote host. Do not retry without checking the state first.",
                    fmt_seconds(timeout_seconds)
                )
            },
            false,
            elapsed_ms(started),
        )
    };

    // PORT NOTE: an unparseable private key or known_hosts text raised
    // ValueError out of Python's `run()`; here it is a failed connection.
    let plan = match auth_plan(credential.as_ref()) {
        Ok(p) => p,
        Err(exc) => return Ok(failed(exc)),
    };
    let known_hosts = match KnownHosts::parse(toolkit.ssh_known_hosts.as_deref().unwrap_or("")) {
        Ok(k) => k,
        Err(exc) => return Ok(failed(exc)),
    };

    let handle = match tokio::time::timeout(seconds(timeout_seconds), connect(toolkit, plan, &known_hosts)).await {
        Err(_) => return Ok(timeout_result()),
        Ok(Err(ConnectError::HostKey(exc))) => {
            return Ok(denied(Denied::new(
                DenialReason::SsrfBlocked,
                format!(
                    "Host key for {} did not match ssh_known_hosts -- refusing to connect (possible MITM): {exc}",
                    toolkit.ssh_host.as_deref().unwrap_or("")
                ),
            )))
        }
        Ok(Err(ConnectError::Other(exc))) => return Ok(failed(exc)),
        Ok(Ok(h)) => h,
    };

    let max = max_output_bytes.max(0) as usize;
    let ran = tokio::time::timeout(seconds(timeout_seconds), run_command(&handle, &command, max + 1)).await;
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        handle.disconnect(Disconnect::ByApplication, "", "English"),
    )
    .await;
    let done = match ran {
        Err(_) => return Ok(timeout_result()),
        Ok(Err(exc)) => return Ok(failed(exc)),
        Ok(Ok(done)) => done,
    };

    let (mut stdout, out_cut) = cap(&done.stdout, max);
    let (mut stderr, err_cut) = cap(&done.stderr, max);
    let truncated = out_cut || err_cut;
    if let Some(redact) = redact {
        stdout = redact(&stdout);
        stderr = redact(&stderr);
    }
    Ok(ExecResult::new(
        if done.exit_status == Some(0) { OUTCOME_OK } else { OUTCOME_FAILED },
        done.exit_status,
        stdout,
        stderr,
        truncated,
        elapsed_ms(started),
    ))
}

#[cfg(test)]
#[path = "ssh_tests.rs"]
mod tests;

/// TCP-connect only, for /health/ready -- no SSH handshake or auth.
pub async fn probe(toolkit: &Toolkit) -> bool {
    let host = toolkit.ssh_host.as_deref().expect("ssh toolkit without ssh_host");
    let Ok(port) = u16::try_from(toolkit.ssh_port) else { return false };
    matches!(tokio::time::timeout(Duration::from_secs(5), asyncio_connect(host, port)).await, Ok(Ok(_)))
}
