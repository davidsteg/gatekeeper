//! OAuth sign-in for `oauth2` credentials (Google, Microsoft) -- port of
//! `oauth.py`, plus the token materialization of `service.py`'s
//! `_google_token_env` / `_microsoft_token_env` / `_oauth_token_env`.
//!
//! Framework-independent: the HTTP layer parses the request, calls
//! [`start_authorize`] (`POST /api/v1/oauth/<provider>/authorize`, after
//! its own session/admin/CSRF gates), [`providers_view`] (`GET
//! /api/v1/oauth/providers`) or [`callback`] (`GET
//! /ui/oauth/{google,microsoft}/callback`), and turns the result into a
//! response. Nothing here renders a page.
//!
//! The refresh token goes from the provider straight into the encrypted
//! credential store and is never rendered, logged or echoed back
//! (FR-10.2/10.7). The callback answers a 303 to `/app/credentials` with a
//! result code -- never a page, never anything the provider sent.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::audit::AuditLog;
use crate::credentials::CredentialStore;
use crate::errors::{ConfigError, DenialReason, Denied};
use crate::identity::token_urlsafe;
use crate::pyfmt::{repr_str, str_value};
use crate::tier1::Tier1;

pub const UI_PREFIX: &str = "/ui";

// -- Google OAuth sign-in -------------------------------------------------

/// Google's consent screen and token endpoint. Constants rather than
/// configuration: these are Google's, not a deployment's, and a
/// configurable token endpoint is a credential-exfiltration knob. (Tests
/// point [`TokenEndpoints`] at a loopback listener; nothing reads it from
/// a file or the environment.)
pub const GOOGLE_AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
/// Bare scope names in a toolkit's `required_scopes` are expanded with this.
pub const GOOGLE_SCOPE_PREFIX: &str = "https://www.googleapis.com/auth/";

pub const OAUTH_AUTHORIZE_PATH: &str = "/ui/oauth/google/authorize";
pub const OAUTH_CALLBACK_PATH: &str = "/ui/oauth/google/callback";

/// Overrides the base URL the callback `redirect_uri` is built from.
pub const BASE_URL_ENV: &str = "GATEKEEPER_BASE_URL";

/// What the consent screen asks for when no `google` toolkit declares
/// `required_scopes`.
pub const DEFAULT_GOOGLE_SCOPES: [&str; 10] = [
    "gmail.readonly",
    "gmail.send",
    "gmail.modify",
    "calendar.events",
    "calendar.events.readonly",
    "drive",
    "drive.file",
    "drive.metadata.readonly",
    "spreadsheets",
    "contacts",
];

/// Bounds on the `scope` field of a token response (both providers).
pub const MAX_GOOGLE_SCOPES: usize = 64;
pub const MAX_GOOGLE_SCOPE_CHARS: usize = 256;

// -- Microsoft OAuth sign-in ----------------------------------------------

pub const MICROSOFT_AUTHORITY: &str = "https://login.microsoftonline.com/common";
pub const MICROSOFT_AUTH_ENDPOINT: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
pub const MICROSOFT_TOKEN_ENDPOINT: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/token";
/// Bare scope names in a toolkit's `required_scopes` are expanded with this.
pub const MICROSOFT_SCOPE_PREFIX: &str = "https://graph.microsoft.com/";

/// The OIDC/OAuth scopes that are *not* Graph resources and must never be
/// prefixed.
pub const MICROSOFT_RESERVED_SCOPES: [&str; 4] = ["offline_access", "openid", "profile", "email"];

pub const MICROSOFT_OAUTH_AUTHORIZE_PATH: &str = "/ui/oauth/microsoft/authorize";
pub const MICROSOFT_OAUTH_CALLBACK_PATH: &str = "/ui/oauth/microsoft/callback";

/// What the consent screen asks for when no `microsoft` toolkit declares
/// `required_scopes`. Minimal on purpose.
pub const DEFAULT_MICROSOFT_SCOPES: [&str; 4] = ["Mail.Read", "Mail.Send", "User.Read", "offline_access"];

/// How long an issued `state` stays redeemable.
pub const OAUTH_STATE_TTL_SECONDS: u64 = 600;

// -- Flows in flight ------------------------------------------------------

/// What an issued `state` stands for: who started the flow, for which
/// credential, with which redirect URI, asking for which scopes, for which
/// provider, and (Microsoft) the PKCE verifier. All pinned at issue time.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthState {
    pub identity: String,
    pub credential: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub provider: String,
    /// Never leaves this process.
    pub code_verifier: String,
}

impl std::fmt::Debug for OAuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthState")
            .field("identity", &self.identity)
            .field("credential", &self.credential)
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field("provider", &self.provider)
            .field("code_verifier", &"***")
            .finish()
    }
}

/// The pending consent flows, in memory -- deliberately not persisted.
/// A state is 32 random bytes, handed out only to a signed-in admin,
/// usable exactly once, expiring after `ttl`.
#[derive(Debug)]
pub struct OAuthStateStore {
    ttl: Duration,
    states: Mutex<HashMap<String, (OAuthState, Instant)>>,
}

impl Default for OAuthStateStore {
    fn default() -> Self {
        OAuthStateStore::new()
    }
}

impl OAuthStateStore {
    pub fn new() -> Self {
        OAuthStateStore::with_ttl(Duration::from_secs(OAUTH_STATE_TTL_SECONDS))
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        OAuthStateStore { ttl, states: Mutex::new(HashMap::new()) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (OAuthState, Instant)>> {
        self.states.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `provider` defaults to "google" and `code_verifier` to "" in Python.
    pub fn issue(
        &self,
        identity: &str,
        credential: &str,
        redirect_uri: &str,
        scopes: &[String],
        provider: &str,
        code_verifier: &str,
    ) -> String {
        let mut states = self.lock();
        prune(&mut states);
        let state = token_urlsafe(32);
        states.insert(
            state.clone(),
            (
                OAuthState {
                    identity: identity.to_string(),
                    credential: credential.to_string(),
                    redirect_uri: redirect_uri.to_string(),
                    scopes: scopes.to_vec(),
                    provider: provider.to_string(),
                    code_verifier: code_verifier.to_string(),
                },
                Instant::now() + self.ttl,
            ),
        );
        state
    }

    /// Single use: a redeemed state is gone, a replay finds nothing.
    pub fn take(&self, state: Option<&str>) -> Option<OAuthState> {
        let mut states = self.lock();
        prune(&mut states);
        let state = state.filter(|s| !s.is_empty())?;
        let (pending, expires) = states.remove(state)?;
        if Instant::now() >= expires {
            return None;
        }
        Some(pending)
    }

    /// Number of flows in flight (tests).
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn prune(states: &mut HashMap<String, (OAuthState, Instant)>) {
    let now = Instant::now();
    states.retain(|_, (_, exp)| now < *exp);
}

// -- Scopes, URLs, PKCE ---------------------------------------------------

/// Python `str.strip()` whitespace (Rust's set plus U+001C..U+001F).
fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// Bare names become full scope URLs; full URLs are left alone.
pub fn google_scope_urls<S: AsRef<str>>(scopes: &[S]) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    for scope in scopes {
        let scope = py_strip(scope.as_ref());
        if scope.is_empty() {
            continue;
        }
        let url = if scope.contains("://") { scope.to_string() } else { format!("{GOOGLE_SCOPE_PREFIX}{scope}") };
        if !urls.contains(&url) {
            urls.push(url);
        }
    }
    urls
}

/// Bare names become Graph scope URLs; full URLs and the reserved
/// OAuth/OIDC scopes are left alone.
pub fn microsoft_scope_urls<S: AsRef<str>>(scopes: &[S]) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    for scope in scopes {
        let scope = py_strip(scope.as_ref());
        if scope.is_empty() {
            continue;
        }
        let url = if MICROSOFT_RESERVED_SCOPES.contains(&scope) || scope.contains("://") {
            scope.to_string()
        } else {
            format!("{MICROSOFT_SCOPE_PREFIX}{scope}")
        };
        if !urls.contains(&url) {
            urls.push(url);
        }
    }
    urls
}

/// The origin a browser reaches this console at, without trailing slash.
/// `GATEKEEPER_BASE_URL` wins when set; otherwise `request_base_url` (what
/// Starlette's `request.base_url` printed: scheme, host, root path, `/`).
pub fn public_base_url(request_base_url: &str) -> String {
    let configured = std::env::var(BASE_URL_ENV).unwrap_or_default();
    let configured = py_strip(&configured);
    if !configured.is_empty() {
        return configured.trim_end_matches('/').to_string();
    }
    request_base_url.trim_end_matches('/').to_string()
}

/// `urllib.parse.quote_plus(s, safe='')`.
pub fn quote_plus(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `urllib.parse.urlencode(pairs)` for string values.
pub fn urlencode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Google's consent screen URL for one flow. `access_type=offline` plus
/// `prompt=consent` is what makes Google return a *refresh* token.
pub fn google_consent_url(client_id: &str, redirect_uri: &str, scopes: &[String], state: &str) -> String {
    let scope = scopes.join(" ");
    let query = urlencode(&[
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", &scope),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("state", state),
    ]);
    format!("{GOOGLE_AUTH_ENDPOINT}?{query}")
}

/// Microsoft's consent screen URL for one flow, with a PKCE S256 challenge.
pub fn microsoft_consent_url(
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    code_challenge: &str,
) -> String {
    let scope = scopes.join(" ");
    let query = urlencode(&[
        ("client_id", client_id),
        ("response_type", "code"),
        ("redirect_uri", redirect_uri),
        ("response_mode", "query"),
        ("scope", &scope),
        ("state", state),
        ("prompt", "consent"),
        ("code_challenge", code_challenge),
        ("code_challenge_method", "S256"),
    ]);
    format!("{MICROSOFT_AUTH_ENDPOINT}?{query}")
}

/// A PKCE (verifier, S256 challenge) pair, RFC 7636 spelling: the verifier
/// is `token_urlsafe(48)` (64 characters), the challenge its SHA-256,
/// base64url, unpadded.
pub fn pkce_pair() -> (String, String) {
    let verifier = token_urlsafe(48);
    let challenge = pkce_challenge(&verifier);
    (verifier, challenge)
}

/// The S256 challenge of a verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

// -- The code exchange ----------------------------------------------------

/// A code exchange (or a client lookup) that did not produce a usable
/// answer. Carries a message safe to render: never the response body,
/// never a token, never the client secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthExchangeError(pub String);

impl std::fmt::Display for OAuthExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OAuthExchangeError {}

/// Where the code exchange is sent. Defaults to the providers' own
/// endpoints; only code (tests, with a loopback listener) sets anything
/// else -- it is deliberately not configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEndpoints {
    pub google: String,
    pub microsoft: String,
}

impl Default for TokenEndpoints {
    fn default() -> Self {
        TokenEndpoints {
            google: GOOGLE_TOKEN_ENDPOINT.to_string(),
            microsoft: MICROSOFT_TOKEN_ENDPOINT.to_string(),
        }
    }
}

/// Why an exchange failed. Both map to the `exchange_failed` result; the
/// split mirrors Python's `except (OAuthExchangeError, httpx.HTTPError)`.
#[derive(Debug)]
pub enum ExchangeError {
    Refused(OAuthExchangeError),
    /// Transport failure. The text is never rendered or audited.
    Transport(String),
}

async fn exchange_code(
    endpoint: &str,
    label: &str,
    form: &[(&str, &str)],
) -> Result<Map<String, Value>, ExchangeError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| ExchangeError::Transport(e.to_string()))?;
    let response = client
        .post(endpoint)
        .form(form)
        .send()
        .await
        .map_err(|e| ExchangeError::Transport(e.to_string()))?;
    let status = response.status().as_u16();
    if status >= 400 {
        // The body may quote the client_secret back -- the status is the
        // only part of it that may ever reach a page or the audit log.
        return Err(ExchangeError::Refused(OAuthExchangeError(format!(
            "{label} refused the code exchange (HTTP {status})."
        ))));
    }
    let body = response.bytes().await.map_err(|e| ExchangeError::Transport(e.to_string()))?;
    // Content-Type is not consulted, as with httpx's `.json()`.
    let payload: Value = serde_json::from_slice(&body).map_err(|_| {
        ExchangeError::Refused(OAuthExchangeError(format!("{label}'s token response was not JSON.")))
    })?;
    match payload {
        Value::Object(map) => Ok(map),
        _ => Err(ExchangeError::Refused(OAuthExchangeError(format!(
            "{label}'s token response was not an object."
        )))),
    }
}

/// Trades the authorization code for a refresh token (Google).
pub async fn exchange_google_code(
    endpoint: &str,
    code: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> Result<Map<String, Value>, ExchangeError> {
    exchange_code(
        endpoint,
        "Google",
        &[
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
        ],
    )
    .await
}

/// Trades the authorization code for a refresh token (Microsoft, PKCE).
pub async fn exchange_microsoft_code(
    endpoint: &str,
    code: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<Map<String, Value>, ExchangeError> {
    exchange_code(
        endpoint,
        "Microsoft",
        &[
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("grant_type", "authorization_code"),
            ("code_verifier", code_verifier),
        ],
    )
    .await
}

/// The `scope` field of a token response, read as the input it is: split
/// on whitespace, each entry bounded in length, the list bounded in count,
/// duplicates dropped, a non-string dropped whole. When nothing usable
/// comes back, `requested` stands in.
pub fn granted_scopes(payload: &Map<String, Value>, requested: &[String]) -> Vec<String> {
    let mut granted: Vec<String> = Vec::new();
    if let Some(Value::String(raw)) = payload.get("scope") {
        for scope in raw.split(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)) {
            if scope.is_empty() {
                continue;
            }
            if scope.chars().count() > MAX_GOOGLE_SCOPE_CHARS || granted.iter().any(|g| g == scope) {
                continue;
            }
            granted.push(scope.to_string());
            if granted.len() >= MAX_GOOGLE_SCOPES {
                break;
            }
        }
    }
    if !granted.is_empty() {
        return granted;
    }
    requested.to_vec()
}

/// The scopes a Google grant actually covers (see [`granted_scopes`]).
pub fn granted_google_scopes(payload: &Map<String, Value>, requested: &[String]) -> Vec<String> {
    granted_scopes(payload, requested)
}

/// [`granted_google_scopes`] for Microsoft, plus the reserved scopes the
/// consent screen asked for (`offline_access`, which Microsoft leaves out
/// of the response) added back.
pub fn granted_microsoft_scopes(payload: &Map<String, Value>, requested: &[String]) -> Vec<String> {
    let mut granted = granted_scopes(payload, requested);
    for scope in requested {
        if MICROSOFT_RESERVED_SCOPES.contains(&scope.as_str()) && !granted.contains(scope) {
            granted.push(scope.clone());
        }
    }
    granted
}

// -- Providers ------------------------------------------------------------

/// The parts of a sign-in flow that differ between providers. `key`
/// doubles as the executor name and the audit action prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthProviderSpec {
    pub key: &'static str,
    pub label: &'static str,
    pub authorize_path: &'static str,
    pub callback_path: &'static str,
    pub default_scopes: &'static [&'static str],
    pub registration_console: &'static str,
    pub mismatch_error: &'static str,
    pub revoke_hint: &'static str,
    pub uses_pkce: bool,
}

pub const GOOGLE_OAUTH: OAuthProviderSpec = OAuthProviderSpec {
    key: "google",
    label: "Google",
    authorize_path: OAUTH_AUTHORIZE_PATH,
    callback_path: OAUTH_CALLBACK_PATH,
    default_scopes: &DEFAULT_GOOGLE_SCOPES,
    registration_console: "Google Cloud console",
    mismatch_error: "redirect_uri_mismatch",
    revoke_hint: "third-party connections",
    uses_pkce: false,
};

pub const MICROSOFT_OAUTH: OAuthProviderSpec = OAuthProviderSpec {
    key: "microsoft",
    label: "Microsoft",
    authorize_path: MICROSOFT_OAUTH_AUTHORIZE_PATH,
    callback_path: MICROSOFT_OAUTH_CALLBACK_PATH,
    default_scopes: &DEFAULT_MICROSOFT_SCOPES,
    registration_console: "Azure portal (App registrations -> Authentication)",
    mismatch_error: "AADSTS50011",
    revoke_hint: "app permissions at microsoft.com/consent",
    uses_pkce: true,
};

/// `PROVIDERS`, in Python dict order.
pub const PROVIDERS: [&OAuthProviderSpec; 2] = [&GOOGLE_OAUTH, &MICROSOFT_OAUTH];

/// `PROVIDERS.get(key)`.
pub fn provider(key: &str) -> Option<&'static OAuthProviderSpec> {
    PROVIDERS.into_iter().find(|p| p.key == key)
}

/// The credential names this provider's toolkits point at (Tier 1), sorted.
pub fn oauth_credential_names(tier1: &Tier1, provider: &OAuthProviderSpec) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for toolkit in tier1.toolkits.values() {
        if toolkit.executor != provider.key {
            continue;
        }
        if let Some(cred) = toolkit.credential.as_deref().filter(|c| !c.is_empty()) {
            if !names.iter().any(|n| n == cred) {
                names.push(cred.to_string());
            }
        }
    }
    names.sort();
    names
}

/// The scopes the next consent screen asks for -- read at request time.
pub fn oauth_scopes(tier1: &Tier1, provider: &OAuthProviderSpec) -> Vec<String> {
    let declared =
        if provider.key == "microsoft" { tier1.microsoft_oauth_scopes() } else { tier1.google_oauth_scopes() };
    let source: Vec<String> = if declared.is_empty() {
        provider.default_scopes.iter().map(|s| s.to_string()).collect()
    } else {
        declared
    };
    if provider.key == "microsoft" {
        microsoft_scope_urls(&source)
    } else {
        google_scope_urls(&source)
    }
}

/// Why `oauth_client` gave no client pair.
#[derive(Debug)]
pub enum ClientError {
    /// The credential is missing or unusable; the message is safe to show.
    Unusable(OAuthExchangeError),
    /// The store itself failed (unreadable file, wrong master key). Python
    /// let this `ConfigError` escape: an HTTP 500.
    Store(ConfigError),
}

/// Python truthiness of a JSON value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
    }
}

/// client_id/client_secret out of the oauth2 credential -- the one read
/// of a credential value for sign-in. The id goes into the consent URL,
/// the secret into the token request body and nowhere else.
pub fn oauth_client(
    credentials: &CredentialStore,
    name: &str,
    provider: &OAuthProviderSpec,
) -> Result<(String, String), ClientError> {
    let unusable = |msg: String| ClientError::Unusable(OAuthExchangeError(msg));
    let resolved = credentials.resolve(name).map_err(ClientError::Store)?;
    let Some(resolved) = resolved else {
        return Err(unusable(format!(
            "Credential {} does not exist yet. Create it as kind oauth2 with the client_id and \
             client_secret of your {} OAuth client first -- this page only adds the refresh token.",
            repr_str(name),
            provider.label
        )));
    };
    if resolved.kind != "oauth2" {
        return Err(unusable(format!(
            "Credential {} is kind {}, not oauth2.",
            repr_str(name),
            repr_str(&resolved.kind)
        )));
    }
    let Ok(bundle) = serde_json::from_str::<Value>(&resolved.value) else {
        return Err(unusable(format!("Credential {} does not hold a JSON bundle.", repr_str(name))));
    };
    let client_id = bundle.as_object().and_then(|b| b.get("client_id"));
    let client_secret = bundle.as_object().and_then(|b| b.get("client_secret"));
    if !truthy(client_id) || !truthy(client_secret) {
        return Err(unusable(format!("Credential {} is missing client_id/client_secret.", repr_str(name))));
    }
    Ok((str_value(client_id.unwrap()), str_value(client_secret.unwrap())))
}

/// Where an `/app`-started flow lands.
pub const APP_RESULT_PATH: &str = "/app/credentials";

/// `/app/credentials?oauth=<result>&provider=<p>&credential=<c>`.
pub fn app_result_url(result: &str, provider: &str, credential: &str) -> String {
    let query = urlencode(&[("oauth", result), ("provider", provider), ("credential", credential)]);
    format!("{APP_RESULT_PATH}?{query}")
}

// -- The console API: providers listing and starting a flow ---------------

/// `models.OAuthProvider`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OAuthProviderView {
    pub key: String,
    pub label: String,
    pub credentials: Vec<String>,
    pub callback_path: String,
}

/// `GET /api/v1/oauth/providers`: providers some toolkit uses, with the
/// credentials it names (viewer session; gate is the HTTP layer's).
pub fn providers_view(tier1: &Tier1) -> Vec<OAuthProviderView> {
    let mut out = Vec::new();
    for spec in PROVIDERS {
        let names = oauth_credential_names(tier1, spec);
        if !names.is_empty() {
            out.push(OAuthProviderView {
                key: spec.key.to_string(),
                label: spec.label.to_string(),
                credentials: names,
                callback_path: spec.callback_path.to_string(),
            });
        }
    }
    out
}

/// `models.OAuthStart`: everything the connect page shows. No client
/// secret, no token, no verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OAuthStart {
    pub provider: String,
    pub label: String,
    pub credential: String,
    pub consent_url: String,
    pub callback_uri: String,
    pub scopes: Vec<String>,
    pub registration_console: String,
    pub mismatch_error: String,
}

/// Why starting a flow failed.
#[derive(Debug)]
pub enum StartError {
    /// An `ApiError(status, message)`.
    Api { status: u16, message: String },
    /// An exception Python let escape (HTTP 500): the store failed.
    Store(ConfigError),
    /// The audit record could not be written (HTTP 500).
    Audit(std::io::Error),
}

/// What [`start_authorize`] needs.
pub struct StartContext<'a> {
    pub tier1: &'a Tier1,
    pub audit: &'a AuditLog,
    pub credentials: Option<&'a CredentialStore>,
    pub states: Option<&'a OAuthStateStore>,
}

/// `POST /api/v1/oauth/{provider}/authorize`, after the HTTP layer's
/// session, `admin` and CSRF gates. `session_identity` is the signed-in
/// admin; `body_credential` the body's `credential` (may be empty);
/// `request_base_url` Starlette's `request.base_url`.
pub fn start_authorize(
    ctx: &StartContext<'_>,
    provider_key: &str,
    body_credential: &str,
    session_identity: &str,
    request_base_url: &str,
) -> Result<OAuthStart, StartError> {
    let api = |status: u16, message: String| StartError::Api { status, message };
    let Some(spec) = provider(provider_key) else {
        return Err(api(404, format!("No sign-in provider {}.", repr_str(provider_key))));
    };
    let (Some(credentials), Some(states)) = (ctx.credentials, ctx.states) else {
        return Err(api(409, "This console cannot write credentials (no credential store).".into()));
    };
    let mut name = py_strip(body_credential).to_string();
    let available = oauth_credential_names(ctx.tier1, spec);
    if name.is_empty() {
        if available.len() == 1 {
            name = available[0].clone();
        } else if available.is_empty() {
            return Err(api(
                400,
                format!(
                    "No {} toolkit in toolkits.yaml names a credential, so there is nothing to \
                     connect. Toolkits are deploy-time only (FR-4.11).",
                    spec.key
                ),
            ));
        } else {
            return Err(api(
                400,
                format!(
                    "Several {} toolkits name different credentials ({}); say which one to connect.",
                    spec.key,
                    available.join(", ")
                ),
            ));
        }
    }
    let client_id = match oauth_client(credentials, &name, spec) {
        Ok((client_id, _secret)) => client_id,
        Err(ClientError::Unusable(exc)) => return Err(api(400, exc.0)),
        Err(ClientError::Store(exc)) => return Err(StartError::Store(exc)),
    };
    let redirect_uri = format!("{}{}", public_base_url(request_base_url), spec.callback_path);
    let scopes = oauth_scopes(ctx.tier1, spec);
    let (verifier, challenge) = if spec.uses_pkce { pkce_pair() } else { (String::new(), String::new()) };
    let state = states.issue(session_identity, &name, &redirect_uri, &scopes, spec.key, &verifier);
    let consent_url = if spec.key == "microsoft" {
        microsoft_consent_url(&client_id, &redirect_uri, &scopes, &state, &challenge)
    } else {
        google_consent_url(&client_id, &redirect_uri, &scopes, &state)
    };
    // Names and scopes only -- no client id, no code, no token, no verifier.
    ctx.audit
        .write(serde_json::json!({
            "kind": "ui_oauth", "actor": session_identity,
            "action": format!("{}_authorize", spec.key), "credential": name,
            "scopes": scopes, "redirect_uri": redirect_uri, "surface": "api",
        }))
        .map_err(StartError::Audit)?;
    Ok(OAuthStart {
        provider: spec.key.to_string(),
        label: spec.label.to_string(),
        credential: name,
        consent_url,
        callback_uri: redirect_uri,
        scopes,
        registration_console: spec.registration_console.to_string(),
        mismatch_error: spec.mismatch_error.to_string(),
    })
}

// -- The callback (`/ui/oauth/{google,microsoft}/callback`) ---------------

/// The query parameters the callback reads, as Starlette's `query_params`
/// would give them (`parse_qsl(keep_blank_values=True)`, last value wins).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallbackQuery {
    pub state: Option<String>,
    pub code: Option<String>,
    pub error: Option<String>,
}

impl CallbackQuery {
    /// From the raw (still percent-encoded) query string.
    pub fn parse(raw_query: &str) -> CallbackQuery {
        let mut query = CallbackQuery::default();
        for (key, value) in url::form_urlencoded::parse(raw_query.as_bytes()) {
            match key.as_ref() {
                "state" => query.state = Some(value.into_owned()),
                "code" => query.code = Some(value.into_owned()),
                "error" => query.error = Some(value.into_owned()),
                _ => {}
            }
        }
        query
    }
}

/// What the callback answers: always `303 See Other` to `location`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackRedirect {
    pub status: u16,
    pub location: String,
}

/// An exception Python let escape from the callback (HTTP 500).
#[derive(Debug)]
pub enum CallbackError {
    Audit(std::io::Error),
    Store(ConfigError),
}

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallbackError::Audit(e) => write!(f, "{e}"),
            CallbackError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CallbackError {}

/// What [`callback`] needs (Python's `build_callback_routes` arguments).
pub struct CallbackContext<'a> {
    pub audit: &'a AuditLog,
    pub credentials: Option<&'a CredentialStore>,
    /// Whether a config store is present (`store is not None`); without
    /// one the console is read-only.
    pub has_config_store: bool,
    /// Is this identity, *now*, an `admin`? (`identities.identities.get(
    /// actor)` with `role == ADMIN_ROLE`.) A closure so the caller keeps
    /// its own locking; it is called before any await.
    pub is_admin: &'a (dyn Fn(&str) -> bool + Send + Sync),
    pub states: &'a OAuthStateStore,
    pub endpoints: &'a TokenEndpoints,
}

/// `GET /ui/oauth/<provider>/callback`. Every outcome is a 303 to
/// `/app/credentials` with a result code; `Err` only where Python raised.
pub async fn callback(
    ctx: &CallbackContext<'_>,
    provider: &OAuthProviderSpec,
    query: &CallbackQuery,
) -> Result<CallbackRedirect, CallbackError> {
    let action = format!("{}_callback", provider.key);
    let mut pending_state = ctx.states.take(Some(query.state.as_deref().unwrap_or("")));
    if pending_state.as_ref().is_some_and(|s| s.provider != provider.key) {
        // One state store, two flows: a state minted for the other
        // provider is spent here and redeems nothing.
        pending_state = None;
    }
    let Some(pending_state) = pending_state else {
        ctx.audit
            .write(serde_json::json!({
                "kind": "ui_oauth", "actor": "", "action": action, "result": "state_mismatch",
            }))
            .map_err(CallbackError::Audit)?;
        return Ok(CallbackRedirect { status: 303, location: app_result_url("state_mismatch", provider.key, "") });
    };

    let actor = pending_state.identity.as_str();
    let name = pending_state.credential.as_str();
    let fail = |result: &str, detail: &str| -> Result<CallbackRedirect, CallbackError> {
        let mut record = Map::new();
        record.insert("kind".into(), "ui_oauth".into());
        record.insert("actor".into(), actor.into());
        record.insert("action".into(), action.clone().into());
        record.insert("result".into(), result.into());
        record.insert("credential".into(), name.into());
        if !detail.is_empty() {
            record.insert("detail".into(), detail.into());
        }
        ctx.audit.write(Value::Object(record)).map_err(CallbackError::Audit)?;
        Ok(CallbackRedirect { status: 303, location: app_result_url(result, provider.key, name) })
    };

    // The state was issued to an admin; it could have been demoted or
    // deleted since.
    if !(ctx.is_admin)(actor) {
        return fail("role_required", "");
    }
    // The provider's own refusal, truncated: audit log only.
    let denial: String = py_strip(query.error.as_deref().unwrap_or("")).chars().take(64).collect();
    if !denial.is_empty() {
        return fail("denied", &denial);
    }
    let code = query.code.as_deref().unwrap_or("");
    if code.is_empty() {
        return fail("no_code", "");
    }
    let Some(credentials) = ctx.credentials.filter(|_| ctx.has_config_store) else {
        return fail("read_only", "");
    };
    let (client_id, client_secret) = match oauth_client(credentials, name, provider) {
        Ok(pair) => pair,
        Err(ClientError::Unusable(_)) => return fail("credential_unusable", ""),
        Err(ClientError::Store(exc)) => return Err(CallbackError::Store(exc)),
    };
    let exchanged = if provider.key == "microsoft" {
        exchange_microsoft_code(
            &ctx.endpoints.microsoft,
            code,
            &client_id,
            &client_secret,
            &pending_state.redirect_uri,
            &pending_state.code_verifier,
        )
        .await
    } else {
        exchange_google_code(&ctx.endpoints.google, code, &client_id, &client_secret, &pending_state.redirect_uri)
            .await
    };
    let Ok(payload) = exchanged else {
        return fail("exchange_failed", "");
    };

    let refresh_token = match payload.get("refresh_token") {
        Some(Value::String(t)) if !t.is_empty() => t.clone(),
        // Omitted when the client was already granted these scopes and
        // the request did not force a fresh consent.
        _ => return fail("no_refresh_token", ""),
    };

    // The grant's scopes travel with the refresh token.
    let scopes = if provider.key == "microsoft" {
        granted_microsoft_scopes(&payload, &pending_state.scopes)
    } else {
        granted_google_scopes(&payload, &pending_state.scopes)
    };
    let mut fields = Map::new();
    fields.insert("client_id".into(), client_id.into());
    fields.insert("client_secret".into(), client_secret.into());
    fields.insert("refresh_token".into(), refresh_token.into());
    fields.insert("scopes".into(), scopes.clone().into());
    // `provider` marks a non-Google bundle.
    if provider.key != "google" {
        fields.insert("provider".into(), provider.key.into());
    }
    let bundle = crate::pyjson::dumps(&Value::Object(fields));
    let existing = credentials.names(None).map_err(CallbackError::Store)?;
    let written = if existing.iter().any(|m| m.name == name) {
        credentials.rotate(name, &bundle, 0, actor, &credentials.revision())
    } else {
        credentials.create(name, "oauth2", &bundle, None, None, None, actor, &credentials.revision())
    };
    if written.is_err() {
        return fail("write_refused", "");
    }

    // Scope names only: no token material.
    ctx.audit
        .write(serde_json::json!({
            "kind": "ui_oauth", "actor": actor, "action": action,
            "result": "ok", "credential": name, "scopes": scopes,
        }))
        .map_err(CallbackError::Audit)?;
    Ok(CallbackRedirect { status: 303, location: app_result_url("ok", provider.key, name) })
}

// -- Token materialization for the executors (service.py) -----------------

/// The per-provider half of `_oauth_token_env`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenFileSpec {
    pub provider: &'static str,
    pub token_filename: &'static str,
    pub tmp_prefix: &'static str,
}

pub const GOOGLE_TOKEN_FILE: TokenFileSpec = TokenFileSpec {
    provider: "google",
    token_filename: "google_token.json",
    tmp_prefix: "gatekeeper-google-",
};

pub const MICROSOFT_TOKEN_FILE: TokenFileSpec = TokenFileSpec {
    provider: "microsoft",
    token_filename: "microsoft_token.json",
    tmp_prefix: "gatekeeper-microsoft-",
};

/// credential name -> materialized temp HOME. One per provider; the
/// service clears it on every credential change
/// (`invalidate_{google,microsoft}_token_cache`).
#[derive(Debug, Default)]
pub struct TokenDirCache {
    dirs: Mutex<HashMap<String, PathBuf>>,
}

impl TokenDirCache {
    pub fn new() -> Self {
        TokenDirCache::default()
    }

    /// Drops every cached directory, from disk too (`_drop_token_dirs`).
    pub fn invalidate(&self) {
        let stale: Vec<PathBuf> = {
            let mut dirs = self.dirs.lock().unwrap_or_else(|e| e.into_inner());
            dirs.drain().map(|(_, p)| p).collect()
        };
        for dir in stale {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn unavailable(detail: String) -> Denied {
    Denied::new(DenialReason::CredentialUnavailable, detail)
}

/// `_oauth_token_env`: materializes an `oauth2` credential to a private
/// temp HOME containing `.hermes/<token_filename>` (0600) and returns
/// `{"HOME": <dir>}` for the executor's subprocess.
pub fn oauth_token_env(
    credentials: Option<&CredentialStore>,
    cred_name: Option<&str>,
    spec: &TokenFileSpec,
    cache: &TokenDirCache,
) -> Result<HashMap<String, String>, Denied> {
    let provider = spec.provider;
    let Some(cred_name) = cred_name else {
        return Err(unavailable(format!("This {provider} toolkit needs a credential configured.")));
    };
    let home_env = |dir: &Path| HashMap::from([("HOME".to_string(), dir.to_string_lossy().into_owned())]);
    let mut dirs = cache.dirs.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cached) = dirs.get(cred_name) {
        return Ok(home_env(cached));
    }
    let Some(credentials) = credentials else {
        return Err(unavailable(format!(
            "No credential store is configured, but this {provider} toolkit needs one."
        )));
    };
    // PORT NOTE: Python let a store error (wrong master key, unreadable
    // file) escape `call()` as an exception; it is an audited denial here.
    let resolved = credentials.resolve(cred_name).map_err(|e| unavailable(e.message))?;
    let Some(resolved) = resolved else {
        return Err(unavailable(format!("Credential {} is not configured yet.", repr_str(cred_name))));
    };
    if resolved.kind != "oauth2" {
        return Err(unavailable(format!("Credential {} is not an oauth2 credential.", repr_str(cred_name))));
    }
    let Ok(bundle) = serde_json::from_str::<Value>(&resolved.value) else {
        return Err(unavailable(format!(
            "Credential {} is not a valid oauth2 JSON bundle.",
            repr_str(cred_name)
        )));
    };
    // PORT NOTE: a JSON bundle that is not an object made Python raise
    // AttributeError on `.get`; it reads as an empty bundle here (and so
    // is refused for missing fields below).
    let empty = Map::new();
    let bundle = bundle.as_object().unwrap_or(&empty);
    if let Some(Value::String(stored_provider)) = bundle.get("provider") {
        if stored_provider != provider {
            return Err(unavailable(format!(
                "Credential {} is a {stored_provider} OAuth credential, but this toolkit is {provider}. \
                 Connect the credential from the console's {provider} sign-in, or point the toolkit \
                 at a different credential.",
                repr_str(cred_name)
            )));
        }
    }
    let client_id = bundle.get("client_id");
    let client_secret = bundle.get("client_secret");
    let refresh_token = bundle.get("refresh_token");
    if !(truthy(client_id) && truthy(client_secret) && truthy(refresh_token)) {
        return Err(unavailable(format!(
            "Credential {} is missing client_id/client_secret/refresh_token.",
            repr_str(cred_name)
        )));
    }
    let mut token = Map::new();
    token.insert("client_id".into(), client_id.cloned().unwrap_or(Value::Null));
    token.insert("client_secret".into(), client_secret.cloned().unwrap_or(Value::Null));
    token.insert("refresh_token".into(), refresh_token.cloned().unwrap_or(Value::Null));
    // The grant's scopes travel with the refresh token; absent (or not a
    // non-empty list) they are left out rather than guessed at.
    if let Some(Value::Array(scopes)) = bundle.get("scopes") {
        if !scopes.is_empty() {
            token.insert(
                "scopes".into(),
                Value::Array(scopes.iter().map(|s| Value::String(str_value(s))).collect()),
            );
        }
    }
    // PORT NOTE: Python let an OSError here escape; it is a denial here.
    let tmp_home = materialize(spec, &crate::pyjson::dumps(&Value::Object(token)))
        .map_err(|e| unavailable(format!("The {provider} token could not be written: {e}")))?;
    let env = home_env(&tmp_home);
    dirs.insert(cred_name.to_string(), tmp_home);
    Ok(env)
}

fn materialize(spec: &TokenFileSpec, content: &str) -> std::io::Result<PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let tmp_home = tempfile::Builder::new().prefix(spec.tmp_prefix).tempdir()?.keep();
    std::fs::set_permissions(&tmp_home, std::fs::Permissions::from_mode(0o700))?;
    let hermes_dir = tmp_home.join(".hermes");
    std::fs::create_dir_all(&hermes_dir)?;
    // 0600 from the start: no window where the file is world-readable.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(hermes_dir.join(spec.token_filename))?;
    file.write_all(content.as_bytes())?;
    Ok(tmp_home)
}

/// `_google_token_env`.
pub fn google_token_env(
    credentials: Option<&CredentialStore>,
    cred_name: Option<&str>,
    cache: &TokenDirCache,
) -> Result<HashMap<String, String>, Denied> {
    oauth_token_env(credentials, cred_name, &GOOGLE_TOKEN_FILE, cache)
}

/// `_microsoft_token_env`.
pub fn microsoft_token_env(
    credentials: Option<&CredentialStore>,
    cred_name: Option<&str>,
    cache: &TokenDirCache,
) -> Result<HashMap<String, String>, Denied> {
    oauth_token_env(credentials, cred_name, &MICROSOFT_TOKEN_FILE, cache)
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const BASE: &str = "http://gatekeeper.test";
    const CLIENT_ID: &str = "1234.apps.googleusercontent.com";
    const CLIENT_SECRET: &str = "GOCSPX-test-client-secret-value";
    const OLD_REFRESH: &str = "1//old-refresh-token-value";
    const NEW_REFRESH: &str = "1//brand-new-refresh-token-value";
    const AUTH_CODE: &str = "4/authorization-code-value";
    const ACCESS_TOKEN: &str = "ya29.access-token-value";
    const SECRETS: [&str; 5] = [NEW_REFRESH, OLD_REFRESH, CLIENT_SECRET, AUTH_CODE, ACCESS_TOKEN];

    // -- A loopback token endpoint ----------------------------------------

    type Seen = Arc<Mutex<Vec<HashMap<String, String>>>>;

    /// One axum listener on 127.0.0.1 answering every POST with `status`
    /// and `body`, recording the form it got.
    struct FakeTokenEndpoint {
        url: String,
        seen: Seen,
    }

    async fn fake_endpoint(status: u16, body: &str) -> FakeTokenEndpoint {
        use axum::{extract::State, routing::post, Form, Router};
        let seen: Seen = Arc::default();
        let body = body.to_string();
        let handler = move |State(seen): State<Seen>, Form(form): Form<HashMap<String, String>>| {
            let body = body.clone();
            async move {
                seen.lock().unwrap().push(form);
                (
                    http::StatusCode::from_u16(status).unwrap(),
                    [("content-type", "application/json; charset=utf-8")],
                    body,
                )
            }
        };
        let app = Router::new().route("/token", post(handler)).with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        FakeTokenEndpoint { url: format!("http://{addr}/token"), seen }
    }

    /// An endpoint nothing listens on: the exchange must never get there,
    /// or fails as a transport error.
    fn never() -> String {
        "http://127.0.0.1:9/never".to_string()
    }

    // -- The environment ----------------------------------------------------

    struct Env {
        tier1: Tier1,
        audit: Arc<AuditLog>,
        credentials: CredentialStore,
        states: OAuthStateStore,
        admins: Arc<Mutex<Vec<String>>>,
        _dir: tempfile::TempDir,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    fn write_tier1(dir: &Path, executor: &str, credential: &str, required_scopes: Option<&[&str]>) -> Tier1 {
        let mut toolkit = serde_json::json!({
            "executor": executor,
            "credential": credential,
            "max_timeout_seconds": 30,
            "max_output_bytes": 65536,
        });
        let t = toolkit.as_object_mut().unwrap();
        if executor == "google" {
            t.insert("binaries".into(), serde_json::json!([]));
            t.insert("google_script".into(), "/opt/gatekeeper/google/google_api.py".into());
            t.insert("allowed_google_actions".into(), serde_json::json!(["gmail search", "calendar list"]));
        } else {
            t.insert("microsoft_script".into(), "/opt/gatekeeper/microsoft/microsoft_api.py".into());
            t.insert("allowed_microsoft_actions".into(), serde_json::json!(["mail list", "mail send"]));
        }
        if let Some(scopes) = required_scopes {
            t.insert("required_scopes".into(), serde_json::json!(scopes));
        }
        let mut toolkits = Map::new();
        toolkits.insert((if executor == "google" { "gmail" } else { "outlook" }).into(), toolkit);
        toolkits.insert(
            "demo".into(),
            serde_json::json!({
                "executor": "local", "binaries": ["/bin/sh"], "path_roots": [],
                "max_timeout_seconds": 30, "max_output_bytes": 8192,
            }),
        );
        let doc = serde_json::json!({
            "toolkits": toolkits,
            "audit": {"dir": dir.join("logs").to_str().unwrap()},
        });
        let path = dir.join("toolkits.yaml");
        std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
        crate::tier1::load_tier1(path.to_str().unwrap()).unwrap()
    }

    fn env_with(executor: &str, credential: &str, required_scopes: Option<&[&str]>) -> Env {
        let guard = crate::credentials::tests::env_lock();
        std::env::remove_var(crate::credentials::KEY_FILE_ENV);
        std::env::remove_var(BASE_URL_ENV);
        std::env::set_var(crate::credentials::KEY_ENV, crate::credentials::generate_master_key());
        let dir = tempfile::tempdir().unwrap();
        let tier1 = write_tier1(dir.path(), executor, credential, required_scopes);
        let audit = Arc::new(AuditLog::new(&tier1.audit_dir).unwrap());
        let credentials =
            CredentialStore::new(dir.path().join("credentials.yaml").to_str().unwrap(), audit.clone());
        Env {
            tier1,
            audit,
            credentials,
            states: OAuthStateStore::new(),
            admins: Arc::new(Mutex::new(vec!["root".to_string()])),
            _dir: dir,
            _guard: guard,
        }
    }

    /// A google toolkit bound to `gws`, holding the full old bundle.
    fn google_env() -> Env {
        let e = env_with("google", "gws", None);
        create(
            &e,
            "gws",
            serde_json::json!({
                "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "refresh_token": OLD_REFRESH,
            }),
        );
        e
    }

    /// A microsoft toolkit bound to `msgraph`, client pair only.
    fn microsoft_env() -> Env {
        let e = env_with("microsoft", "msgraph", None);
        create(&e, "msgraph", serde_json::json!({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}));
        e
    }

    fn create(e: &Env, name: &str, bundle: Value) {
        e.credentials
            .create(name, "oauth2", &serde_json::to_string(&bundle).unwrap(), None, None, None, "root", "")
            .unwrap();
    }

    fn stored(e: &Env, name: &str) -> Map<String, Value> {
        let value = e.credentials.resolve(name).unwrap().unwrap().value;
        serde_json::from_str::<Value>(&value).unwrap().as_object().unwrap().clone()
    }

    fn audit_text(e: &Env) -> String {
        std::fs::read_to_string(e.audit.path()).unwrap_or_default()
    }

    fn audit_records(e: &Env) -> Vec<Value> {
        audit_text(e).lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    fn assert_clean(texts: &[&str]) {
        for text in texts {
            for secret in SECRETS {
                assert!(!text.contains(secret), "{secret} in {text}");
            }
        }
    }

    fn start(e: &Env, provider: &str, credential: &str) -> Result<OAuthStart, StartError> {
        let ctx = StartContext {
            tier1: &e.tier1,
            audit: &e.audit,
            credentials: Some(&e.credentials),
            states: Some(&e.states),
        };
        start_authorize(&ctx, provider, credential, "root", &format!("{BASE}/"))
    }

    fn consent_params(start: &OAuthStart) -> HashMap<String, String> {
        let url = url::Url::parse(&start.consent_url).unwrap();
        url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
    }

    fn state_of(e: &Env, provider: &str, credential: &str) -> String {
        consent_params(&start(e, provider, credential).unwrap())["state"].clone()
    }

    async fn run_callback(e: &Env, spec: &OAuthProviderSpec, query: &str, endpoints: &TokenEndpoints) -> String {
        let admins = e.admins.clone();
        let is_admin = move |id: &str| admins.lock().unwrap().iter().any(|a| a == id);
        let ctx = CallbackContext {
            audit: &e.audit,
            credentials: Some(&e.credentials),
            has_config_store: true,
            is_admin: &is_admin,
            states: &e.states,
            endpoints,
        };
        let redirect = callback(&ctx, spec, &CallbackQuery::parse(query)).await.unwrap();
        assert_eq!(redirect.status, 303);
        assert!(redirect.location.starts_with("/app/credentials?"), "{}", redirect.location);
        assert_clean(&[&redirect.location]);
        redirect.location
    }

    fn result(location: &str) -> Vec<(String, String)> {
        let query = location.split_once('?').unwrap().1;
        url::form_urlencoded::parse(query.as_bytes()).map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
    }

    fn mismatch(provider: &str) -> Vec<(String, String)> {
        vec![
            ("oauth".into(), "state_mismatch".into()),
            ("provider".into(), provider.into()),
            ("credential".into(), "".into()),
        ]
    }

    fn google_endpoints(url: &str) -> TokenEndpoints {
        TokenEndpoints { google: url.to_string(), microsoft: never() }
    }

    fn ms_endpoints(url: &str) -> TokenEndpoints {
        TokenEndpoints { google: never(), microsoft: url.to_string() }
    }

    fn consented_google() -> Vec<String> {
        DEFAULT_GOOGLE_SCOPES.iter().map(|s| format!("{GOOGLE_SCOPE_PREFIX}{s}")).collect()
    }

    fn consented_ms() -> Vec<String> {
        microsoft_scope_urls(&DEFAULT_MICROSOFT_SCOPES)
    }

    fn api_error(r: Result<OAuthStart, StartError>) -> (u16, String) {
        match r {
            Err(StartError::Api { status, message }) => (status, message),
            other => panic!("{other:?}"),
        }
    }

    // -- Google: the gate ---------------------------------------------------

    #[tokio::test]
    async fn callback_without_a_state_cannot_be_driven_by_query_alone() {
        let e = google_env();
        for query in [
            format!("code={AUTH_CODE}&state=invented"),
            format!("code={AUTH_CODE}"),
            format!("code={AUTH_CODE}&state="),
            String::new(),
        ] {
            let location = run_callback(&e, &GOOGLE_OAUTH, &query, &google_endpoints(&never())).await;
            assert_eq!(result(&location), mismatch("google"));
        }
        assert_eq!(stored(&e, "gws")["refresh_token"], OLD_REFRESH);
        assert!(audit_text(&e).contains(r#""result": "state_mismatch""#));
    }

    #[test]
    fn an_unknown_provider_is_404_and_no_store_is_409() {
        let e = google_env();
        assert_eq!(api_error(start(&e, "yahoo", "gws")), (404, "No sign-in provider 'yahoo'.".to_string()));
        let ctx = StartContext { tier1: &e.tier1, audit: &e.audit, credentials: None, states: Some(&e.states) };
        assert_eq!(
            api_error(start_authorize(&ctx, "google", "gws", "root", BASE)),
            (409, "This console cannot write credentials (no credential store).".to_string())
        );
    }

    // -- Google: the consent URL ----------------------------------------------

    #[test]
    fn authorize_builds_the_consent_url_with_state() {
        let e = google_env();
        let start = start(&e, "google", "gws").unwrap();
        let params = consent_params(&start);
        assert_eq!(params["client_id"], CLIENT_ID);
        assert_eq!(params["redirect_uri"], format!("{BASE}{OAUTH_CALLBACK_PATH}"));
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["access_type"], "offline");
        assert_eq!(params["prompt"], "consent");
        assert!(params["state"].len() >= 32);
        assert_clean(&[&serde_json::to_string(&start).unwrap()]);
        assert_eq!(start.callback_uri, format!("{BASE}{OAUTH_CALLBACK_PATH}"));
        assert_eq!(start.provider, "google");
        assert_eq!(start.credential, "gws");
        assert_eq!(start.mismatch_error, "redirect_uri_mismatch");
        assert!(start.registration_console.contains("Google Cloud"));
        // Field order of models.OAuthStart.
        let keys: Vec<String> =
            serde_json::to_value(&start).unwrap().as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            [
                "provider", "label", "credential", "consent_url", "callback_uri", "scopes",
                "registration_console", "mismatch_error"
            ]
        );
        // The authorize audit record: names and scopes only.
        let records = audit_records(&e);
        let rec = records.iter().find(|r| r["action"] == "google_authorize").unwrap();
        assert_eq!(rec["surface"], "api");
        assert_eq!(rec["redirect_uri"], format!("{BASE}{OAUTH_CALLBACK_PATH}"));
        assert!(!audit_text(&e).contains(CLIENT_ID));
    }

    #[test]
    fn an_empty_credential_picks_the_one_the_toolkit_names() {
        let e = google_env();
        assert_eq!(start(&e, "google", "  ").unwrap().credential, "gws");
        assert_eq!(
            api_error(start(&e, "microsoft", "")),
            (
                400,
                "No microsoft toolkit in toolkits.yaml names a credential, so there is nothing to \
                 connect. Toolkits are deploy-time only (FR-4.11)."
                    .to_string()
            )
        );
    }

    #[test]
    fn the_base_url_env_wins() {
        let e = google_env();
        std::env::set_var(BASE_URL_ENV, " https://console.example/ ");
        let start = start(&e, "google", "gws").unwrap();
        std::env::remove_var(BASE_URL_ENV);
        assert_eq!(start.callback_uri, format!("https://console.example{OAUTH_CALLBACK_PATH}"));
    }

    #[test]
    fn scopes_default_when_no_toolkit_declares_any() {
        let e = google_env();
        let start = start(&e, "google", "gws").unwrap();
        let scope = consent_params(&start)["scope"].clone();
        assert_eq!(scope.split(' ').map(String::from).collect::<Vec<_>>(), consented_google());
        assert_eq!(start.scopes, consented_google());
        // Spaces are `+` in the URL, as urlencode writes them.
        assert!(start.consent_url.contains("gmail.readonly+https%3A%2F%2F"));
    }

    #[test]
    fn scopes_are_the_union_of_the_google_toolkits() {
        let full = format!("{GOOGLE_SCOPE_PREFIX}calendar.events");
        let e = env_with("google", "gws", Some(&["gmail.readonly", &full, "gmail.readonly"]));
        create(&e, "gws", serde_json::json!({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}));
        let start = start(&e, "google", "gws").unwrap();
        let expected = vec![format!("{GOOGLE_SCOPE_PREFIX}gmail.readonly"), full.clone()];
        assert_eq!(start.scopes, expected);
        assert_eq!(consent_params(&start)["scope"], expected.join(" "));
    }

    #[test]
    fn authorize_refuses_a_credential_that_has_no_client_pair() {
        let e = env_with("google", "gws", None);
        create(&e, "gws", serde_json::json!({"client_id": CLIENT_ID}));
        assert_eq!(
            api_error(start(&e, "google", "gws")),
            (400, "Credential 'gws' is missing client_id/client_secret.".to_string())
        );
        assert!(!audit_text(&e).contains(r#""action": "google_authorize""#));
        assert!(e.states.is_empty());
    }

    #[test]
    fn authorize_refuses_a_missing_or_non_oauth2_credential() {
        let e = google_env();
        e.credentials.create("sonarr", "bearer", "not-an-oauth-credential", None, None, None, "root", "").unwrap();
        assert_eq!(api_error(start(&e, "google", "sonarr")).1, "Credential 'sonarr' is kind 'bearer', not oauth2.");
        assert_eq!(
            api_error(start(&e, "google", "nope")).1,
            "Credential 'nope' does not exist yet. Create it as kind oauth2 with the client_id and \
             client_secret of your Google OAuth client first -- this page only adds the refresh token."
        );
        e.credentials.create("raw", "oauth2", "not json", None, None, None, "root", "").unwrap();
        assert_eq!(api_error(start(&e, "google", "raw")).1, "Credential 'raw' does not hold a JSON bundle.");
    }

    #[test]
    fn the_providers_listing_offers_the_flow_for_toolkit_credentials() {
        let e = google_env();
        e.credentials.create("sonarr", "bearer", "x", None, None, None, "root", "").unwrap();
        assert_eq!(
            serde_json::to_value(providers_view(&e.tier1)).unwrap(),
            serde_json::json!([{
                "key": "google", "label": "Google", "credentials": ["gws"],
                "callback_path": OAUTH_CALLBACK_PATH,
            }])
        );
        drop(e);
        let m = microsoft_env();
        assert_eq!(
            serde_json::to_value(providers_view(&m.tier1)).unwrap(),
            serde_json::json!([{
                "key": "microsoft", "label": "Microsoft", "credentials": ["msgraph"],
                "callback_path": MICROSOFT_OAUTH_CALLBACK_PATH,
            }])
        );
    }

    // -- Google: the callback -------------------------------------------------

    #[tokio::test]
    async fn callback_persists_the_refresh_token() {
        let e = google_env();
        let body = serde_json::json!({
            "access_token": ACCESS_TOKEN, "refresh_token": NEW_REFRESH, "expires_in": 3599,
            "scope": consented_google().join(" "),
        });
        let fake = fake_endpoint(200, &body.to_string()).await;
        let start = start(&e, "google", "gws").unwrap();
        let state = consent_params(&start)["state"].clone();
        let location =
            run_callback(&e, &GOOGLE_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &google_endpoints(&fake.url))
                .await;
        let seen = fake.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let form = &seen[0];
        assert_eq!(form["code"], AUTH_CODE);
        assert_eq!(form["client_id"], CLIENT_ID);
        assert_eq!(form["client_secret"], CLIENT_SECRET);
        assert_eq!(form["redirect_uri"], format!("{BASE}{OAUTH_CALLBACK_PATH}"));
        assert_eq!(form["grant_type"], "authorization_code");
        assert!(!form.contains_key("code_verifier"));

        assert_eq!(
            Value::Object(stored(&e, "gws")),
            serde_json::json!({
                "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
                "refresh_token": NEW_REFRESH, "scopes": consented_google(),
            })
        );
        // Rotated, not re-created.
        let meta = e.credentials.names(None).unwrap().into_iter().find(|m| m.name == "gws").unwrap();
        assert!(meta.rotated_at.is_some());
        assert_eq!(location, "/app/credentials?oauth=ok&provider=google&credential=gws");
        assert_clean(&[&serde_json::to_string(&start).unwrap()]);
    }

    #[tokio::test]
    async fn a_credential_deleted_mid_flow_is_unusable() {
        let e = google_env();
        let fake = fake_endpoint(200, &serde_json::json!({"refresh_token": NEW_REFRESH}).to_string()).await;
        let state = state_of(&e, "google", "gws");
        // The flow found the client pair at the start; deleting the slot
        // in between leaves nothing to resolve -> unusable.
        e.credentials.delete("gws", "root", &e.credentials.revision()).unwrap();
        let location =
            run_callback(&e, &GOOGLE_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &google_endpoints(&fake.url))
                .await;
        assert!(location.contains("oauth=credential_unusable"));
        assert!(fake.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_audit_log_carries_no_token_material() {
        let e = google_env();
        let body = serde_json::json!({"refresh_token": NEW_REFRESH, "access_token": ACCESS_TOKEN});
        let fake = fake_endpoint(200, &body.to_string()).await;
        let state = state_of(&e, "google", "gws");
        let location =
            run_callback(&e, &GOOGLE_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &google_endpoints(&fake.url))
                .await;
        assert!(location.contains("oauth=ok"));
        let log = audit_text(&e);
        assert!(log.contains(r#""action": "google_authorize""#));
        assert!(log.contains(r#""action": "google_callback""#));
        assert!(log.contains(r#""result": "ok""#));
        assert!(log.contains(r#""credential": "gws""#));
        let ok: Vec<Value> = audit_records(&e)
            .into_iter()
            .filter(|r| r["action"] == "google_callback" && r["result"] == "ok")
            .collect();
        assert!(!ok.last().unwrap()["scopes"].as_array().unwrap().is_empty());
        for secret in SECRETS.iter().chain([CLIENT_ID, state.as_str()].iter()) {
            assert!(!log.contains(secret), "{secret}");
        }
    }

    #[tokio::test]
    async fn a_denied_consent_changes_nothing() {
        let e = google_env();
        let state = state_of(&e, "google", "gws");
        let location = run_callback(
            &e,
            &GOOGLE_OAUTH,
            &format!(
                "error=access_denied%3Cscript%3Ealert(1)%3C%2Fscript%3E&error_description=evil+text&state={state}"
            ),
            &google_endpoints(&never()),
        )
        .await;
        assert_eq!(location, "/app/credentials?oauth=denied&provider=google&credential=gws");
        assert_eq!(stored(&e, "gws")["refresh_token"], OLD_REFRESH);
        let denied: Vec<Value> = audit_records(&e).into_iter().filter(|r| r["result"] == "denied").collect();
        let detail = denied.last().unwrap()["detail"].as_str().unwrap().to_string();
        assert!(detail.starts_with("access_denied"));
        assert!(detail.chars().count() <= 64);
    }

    #[tokio::test]
    async fn a_long_denial_is_stripped_and_truncated_to_64_characters() {
        let e = google_env();
        let state = state_of(&e, "google", "gws");
        let long = "x".repeat(100);
        run_callback(&e, &GOOGLE_OAUTH, &format!("error=+{long}&state={state}"), &google_endpoints(&never())).await;
        let denied: Vec<Value> = audit_records(&e).into_iter().filter(|r| r["result"] == "denied").collect();
        assert_eq!(denied[0]["detail"], "x".repeat(64));
    }

    #[tokio::test]
    async fn a_state_is_single_use_and_spent_on_failure_too() {
        let e = google_env();
        let fake = fake_endpoint(200, &serde_json::json!({"refresh_token": NEW_REFRESH}).to_string()).await;
        let state = state_of(&e, "google", "gws");
        let q = format!("code={AUTH_CODE}&state={state}");
        let first = run_callback(&e, &GOOGLE_OAUTH, &q, &google_endpoints(&fake.url)).await;
        let second = run_callback(&e, &GOOGLE_OAUTH, &q, &google_endpoints(&fake.url)).await;
        assert!(first.contains("oauth=ok"));
        assert_eq!(result(&second), mismatch("google"));
        assert_eq!(fake.seen.lock().unwrap().len(), 1);

        let state = state_of(&e, "google", "gws");
        let denied =
            run_callback(&e, &GOOGLE_OAUTH, &format!("error=access_denied&state={state}"), &google_endpoints(&never()))
                .await;
        let retry =
            run_callback(&e, &GOOGLE_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &google_endpoints(&never()))
                .await;
        assert!(denied.contains("oauth=denied"));
        assert!(retry.contains("oauth=state_mismatch"));
    }

    #[tokio::test]
    async fn an_expired_state_redeems_nothing() {
        let mut e = google_env();
        e.states = OAuthStateStore::with_ttl(Duration::ZERO);
        let state = state_of(&e, "google", "gws");
        let location =
            run_callback(&e, &GOOGLE_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &google_endpoints(&never()))
                .await;
        assert_eq!(result(&location), mismatch("google"));
    }

    #[tokio::test]
    async fn a_state_writes_as_the_operator_it_was_issued_to() {
        let e = google_env();
        let fake = fake_endpoint(200, &serde_json::json!({"refresh_token": NEW_REFRESH}).to_string()).await;
        let state = state_of(&e, "google", "gws");
        run_callback(&e, &GOOGLE_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &google_endpoints(&fake.url))
            .await;
        assert_eq!(stored(&e, "gws")["refresh_token"], NEW_REFRESH);
        let actors: Vec<Value> = audit_records(&e)
            .into_iter()
            .filter(|r| r["action"] == "google_callback")
            .map(|r| r["actor"].clone())
            .collect();
        assert_eq!(actors, vec![Value::from("root")]);
    }

    #[tokio::test]
    async fn a_revoked_admin_cannot_finish_a_flow_it_started() {
        let e = google_env();
        let state = state_of(&e, "google", "gws");
        e.admins.lock().unwrap().clear();
        let location =
            run_callback(&e, &GOOGLE_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &google_endpoints(&never()))
                .await;
        assert_eq!(location, "/app/credentials?oauth=role_required&provider=google&credential=gws");
        assert_eq!(stored(&e, "gws")["refresh_token"], OLD_REFRESH);
        assert!(audit_text(&e).contains(r#""result": "role_required""#));
    }

    #[tokio::test]
    async fn a_response_without_a_refresh_token_is_an_error() {
        let e = google_env();
        let body = serde_json::json!({"access_token": ACCESS_TOKEN, "expires_in": 3599});
        let fake = fake_endpoint(200, &body.to_string()).await;
        let state = state_of(&e, "google", "gws");
        let location =
            run_callback(&e, &GOOGLE_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &google_endpoints(&fake.url))
                .await;
        assert!(location.contains("oauth=no_refresh_token"));
        assert_eq!(stored(&e, "gws")["refresh_token"], OLD_REFRESH);
        assert_clean(&[&location, &audit_text(&e)]);
    }

    #[tokio::test]
    async fn a_failed_exchange_says_so_without_quoting_google() {
        let refused = format!(r#"{{"error": "invalid_client", "echo": "{CLIENT_SECRET}"}}"#);
        for (status, body) in [(400, refused.as_str()), (200, "not json"), (200, "[1, 2]")] {
            let e = google_env();
            let fake = fake_endpoint(status, body).await;
            let state = state_of(&e, "google", "gws");
            let location = run_callback(
                &e,
                &GOOGLE_OAUTH,
                &format!("code={AUTH_CODE}&state={state}"),
                &google_endpoints(&fake.url),
            )
            .await;
            assert_eq!(location, "/app/credentials?oauth=exchange_failed&provider=google&credential=gws");
            assert_clean(&[&audit_text(&e)]);
            assert_eq!(stored(&e, "gws")["refresh_token"], OLD_REFRESH);
            assert!(audit_text(&e).contains(r#""result": "exchange_failed""#));
        }
        // Transport failure: nothing listens.
        let e = google_env();
        let state = state_of(&e, "google", "gws");
        let location =
            run_callback(&e, &GOOGLE_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &google_endpoints(&never()))
                .await;
        assert!(location.contains("oauth=exchange_failed"));
    }

    #[tokio::test]
    async fn the_exchange_errors_name_the_status_only() {
        let fake = fake_endpoint(401, &format!(r#"{{"secret": "{CLIENT_SECRET}"}}"#)).await;
        match exchange_google_code(&fake.url, "c", "i", CLIENT_SECRET, "r").await {
            Err(ExchangeError::Refused(e)) => assert_eq!(e.0, "Google refused the code exchange (HTTP 401)."),
            other => panic!("{other:?}"),
        }
        let fake = fake_endpoint(200, "nope").await;
        match exchange_microsoft_code(&fake.url, "c", "i", "s", "r", "v").await {
            Err(ExchangeError::Refused(e)) => assert_eq!(e.0, "Microsoft's token response was not JSON."),
            other => panic!("{other:?}"),
        }
        let fake = fake_endpoint(200, "\"str\"").await;
        match exchange_google_code(&fake.url, "c", "i", "s", "r").await {
            Err(ExchangeError::Refused(e)) => assert_eq!(e.0, "Google's token response was not an object."),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn without_a_config_store_the_callback_is_read_only() {
        let e = google_env();
        let endpoints = google_endpoints(&never());
        let is_admin = |_: &str| true;
        let ctx = CallbackContext {
            audit: &e.audit,
            credentials: Some(&e.credentials),
            has_config_store: false,
            is_admin: &is_admin,
            states: &e.states,
            endpoints: &endpoints,
        };
        let state = state_of(&e, "google", "gws");
        let q = CallbackQuery::parse(&format!("code=x&state={state}"));
        let redirect = callback(&ctx, &GOOGLE_OAUTH, &q).await.unwrap();
        assert_eq!(redirect.location, "/app/credentials?oauth=read_only&provider=google&credential=gws");
        // no_code comes before read_only.
        let state = state_of(&e, "google", "gws");
        let q = CallbackQuery::parse(&format!("state={state}"));
        let redirect = callback(&ctx, &GOOGLE_OAUTH, &q).await.unwrap();
        assert!(redirect.location.contains("oauth=no_code"));
    }

    #[tokio::test]
    async fn an_unusable_credential_is_flagged_before_any_exchange() {
        let e = google_env();
        let fake = fake_endpoint(200, &serde_json::json!({"refresh_token": NEW_REFRESH}).to_string()).await;
        let state = state_of(&e, "google", "gws");
        let half = serde_json::json!({"client_id": CLIENT_ID}).to_string();
        e.credentials.rotate("gws", &half, 0, "root", &e.credentials.revision()).unwrap();
        let location =
            run_callback(&e, &GOOGLE_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &google_endpoints(&fake.url))
                .await;
        assert!(location.contains("oauth=credential_unusable"));
        assert!(fake.seen.lock().unwrap().is_empty());
    }

    // -- Scope handling (units) ----------------------------------------------

    #[test]
    fn an_unusable_scope_field_falls_back() {
        for raw in [Value::Null, Value::from(""), Value::from(123), serde_json::json!(["not", "a", "string"])] {
            let mut payload = Map::new();
            payload.insert("scope".into(), raw);
            assert_eq!(granted_google_scopes(&payload, &consented_google()), consented_google());
            assert_eq!(granted_microsoft_scopes(&payload, &consented_ms()), consented_ms());
        }
    }

    #[test]
    fn the_scope_field_is_bounded_and_deduplicated() {
        let mut parts = vec!["a".repeat(MAX_GOOGLE_SCOPE_CHARS + 1)];
        parts.extend((0..200).map(|i| format!("s{i}")));
        let mut payload = Map::new();
        payload.insert("scope".into(), parts.join(" ").into());
        for granted in [granted_google_scopes(&payload, &consented_google()), granted_microsoft_scopes(&payload, &[])] {
            assert_eq!(granted.len(), MAX_GOOGLE_SCOPES);
            assert!(granted.iter().all(|s| s.len() <= MAX_GOOGLE_SCOPE_CHARS));
        }
        payload.insert("scope".into(), "one one two".into());
        assert_eq!(granted_google_scopes(&payload, &consented_google()), ["one", "two"]);
        assert_eq!(granted_microsoft_scopes(&payload, &[]), ["one", "two"]);
    }

    #[test]
    fn the_reserved_scopes_are_never_prefixed() {
        for reserved in MICROSOFT_RESERVED_SCOPES {
            assert_eq!(microsoft_scope_urls(&[reserved]), [reserved]);
        }
    }

    #[test]
    fn bare_names_are_expanded_and_urls_left_alone() {
        let full = format!("{MICROSOFT_SCOPE_PREFIX}Mail.Read");
        assert_eq!(
            microsoft_scope_urls(&["Mail.Read", &full, " ", "User.Read"]),
            [full.clone(), format!("{MICROSOFT_SCOPE_PREFIX}User.Read")]
        );
        assert_eq!(
            google_scope_urls(&[" gmail.send ", "", "https://x/y"]),
            [format!("{GOOGLE_SCOPE_PREFIX}gmail.send"), "https://x/y".to_string()]
        );
    }

    #[test]
    fn the_pkce_pair_is_a_valid_rfc7636_pair() {
        let (verifier, challenge) = pkce_pair();
        assert!((43..=128).contains(&verifier.len()));
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, expected);
        assert_eq!(challenge.len(), 43);
        assert_ne!(pkce_pair().0, verifier);
    }

    #[test]
    fn urlencode_matches_python() {
        // urllib.parse.urlencode({"a": "x y*~/", "b": "ä"}) == 'a=x+y%2A~%2F&b=%C3%A4'
        assert_eq!(urlencode(&[("a", "x y*~/"), ("b", "ä")]), "a=x+y%2A~%2F&b=%C3%A4");
        assert_eq!(app_result_url("ok", "google", "a b"), "/app/credentials?oauth=ok&provider=google&credential=a+b");
    }

    #[test]
    fn the_callback_query_takes_the_last_value() {
        let q = CallbackQuery::parse("state=a&state=b&code=x+y&error=");
        assert_eq!(q.state.as_deref(), Some("b"));
        assert_eq!(q.code.as_deref(), Some("x y"));
        assert_eq!(q.error.as_deref(), Some(""));
    }

    // -- Microsoft ------------------------------------------------------------

    #[test]
    fn microsoft_authorize_builds_the_consent_url_with_state_and_pkce() {
        let e = microsoft_env();
        let start = start(&e, "microsoft", "msgraph").unwrap();
        let params = consent_params(&start);
        assert_eq!(params["client_id"], CLIENT_ID);
        assert_eq!(params["redirect_uri"], format!("{BASE}{MICROSOFT_OAUTH_CALLBACK_PATH}"));
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["response_mode"], "query");
        assert_eq!(params["prompt"], "consent");
        assert!(params["state"].len() >= 32);
        assert_eq!(params["code_challenge_method"], "S256");
        assert!(!params["code_challenge"].contains('='));
        assert_eq!(params["code_challenge"].len(), 43);
        assert_eq!(start.callback_uri, params["redirect_uri"]);
        assert_eq!(start.mismatch_error, "AADSTS50011");
        assert_eq!(params["scope"].split(' ').map(String::from).collect::<Vec<_>>(), consented_ms());
        assert_eq!(start.scopes, consented_ms());
        assert_clean(&[&serde_json::to_string(&start).unwrap()]);
    }

    #[test]
    fn microsoft_scopes_are_the_union_of_the_toolkits() {
        let full = format!("{MICROSOFT_SCOPE_PREFIX}Mail.Send");
        let e = env_with("microsoft", "msgraph", Some(&["Mail.Read", &full, "offline_access", "Mail.Read"]));
        create(&e, "msgraph", serde_json::json!({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}));
        let start = start(&e, "microsoft", "msgraph").unwrap();
        assert_eq!(start.scopes, [format!("{MICROSOFT_SCOPE_PREFIX}Mail.Read"), full, "offline_access".into()]);
    }

    async fn ms_flow(e: &Env, body: Value) -> (OAuthStart, String, FakeTokenEndpoint) {
        let fake = fake_endpoint(200, &body.to_string()).await;
        let start = start(e, "microsoft", "msgraph").unwrap();
        let state = consent_params(&start)["state"].clone();
        let location =
            run_callback(e, &MICROSOFT_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &ms_endpoints(&fake.url))
                .await;
        assert_eq!(location, "/app/credentials?oauth=ok&provider=microsoft&credential=msgraph");
        assert_clean(&[&serde_json::to_string(&start).unwrap()]);
        (start, location, fake)
    }

    #[tokio::test]
    async fn the_exchange_gets_the_verifier_that_matches_the_challenge() {
        let e = microsoft_env();
        let (start, location, fake) = ms_flow(&e, serde_json::json!({"refresh_token": NEW_REFRESH})).await;
        let form = fake.seen.lock().unwrap()[0].clone();
        let verifier = form["code_verifier"].clone();
        assert!(!verifier.is_empty());
        assert!(!serde_json::to_string(&start).unwrap().contains(&verifier));
        assert!(!location.contains(&verifier));
        assert!(!audit_text(&e).contains(&verifier));
        assert_eq!(pkce_challenge(&verifier), consent_params(&start)["code_challenge"]);
        assert_eq!(form["redirect_uri"], format!("{BASE}{MICROSOFT_OAUTH_CALLBACK_PATH}"));
        assert_eq!(form["client_id"], CLIENT_ID);
        assert_eq!(form["grant_type"], "authorization_code");
    }

    #[tokio::test]
    async fn microsoft_callback_persists_the_token_scopes_and_provider() {
        let e = microsoft_env();
        ms_flow(
            &e,
            serde_json::json!({
                "access_token": "EwB.access-token-value", "refresh_token": NEW_REFRESH,
                "expires_in": 3599, "scope": consented_ms().join(" "),
            }),
        )
        .await;
        assert_eq!(
            Value::Object(stored(&e, "msgraph")),
            serde_json::json!({
                "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "refresh_token": NEW_REFRESH,
                "scopes": consented_ms(), "provider": "microsoft",
            })
        );
        let log = audit_text(&e);
        assert!(log.contains(r#""action": "microsoft_authorize""#));
        assert!(log.contains(r#""action": "microsoft_callback""#));
        assert!(log.contains(&format!("{MICROSOFT_SCOPE_PREFIX}Mail.Send")));
        for secret in [NEW_REFRESH, CLIENT_SECRET, CLIENT_ID, AUTH_CODE, "EwB.access-token-value"] {
            assert!(!log.contains(secret), "{secret}");
        }
    }

    #[tokio::test]
    async fn offline_access_survives_a_response_that_omits_it() {
        let e = microsoft_env();
        let graph_only: Vec<String> = consented_ms().into_iter().filter(|s| s != "offline_access").collect();
        ms_flow(&e, serde_json::json!({"refresh_token": NEW_REFRESH, "scope": graph_only.join(" ")})).await;
        let mut expected = graph_only.clone();
        expected.push("offline_access".into());
        assert_eq!(stored(&e, "msgraph")["scopes"], serde_json::json!(expected));
    }

    #[tokio::test]
    async fn a_narrowed_microsoft_grant_is_stored_as_granted() {
        let e = microsoft_env();
        let narrowed = format!("{MICROSOFT_SCOPE_PREFIX}Mail.Read");
        ms_flow(&e, serde_json::json!({"refresh_token": NEW_REFRESH, "scope": narrowed})).await;
        assert_eq!(stored(&e, "msgraph")["scopes"], serde_json::json!([narrowed, "offline_access"]));
    }

    #[tokio::test]
    async fn microsoft_scopes_fall_back_to_the_consent_screens() {
        let e = microsoft_env();
        ms_flow(&e, serde_json::json!({"refresh_token": NEW_REFRESH})).await;
        assert_eq!(stored(&e, "msgraph")["scopes"], serde_json::json!(consented_ms()));
    }

    #[tokio::test]
    async fn a_microsoft_denied_consent_changes_nothing() {
        let e = microsoft_env();
        let state = state_of(&e, "microsoft", "msgraph");
        let location = run_callback(
            &e,
            &MICROSOFT_OAUTH,
            &format!("error=access_denied&error_description=AADSTS65004+evil&state={state}"),
            &ms_endpoints(&never()),
        )
        .await;
        assert_eq!(location, "/app/credentials?oauth=denied&provider=microsoft&credential=msgraph");
        assert!(audit_text(&e).contains(r#""result": "denied""#));
        assert!(!stored(&e, "msgraph").contains_key("refresh_token"));
    }

    #[tokio::test]
    async fn a_google_state_is_not_redeemable_at_the_microsoft_callback() {
        let e = google_env();
        let state = state_of(&e, "google", "gws");
        let q = format!("code={AUTH_CODE}&state={state}");
        let both_never = TokenEndpoints { google: never(), microsoft: never() };
        let crossed = run_callback(&e, &MICROSOFT_OAUTH, &q, &both_never).await;
        let after = run_callback(&e, &GOOGLE_OAUTH, &q, &both_never).await;
        assert_eq!(result(&crossed), mismatch("microsoft"));
        assert_eq!(result(&after), mismatch("google"));
        assert_eq!(stored(&e, "gws")["refresh_token"], OLD_REFRESH);
        assert!(audit_text(&e).contains(r#""result": "state_mismatch""#));
    }

    #[tokio::test]
    async fn a_microsoft_state_is_not_redeemable_at_the_google_callback() {
        let e = microsoft_env();
        let state = state_of(&e, "microsoft", "msgraph");
        let both_never = TokenEndpoints { google: never(), microsoft: never() };
        let crossed = run_callback(&e, &GOOGLE_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &both_never).await;
        assert!(crossed.contains("oauth=state_mismatch"));
        assert!(!stored(&e, "msgraph").contains_key("refresh_token"));
    }

    #[tokio::test]
    async fn a_microsoft_response_without_a_refresh_token_is_an_error() {
        let e = microsoft_env();
        let fake = fake_endpoint(200, r#"{"access_token": "EwB.access-token-value", "expires_in": 3599}"#).await;
        let state = state_of(&e, "microsoft", "msgraph");
        let location =
            run_callback(&e, &MICROSOFT_OAUTH, &format!("code={AUTH_CODE}&state={state}"), &ms_endpoints(&fake.url))
                .await;
        assert!(location.contains("oauth=no_refresh_token"));
        assert!(!audit_text(&e).contains("EwB.access-token-value"));
        assert!(!stored(&e, "msgraph").contains_key("refresh_token"));
    }

    // -- Token materialization (service.py) ------------------------------------

    fn token_bundle(extra: Value) -> Value {
        let mut b = serde_json::json!({
            "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "refresh_token": NEW_REFRESH,
        });
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    }

    fn materialized(e: &Env, spec: &TokenFileSpec, name: &str, cache: &TokenDirCache) -> Value {
        let env = oauth_token_env(Some(&e.credentials), Some(name), spec, cache).unwrap();
        let path = Path::new(&env["HOME"]).join(".hermes").join(spec.token_filename);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn materialized_token_carries_the_stored_scopes() {
        let e = env_with("microsoft", "msgraph", None);
        create(&e, "msgraph", token_bundle(serde_json::json!({"scopes": consented_ms(), "provider": "microsoft"})));
        create(&e, "gws", token_bundle(serde_json::json!({"scopes": consented_google()})));
        let cache = TokenDirCache::new();
        assert_eq!(
            materialized(&e, &MICROSOFT_TOKEN_FILE, "msgraph", &cache),
            token_bundle(serde_json::json!({"scopes": consented_ms()}))
        );
        let gcache = TokenDirCache::new();
        assert_eq!(
            materialized(&e, &GOOGLE_TOKEN_FILE, "gws", &gcache),
            token_bundle(serde_json::json!({"scopes": consented_google()}))
        );
        cache.invalidate();
        gcache.invalidate();
    }

    #[test]
    fn the_token_file_and_dir_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let e = env_with("microsoft", "msgraph", None);
        create(&e, "msgraph", token_bundle(serde_json::json!({})));
        let cache = TokenDirCache::new();
        let env = microsoft_token_env(Some(&e.credentials), Some("msgraph"), &cache).unwrap();
        let home = Path::new(&env["HOME"]);
        assert!(home.file_name().unwrap().to_str().unwrap().starts_with("gatekeeper-microsoft-"));
        let file = home.join(".hermes/microsoft_token.json");
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o077, 0);
        assert_eq!(std::fs::metadata(home).unwrap().permissions().mode() & 0o777, 0o700);
        cache.invalidate();
    }

    #[test]
    fn a_credential_without_or_with_a_non_list_scopes_field_omits_it() {
        let e = env_with("google", "gws", None);
        let cache = TokenDirCache::new();
        let variants = [
            None,
            Some(Value::from("")),
            Some(serde_json::json!([])),
            Some(serde_json::json!({})),
            Some(Value::from("a-string")),
        ];
        for (i, scopes) in variants.into_iter().enumerate() {
            let name = format!("gws{i}");
            let extra = match scopes {
                Some(s) => serde_json::json!({"scopes": s}),
                None => serde_json::json!({}),
            };
            create(&e, &name, token_bundle(extra));
            assert!(materialized(&e, &GOOGLE_TOKEN_FILE, &name, &cache).get("scopes").is_none());
        }
        cache.invalidate();
    }

    #[test]
    fn the_token_env_refusals_read_as_before() {
        let e = env_with("microsoft", "msgraph", None);
        let cache = TokenDirCache::new();
        let detail = |r: Result<HashMap<String, String>, Denied>| {
            let d = r.unwrap_err();
            assert_eq!(d.reason, DenialReason::CredentialUnavailable);
            d.agent_message()
        };
        let creds = Some(&e.credentials);
        assert_eq!(
            detail(microsoft_token_env(creds, None, &cache)),
            "This microsoft toolkit needs a credential configured."
        );
        assert_eq!(
            detail(microsoft_token_env(None, Some("msgraph"), &cache)),
            "No credential store is configured, but this microsoft toolkit needs one."
        );
        assert_eq!(
            detail(microsoft_token_env(creds, Some("msgraph"), &cache)),
            "Credential 'msgraph' is not configured yet."
        );
        e.credentials.create("bear", "bearer", "x", None, None, None, "root", "").unwrap();
        assert_eq!(
            detail(microsoft_token_env(creds, Some("bear"), &cache)),
            "Credential 'bear' is not an oauth2 credential."
        );
        e.credentials.create("raw", "oauth2", "{not json", None, None, None, "root", "").unwrap();
        assert_eq!(
            detail(microsoft_token_env(creds, Some("raw"), &cache)),
            "Credential 'raw' is not a valid oauth2 JSON bundle."
        );
        create(&e, "half", serde_json::json!({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}));
        assert_eq!(
            detail(microsoft_token_env(creds, Some("half"), &cache)),
            "Credential 'half' is missing client_id/client_secret/refresh_token."
        );
        create(&e, "g", token_bundle(serde_json::json!({"provider": "google"})));
        let message = detail(microsoft_token_env(creds, Some("g"), &cache));
        assert_eq!(
            message,
            "Credential 'g' is a google OAuth credential, but this toolkit is microsoft. Connect the \
             credential from the console's microsoft sign-in, or point the toolkit at a different credential."
        );
        // A bundle with no `provider` passes either toolkit.
        create(&e, "plain", token_bundle(serde_json::json!({})));
        assert!(google_token_env(creds, Some("plain"), &cache).is_ok());
        cache.invalidate();
    }

    #[test]
    fn invalidating_the_cache_re_materializes() {
        let e = env_with("microsoft", "msgraph", None);
        create(&e, "msgraph", token_bundle(serde_json::json!({"scopes": consented_ms()})));
        let cache = TokenDirCache::new();
        let home = |c: &TokenDirCache| microsoft_token_env(Some(&e.credentials), Some("msgraph"), c).unwrap()["HOME"].clone();
        let first = home(&cache);
        assert_eq!(home(&cache), first);
        cache.invalidate();
        let second = home(&cache);
        assert_ne!(first, second);
        assert!(!Path::new(&first).exists());
        cache.invalidate();
    }

    /// The `SCOPES = [...]` fallback list of a vendored script, as written.
    fn script_scopes(rel: &str) -> Vec<String> {
        let text = std::fs::read_to_string(format!("{}/../scripts/{rel}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let start = text.find("\nSCOPES = [\n").expect("a SCOPES list") + "\nSCOPES = [\n".len();
        let body = &text[start..start + text[start..].find("\n]").unwrap()];
        body.lines().map(|l| l.trim().trim_end_matches(',').trim_matches('"').to_string()).collect()
    }

    /// The scripts fall back to exactly what the console asks a human to
    /// consent to, for a token file written before scopes were stored --
    /// a wider list is a refresh Google or Microsoft refuses outright.
    #[test]
    fn the_vendored_scripts_fall_back_to_the_consented_scopes() {
        assert_eq!(script_scopes("google/google_api.py"), consented_google());
        assert_eq!(script_scopes("microsoft/microsoft_api.py"), consented_ms());
    }
}
