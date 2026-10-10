"""OAuth sign-in for `oauth2` credentials (Google, Microsoft).

Moved out of `ui.py` so the console API can start a flow too: the
constants, the single-use `state` store, the consent URLs, the code
exchange and the provider descriptors. Nothing here renders a page.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import secrets
import time
import urllib.parse
from collections.abc import Iterable, Mapping
from typing import Any

import httpx
from starlette.requests import Request

UI_PREFIX = "/ui"


# -- Google OAuth sign-in -------------------------------------------------
#
# The `google` executor needs an `oauth2` credential holding
# {client_id, client_secret, refresh_token, scopes}. The first two come
# from a Google Cloud OAuth client and can be typed into the credential
# form; the other two cannot -- they only exist after a human has
# clicked through a consent screen. Before this, that meant running a setup script outside
# gatekeeper and pasting the resulting token back in, which is exactly
# the kind of secret handling (clipboard, shell history, a file on
# someone's laptop) the credential store exists to avoid.
#
# So the console performs the code exchange itself: the operator clicks
# through consent, Google redirects back to the callback route, and the
# refresh token goes straight into the credential store, encrypted, and
# is never rendered, logged, or echoed back (FR-10.2/10.7). The pages
# below say "ok" or "error" and nothing else.

#: Google's consent screen and token endpoint. Constants rather than
#: configuration: these are Google's, not a deployment's, and a
#: configurable token endpoint is a credential-exfiltration knob.
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
#: Bare scope names in a toolkit's `required_scopes` are expanded with this.
GOOGLE_SCOPE_PREFIX = "https://www.googleapis.com/auth/"

OAUTH_AUTHORIZE_PATH = f"{UI_PREFIX}/oauth/google/authorize"
OAUTH_CALLBACK_PATH = f"{UI_PREFIX}/oauth/google/callback"

#: Overrides the base URL the callback `redirect_uri` is built from. Only
#: needed when the console is reached through a proxy that rewrites the
#: host and does not forward it -- otherwise the request's own base URL
#: is what the browser just used and therefore what Google must be told.
#: The URI has to match the OAuth client's registered redirect URI
#: character for character, which is why the authorize page prints it.
BASE_URL_ENV = "GATEKEEPER_BASE_URL"

#: What the consent screen asks for when no `google` toolkit declares
#: `required_scopes`. The union of what `google_api.py`'s actions need
#: across gmail, calendar, drive, sheets and contacts -- a deployment
#: that wants less says so per toolkit in `toolkits.yaml` and gets
#: exactly that instead (`Tier1.google_oauth_scopes`).
DEFAULT_GOOGLE_SCOPES = (
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
)

#: Bounds on the `scope` field of a token response before any of it is
#: written to the credential store. Google returns ten-ish short URLs;
#: these are the "this is not a scope list" line, not a real limit.
#: Applied to Microsoft's `scope` field too (`_granted_scopes`) -- it is
#: the same OAuth 2.0 field and its scopes are the same shape, so the
#: same bound answers the same question. Kept under the original name
#: because it is what the constant has always been called.
MAX_GOOGLE_SCOPES = 64
MAX_GOOGLE_SCOPE_CHARS = 256


# -- Microsoft OAuth sign-in ----------------------------------------------
#
# The `microsoft` executor wants the same `oauth2` credential the google
# one does, filled the same way: client_id and client_secret typed in
# from an Azure app registration, refresh token and scopes obtained by a
# human clicking through a consent screen. So these two routes are the
# google pair with Microsoft's endpoints behind them, and everything the
# comment above says about why the console does the exchange itself
# holds here word for word.
#
# Two things differ, both Microsoft's:
#
# 1. The flow uses PKCE. The google pair predates it and a confidential
#    client with a secret does not strictly need it, but Microsoft
#    accepts a `code_challenge` from a confidential client and an
#    authorization code that only redeems together with a verifier this
#    process generated is strictly less useful to anyone who intercepts
#    it. New flow, so it starts with the better default.
# 2. `offline_access` is what makes Microsoft return a refresh token --
#    there is no `access_type=offline`. It is also a scope Microsoft
#    usually leaves out of the token response's `scope` field, which is
#    why `_granted_microsoft_scopes` puts it back (see there).

#: Microsoft's identity platform, v2.0. `common` rather than a tenant id:
#: this is mail for outlook.com/hotmail.com accounts as much as for work
#: accounts, and `common` is the authority that accepts both. Constants
#: rather than configuration, for the reason the google pair is.
MICROSOFT_AUTHORITY = "https://login.microsoftonline.com/common"
MICROSOFT_AUTH_ENDPOINT = f"{MICROSOFT_AUTHORITY}/oauth2/v2.0/authorize"
MICROSOFT_TOKEN_ENDPOINT = f"{MICROSOFT_AUTHORITY}/oauth2/v2.0/token"
#: Bare scope names in a toolkit's `required_scopes` are expanded with
#: this -- `Mail.Read` and `https://graph.microsoft.com/Mail.Read` are
#: the same request.
MICROSOFT_SCOPE_PREFIX = "https://graph.microsoft.com/"

#: The OIDC/OAuth scopes that are *not* Graph resources and must never be
#: prefixed: `https://graph.microsoft.com/offline_access` is not a scope
#: and Microsoft rejects the whole request for it.
MICROSOFT_RESERVED_SCOPES = ("offline_access", "openid", "profile", "email")

MICROSOFT_OAUTH_AUTHORIZE_PATH = f"{UI_PREFIX}/oauth/microsoft/authorize"
MICROSOFT_OAUTH_CALLBACK_PATH = f"{UI_PREFIX}/oauth/microsoft/callback"

#: What the consent screen asks for when no `microsoft` toolkit declares
#: `required_scopes`. Minimal on purpose -- read mail, send mail, know
#: whose mailbox this is, and keep the refresh token alive -- because the
#: grant is what a compromise of the credential would be worth. A
#: deployment that wants less says so per toolkit in `toolkits.yaml` and
#: gets exactly that instead (`Tier1.microsoft_oauth_scopes`).
DEFAULT_MICROSOFT_SCOPES = (
    "Mail.Read",
    "Mail.Send",
    "User.Read",
    "offline_access",
)

#: How long an issued `state` stays redeemable. Long enough to read a
#: consent screen, short enough that an abandoned flow does not leave a
#: usable handle lying around.
OAUTH_STATE_TTL_SECONDS = 600


# -- Flows in flight -------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class OAuthState:
    """What an issued `state` stands for: who started the flow, for which

    credential, with which redirect URI, and asking for which scopes. All
    four are pinned at issue time, so the callback cannot be talked into
    writing a different credential or into accepting a code minted for a
    different URI -- and the scopes the consent screen actually asked for
    are still known when the code comes back, which is what gets stored
    alongside the refresh token (see `oauth_google_callback`).
    """

    identity: str
    credential: str
    redirect_uri: str
    scopes: tuple[str, ...] = ()
    #: Which sign-in this state belongs to. One store serves both
    #: providers, and a state issued by the Google flow must not be
    #: redeemable at the Microsoft callback -- the credential would be
    #: written with a bundle from the wrong identity platform.
    provider: str = "google"
    #: The PKCE verifier, for a provider whose flow uses one. Never
    #: leaves this process: the challenge goes to the consent screen, the
    #: verifier goes into the token request, and the two only meet at a
    #: callback this console issued the state for.
    code_verifier: str = ""


@dataclasses.dataclass(slots=True)
class OAuthStateStore:
    """The pending Google consent flows, in memory.

    Like `SessionStore`, deliberately not persisted: a restart cancels
    every half-finished flow, which costs one more click and keeps a
    redeemable handle off disk.

    `state` does the binding OAuth expects of it. It matters more here
    than in a typical web app, because the console session cookie is
    `SameSite=Strict` and Google's redirect back is a cross-site
    navigation -- browsers do not attach a Strict cookie to it, so the
    callback frequently sees no session at all. The state is therefore
    the proof that this callback belongs to a flow an authenticated
    operator started: 32 random bytes, handed out only to a signed-in
    admin, usable exactly once, expiring in
    `OAUTH_STATE_TTL_SECONDS`. The write is made as the operator the state
    was issued to, and only while that operator is still an admin; the
    console's session cookie (path `/api/v1`) never reaches the callback.
    """

    ttl: int = OAUTH_STATE_TTL_SECONDS
    _states: dict[str, tuple[OAuthState, float]] = dataclasses.field(default_factory=dict)

    def issue(
        self, *, identity: str, credential: str, redirect_uri: str,
        scopes: Iterable[str] = (), provider: str = "google",
        code_verifier: str = "",
    ) -> str:
        self._prune()
        state = secrets.token_urlsafe(32)
        self._states[state] = (
            OAuthState(
                identity=identity, credential=credential,
                redirect_uri=redirect_uri, scopes=tuple(scopes),
                provider=provider, code_verifier=code_verifier,
            ),
            time.monotonic() + self.ttl,
        )
        return state

    def take(self, state: str | None) -> OAuthState | None:
        """Single use: a redeemed state is gone, a replay finds nothing."""
        self._prune()
        if not state:
            return None
        entry = self._states.pop(state, None)
        if entry is None:
            return None
        pending, expires = entry
        if time.monotonic() >= expires:
            return None
        return pending

    def _prune(self) -> None:
        now = time.monotonic()
        for state in [s for s, (_, exp) in self._states.items() if now >= exp]:
            self._states.pop(state, None)


# -- Google OAuth sign-in -------------------------------------------------


def _google_scope_urls(scopes: Iterable[str]) -> list[str]:
    """Bare names become full scope URLs; full URLs are left alone.

    `required_scopes: [gmail.send]` and
    `required_scopes: [https://www.googleapis.com/auth/gmail.send]` are
    the same request -- a toolkit may write whichever reads better next
    to its `allowed_google_actions`.
    """
    urls: list[str] = []
    for scope in scopes:
        scope = scope.strip()
        if not scope:
            continue
        url = scope if "://" in scope else GOOGLE_SCOPE_PREFIX + scope
        if url not in urls:
            urls.append(url)
    return urls


def _public_base_url(request: Request) -> str:
    """The origin a browser reaches this console at, without trailing slash.

    `GATEKEEPER_BASE_URL` wins when set, because behind a proxy that
    rewrites the host the request's own view of itself is the internal
    one, and Google compares the `redirect_uri` against the registered
    string exactly.
    """
    configured = os.environ.get(BASE_URL_ENV, "").strip()
    if configured:
        return configured.rstrip("/")
    return str(request.base_url).rstrip("/")


def _google_consent_url(*, client_id: str, redirect_uri: str, scopes: list[str], state: str) -> str:
    """Google's consent screen URL for one flow.

    `access_type=offline` plus `prompt=consent` is what makes Google
    return a *refresh* token: without them a re-authorization of an
    already-granted client comes back with an access token only, and an
    access token is useless here -- it expires in an hour and the
    `google` executor has nothing to renew it with.
    """
    query = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
    )
    return f"{GOOGLE_AUTH_ENDPOINT}?{query}"


class OAuthExchangeError(Exception):
    """A code exchange that did not produce a usable answer.

    Carries a message safe to render: never the response body, never a
    token, never the client secret.
    """


async def _exchange_google_code(
    *, code: str, client_id: str, client_secret: str, redirect_uri: str
) -> dict[str, Any]:
    """Trades the authorization code for a refresh token.

    A module-level function rather than an inline request so a test can
    replace it without a network listener, and so there is exactly one
    place where the token response exists. The caller keeps two fields of
    it, `refresh_token` and `scope` (see `_granted_google_scopes`) -- the
    access token in the same response is deliberately dropped on the
    floor.
    """
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            GOOGLE_TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
    if response.status_code >= 400:
        # The body may quote the client_secret back -- the status is the
        # only part of it that may ever reach a page or the audit log.
        raise OAuthExchangeError(
            f"Google refused the code exchange (HTTP {response.status_code})."
        )
    try:
        payload = response.json()
    except ValueError:
        raise OAuthExchangeError("Google's token response was not JSON.") from None
    if not isinstance(payload, dict):
        raise OAuthExchangeError("Google's token response was not an object.")
    return payload


async def _exchange_microsoft_code(
    *, code: str, client_id: str, client_secret: str, redirect_uri: str,
    code_verifier: str,
) -> dict[str, Any]:
    """Trades the authorization code for a refresh token.

    A module-level function for the same two reasons
    `_exchange_google_code` is one: a test can replace it without a
    network listener, and there is exactly one place where the token
    response exists. The caller keeps `refresh_token` and `scope` -- the
    access token in the same response is deliberately dropped on the
    floor.

    The request is form-encoded and the response is `application/json`,
    which is not the symmetry the form encoding suggests. `httpx`'s
    `.json()` does not care what the Content-Type header claims, so a
    `application/json; charset=utf-8` (which is what Microsoft actually
    sends) parses the same as a bare one.

    `code_verifier` is the PKCE half kept in the state store: without it
    Microsoft refuses the exchange, so an intercepted code is not
    redeemable anywhere but here.
    """
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.post(
            MICROSOFT_TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
                "code_verifier": code_verifier,
            },
        )
    if response.status_code >= 400:
        # The body may quote the client_secret back -- the status is the
        # only part of it that may ever reach a page or the audit log.
        raise OAuthExchangeError(
            f"Microsoft refused the code exchange (HTTP {response.status_code})."
        )
    try:
        payload = response.json()
    except ValueError:
        raise OAuthExchangeError("Microsoft's token response was not JSON.") from None
    if not isinstance(payload, dict):
        raise OAuthExchangeError("Microsoft's token response was not an object.")
    return payload


def _granted_google_scopes(
    payload: Mapping[str, Any], requested: Iterable[str]
) -> list[str]:
    """The scopes this grant actually covers.

    Google's token response carries a space-separated `scope` field, and
    it is the only authoritative answer: an operator may clear a checkbox
    on the consent screen, and the grant is then *narrower* than what the
    consent URL asked for. Storing what we asked for instead of what we
    got is exactly the bug this function exists to avoid -- a refresh may
    only ever request a subset of the grant, and Google answers anything
    wider with `invalid_scope`, refusing the refresh itself.

    The field is external input arriving through a token response, so it
    is treated like one: split on whitespace, each entry bounded in
    length, the list bounded in count, anything else dropped. When
    nothing usable comes back, the scopes the consent screen asked for
    stand in -- for a grant the operator did not narrow those are the
    same list, and they are ours, not Google's.
    """
    return _granted_scopes(payload, requested)


def _granted_scopes(
    payload: Mapping[str, Any], requested: Iterable[str]
) -> list[str]:
    """The `scope` field of a token response, read as the input it is.

    Split on whitespace, each entry bounded in length, the list bounded
    in count, duplicates dropped, anything that is not a string dropped
    whole. When nothing usable comes back the caller's requested list
    stands in -- it is ours rather than an absent third party's.

    Shared by both providers because the field is the same field: OAuth
    2.0 spells it this way and Google and Microsoft both send it.
    """
    raw = payload.get("scope")
    granted: list[str] = []
    if isinstance(raw, str):
        for scope in raw.split():
            if len(scope) > MAX_GOOGLE_SCOPE_CHARS or scope in granted:
                continue
            granted.append(scope)
            if len(granted) >= MAX_GOOGLE_SCOPES:
                break
    if granted:
        return granted
    return list(requested)


def _granted_microsoft_scopes(
    payload: Mapping[str, Any], requested: Iterable[str]
) -> list[str]:
    """`_granted_google_scopes` for Microsoft, plus one correction.

    Microsoft answers with the *resource* scopes it granted and leaves
    `offline_access` out of the list -- it is not a Graph permission, it
    is the instruction that produced the refresh token in the first
    place. Storing the response verbatim would therefore drop it, the
    next refresh would not ask for it, and Microsoft would stop returning
    a rotated refresh token: the credential would go quietly read-only on
    an expiry nobody scheduled.

    So the reserved OAuth/OIDC scopes the consent screen *asked* for are
    added back to whatever Microsoft named. They are not resources and
    cannot widen the grant -- a refresh asking for `offline_access` on a
    grant that has it is exactly the request Microsoft documents.
    """
    requested = list(requested)
    granted = _granted_scopes(payload, requested)
    for scope in requested:
        if scope in MICROSOFT_RESERVED_SCOPES and scope not in granted:
            granted.append(scope)
    return granted


def _microsoft_scope_urls(scopes: Iterable[str]) -> list[str]:
    """Bare names become Graph scope URLs; full URLs are left alone.

    `required_scopes: [Mail.Read]` and
    `required_scopes: [https://graph.microsoft.com/Mail.Read]` are the
    same request, the way `_google_scope_urls` makes them the same one
    provider over. `offline_access` and its OIDC siblings are passed
    through untouched -- they are not Graph resources, and
    `https://graph.microsoft.com/offline_access` is not a scope at all:
    Microsoft rejects the whole authorization request for it.
    """
    urls: list[str] = []
    for scope in scopes:
        scope = scope.strip()
        if not scope:
            continue
        if scope in MICROSOFT_RESERVED_SCOPES or "://" in scope:
            url = scope
        else:
            url = MICROSOFT_SCOPE_PREFIX + scope
        if url not in urls:
            urls.append(url)
    return urls


def _pkce_pair() -> tuple[str, str]:
    """A PKCE (verifier, S256 challenge) pair, RFC 7636 spelling.

    The verifier is 43-128 unreserved characters -- `token_urlsafe(48)`
    is 64 of them -- and the challenge is its SHA-256, base64url, without
    padding. Only the challenge is ever sent to the consent screen; the
    verifier stays in the state store until the callback redeems it.
    """
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def _microsoft_consent_url(
    *, client_id: str, redirect_uri: str, scopes: list[str], state: str,
    code_challenge: str,
) -> str:
    """Microsoft's consent screen URL for one flow.

    `offline_access` among the scopes is what makes Microsoft return a
    *refresh* token -- there is no `access_type=offline` here. `prompt=
    consent` forces the screen even for an already-granted client, for
    the same reason the google flow forces it: a re-authorization that
    silently returns an access token only is useless, because the
    executor has nothing to renew it with.

    `response_mode=query` keeps the code in the query string where the
    callback route reads it; the default for a code request is already
    `query`, and saying so is cheaper than depending on it.
    """
    query = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": " ".join(scopes),
            "state": state,
            "prompt": "consent",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{MICROSOFT_AUTH_ENDPOINT}?{query}"


@dataclasses.dataclass(frozen=True, slots=True)
class OAuthProviderSpec:
    """The parts of a sign-in flow that differ between providers.

    Two providers, one flow: every gate in `_oauth_authorize` and
    `_oauth_callback` -- session, role, state, single use, re-checked
    role, audited names only -- is the same question for Google and
    Microsoft, and only the endpoint, the spelling of a scope and a
    handful of words on the page are not. Those live here, so adding a
    third provider is a descriptor and two `if provider.key` arms rather
    than a third copy of the security-relevant half.

    `key` doubles as the executor name (`toolkit.executor == key` is how
    a credential is matched to its flow) and as the audit action prefix
    (`google_authorize`, `microsoft_callback`).
    """

    key: str
    label: str
    authorize_path: str
    callback_path: str
    default_scopes: tuple[str, ...]
    #: Where the operator registers the redirect URI, named the way that
    #: product names itself -- this is the one line that turns a
    #: `redirect_uri_mismatch` into an action.
    registration_console: str
    #: What that provider calls a redirect URI it does not recognise.
    mismatch_error: str
    #: Where an operator revokes an existing grant, when the provider
    #: returned no refresh token because one already exists.
    revoke_hint: str
    #: Whether the authorization request carries a PKCE challenge. The
    #: google pair predates PKCE and changing a working consent flow is
    #: not free; the microsoft one starts with it.
    uses_pkce: bool


GOOGLE_OAUTH = OAuthProviderSpec(
    key="google",
    label="Google",
    authorize_path=OAUTH_AUTHORIZE_PATH,
    callback_path=OAUTH_CALLBACK_PATH,
    default_scopes=DEFAULT_GOOGLE_SCOPES,
    registration_console="Google Cloud console",
    mismatch_error="redirect_uri_mismatch",
    revoke_hint="third-party connections",
    uses_pkce=False,
)

MICROSOFT_OAUTH = OAuthProviderSpec(
    key="microsoft",
    label="Microsoft",
    authorize_path=MICROSOFT_OAUTH_AUTHORIZE_PATH,
    callback_path=MICROSOFT_OAUTH_CALLBACK_PATH,
    default_scopes=DEFAULT_MICROSOFT_SCOPES,
    registration_console="Azure portal (App registrations -> Authentication)",
    mismatch_error="AADSTS50011",
    revoke_hint="app permissions at microsoft.com/consent",
    uses_pkce=True,
)


# -- Shared by both console surfaces -------------------------------------------


def oauth_credential_names(service: Any, provider: OAuthProviderSpec) -> list[str]:
    """The credential names this provider's toolkits point at (Tier 1)."""
    names: list[str] = []
    for toolkit in service.tier1.toolkits.values():
        if toolkit.executor == provider.key and toolkit.credential:
            if toolkit.credential not in names:
                names.append(toolkit.credential)
    return sorted(names)


def oauth_scopes(service: Any, provider: OAuthProviderSpec) -> list[str]:
    """Read at request time, not at startup: a toolkit added or narrowed by
    a redeploy changes the next consent screen without anything here to
    keep in step."""
    if provider.key == "microsoft":
        declared = service.tier1.microsoft_oauth_scopes()
        return _microsoft_scope_urls(declared or provider.default_scopes)
    declared = service.tier1.google_oauth_scopes()
    return _google_scope_urls(declared or provider.default_scopes)


def oauth_client(credentials: Any, name: str, provider: OAuthProviderSpec) -> tuple[str, str]:
    """client_id/client_secret out of the oauth2 credential.

    The one read of a credential value for sign-in. It never leaves this
    function's callers: the id goes into the consent URL (which is where
    the provider requires it), the secret goes into the token request body
    and nowhere else -- not into a page, not into the audit log, not into a
    process argument (FR-10.2/10.7).
    """
    resolved = credentials._resolve(name)
    if resolved is None:
        raise OAuthExchangeError(
            f"Credential {name!r} does not exist yet. Create it as kind "
            f"oauth2 with the client_id and client_secret of your "
            f"{provider.label} OAuth client first -- this page only adds "
            "the refresh token."
        )
    if resolved.kind != "oauth2":
        raise OAuthExchangeError(f"Credential {name!r} is kind {resolved.kind!r}, not oauth2.")
    try:
        bundle = json.loads(resolved.value)
    except (json.JSONDecodeError, TypeError):
        raise OAuthExchangeError(f"Credential {name!r} does not hold a JSON bundle.") from None
    client_id = bundle.get("client_id") if isinstance(bundle, dict) else None
    client_secret = bundle.get("client_secret") if isinstance(bundle, dict) else None
    if not client_id or not client_secret:
        raise OAuthExchangeError(f"Credential {name!r} is missing client_id/client_secret.")
    return str(client_id), str(client_secret)


PROVIDERS = {GOOGLE_OAUTH.key: GOOGLE_OAUTH, MICROSOFT_OAUTH.key: MICROSOFT_OAUTH}


#: Where an `/app`-started flow lands, with `?oauth=<result>&provider=&credential=`.
APP_RESULT_PATH = "/app/credentials"


def app_result_url(*, result: str, provider: str, credential: str) -> str:
    """The `/app` page an `/app`-started flow returns to. Only a result
    code and two names travel in the URL; the message for each code is the
    console's own text, so nothing a provider sent is reflected."""
    query = urllib.parse.urlencode(
        {"oauth": result, "provider": provider, "credential": credential}
    )
    return f"{APP_RESULT_PATH}?{query}"


# -- The callback (the one `/ui` path that outlives the HTML console) ---------


def build_callback_routes(
    *, identities: Any, audit: Any, store: Any, credentials: Any,
    states: OAuthStateStore,
) -> list[Any]:
    """`/ui/oauth/{google,microsoft}/callback`.

    The paths stay where 0.x registered them, because they are the
    redirect URIs operators entered at Google and Microsoft; moving them
    would break every OAuth client already set up. Everything else about
    the route is the console API's: the flow is started by `POST
    /api/v1/oauth/<provider>/authorize`, the state carries who started it
    (the API's session cookie is scoped to `/api/v1` and never reaches
    this path), and the answer is always a redirect to
    `/app/credentials` with a result code -- never a page, never anything
    the provider sent.
    """
    from starlette.responses import RedirectResponse, Response
    from starlette.routing import Route

    from .credentials import WriteRefused as CredentialWriteRefused
    from .errors import ConfigError
    from .identity import ADMIN_ROLE

    async def callback(request: Request, provider: OAuthProviderSpec) -> Response:
        pending_state = states.take(request.query_params.get("state", ""))
        if pending_state is not None and pending_state.provider != provider.key:
            # One state store, two flows: a state minted for the other
            # provider is spent here (`take` popped it) and redeems nothing.
            pending_state = None
        if pending_state is None:
            audit.write({
                "kind": "ui_oauth", "actor": "",
                "action": f"{provider.key}_callback", "result": "state_mismatch",
            })
            return RedirectResponse(
                app_result_url(result="state_mismatch", provider=provider.key, credential=""),
                status_code=303,
            )

        actor = pending_state.identity
        name = pending_state.credential

        def _fail(result: str, *, detail: str = "") -> Response:
            record: dict[str, Any] = {
                "kind": "ui_oauth", "actor": actor,
                "action": f"{provider.key}_callback", "result": result, "credential": name,
            }
            if detail:
                record["detail"] = detail
            audit.write(record)
            return RedirectResponse(
                app_result_url(result=result, provider=provider.key, credential=name),
                status_code=303,
            )

        # The state was issued to an admin; between then and now that
        # identity could have been demoted or deleted.
        current = identities.identities.get(actor)
        if current is None or current.role != ADMIN_ROLE:
            return _fail("role_required")
        # The provider's own refusal, truncated: their text arriving
        # through a URL goes to the audit log only, never back to the page.
        denial = request.query_params.get("error", "").strip()[:64]
        if denial:
            return _fail("denied", detail=denial)
        code = request.query_params.get("code", "")
        if not code:
            return _fail("no_code")
        if store is None or credentials is None:
            return _fail("read_only")
        try:
            client_id, client_secret = oauth_client(credentials, name, provider)
        except OAuthExchangeError:
            return _fail("credential_unusable")
        try:
            if provider.key == "microsoft":
                payload = await _exchange_microsoft_code(
                    code=code, client_id=client_id, client_secret=client_secret,
                    redirect_uri=pending_state.redirect_uri,
                    code_verifier=pending_state.code_verifier,
                )
            else:
                payload = await _exchange_google_code(
                    code=code, client_id=client_id, client_secret=client_secret,
                    redirect_uri=pending_state.redirect_uri,
                )
        except (OAuthExchangeError, httpx.HTTPError):
            return _fail("exchange_failed")

        refresh_token = payload.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            # Omitted when the client was already granted these scopes and
            # the request did not force a fresh consent.
            return _fail("no_refresh_token")

        # The grant's scopes travel with the refresh token, because a
        # refresh asks for exactly these again (tests/test_google_token_scopes.py).
        if provider.key == "microsoft":
            scopes = _granted_microsoft_scopes(payload, pending_state.scopes)
        else:
            scopes = _granted_google_scopes(payload, pending_state.scopes)
        bundle_fields: dict[str, Any] = {
            "client_id": client_id, "client_secret": client_secret,
            "refresh_token": refresh_token, "scopes": scopes,
        }
        # `provider` marks a non-Google bundle, so a toolkit pointed at the
        # wrong platform fails with a reason (`service._oauth_token_env`).
        if provider.key != "google":
            bundle_fields["provider"] = provider.key
        bundle = json.dumps(bundle_fields)
        existing = {meta.name for meta in credentials.names()}
        try:
            if name in existing:
                credentials.rotate(name, value=bundle, actor=actor, rev=credentials.revision())
            else:
                credentials.create(
                    name, kind="oauth2", value=bundle, actor=actor, rev=credentials.revision(),
                )
        except (CredentialWriteRefused, ConfigError):
            return _fail("write_refused")

        # Scope names only: no token material.
        audit.write({
            "kind": "ui_oauth", "actor": actor, "action": f"{provider.key}_callback",
            "result": "ok", "credential": name, "scopes": scopes,
        })
        return RedirectResponse(
            app_result_url(result="ok", provider=provider.key, credential=name), status_code=303,
        )

    async def google(request: Request) -> Response:
        return await callback(request, GOOGLE_OAUTH)

    async def microsoft(request: Request) -> Response:
        return await callback(request, MICROSOFT_OAUTH)

    return [
        Route(GOOGLE_OAUTH.callback_path, google, methods=["GET"]),
        Route(MICROSOFT_OAUTH.callback_path, microsoft, methods=["GET"]),
    ]
