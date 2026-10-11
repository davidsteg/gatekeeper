"""Pydantic response models -- the security boundary for API output.

FastAPI serialises every response through its declared model and drops
any field the model does not name. That makes these classes the place
where "what may leave the process" is decided, not the handlers: a
credential model with no value field cannot emit a value, an identity
model with no hash field cannot emit a hash, however the dict feeding it
was built (FR-10.2, FR-11.5).

Free-form `dict[str, Any]` appears only where the console deliberately
shows the data verbatim to a viewer: audit records (redacted at write
time by `audit.Redactor`), a pending item's payload, a tool's spec.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Problem(_Model):
    """Every error body: one human-readable sentence."""

    error: str


# -- Session -----------------------------------------------------------------


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity: str = Field(max_length=256)
    password: str = Field(max_length=4096)


class SessionInfo(_Model):
    identity: str
    role: str
    #: `admin` and a writable configuration -- what the SPA uses to hide
    #: write controls. The server checks again on every write.
    can_write: bool
    #: The console runs without writable Tier 2 (`--ui-read-only` /
    #: `GATEKEEPER_UI_READ_ONLY`).
    read_only: bool
    #: Echo in `X-CSRF-Token` on every mutating request.
    csrf: str
    version: str


class Account(_Model):
    identity: str
    role: str
    can_change_password: bool


# -- Overview ------------------------------------------------------------------


class CallCounts(_Model):
    ok: int = 0
    denied: int = 0
    failed: int = 0
    total: int = 0


class OverviewStats(_Model):
    tools_active: int
    identities: int
    protected_resources: int
    tools_disabled: int


class Outcomes(CallCounts):
    error_rate: int
    success_pct: int


class ActivityBucket(_Model):
    #: Start of the hour, ISO 8601 with offset, container-local time.
    hour: str
    ok: int
    not_ok: int


class Notices(_Model):
    unwritable: list[str]
    disabled_by_tier1: list[str]
    pending_changes: int
    pending_toolkits: int
    no_toolkits: bool
    empty_catalog: bool


class MatrixColumn(_Model):
    name: str
    executor: str


class MatrixCell(_Model):
    toolkit: str
    granted: list[str]
    calls: CallCounts


class MatrixRow(_Model):
    identity: str
    role: str
    tool_count: int
    cells: list[MatrixCell]


class AccessMatrix(_Model):
    toolkits: list[MatrixColumn]
    rows: list[MatrixRow]
    hot_threshold: int


class Overview(_Model):
    stats: OverviewStats
    outcomes: Outcomes
    events_logged: int
    activity: list[ActivityBucket]
    recent: list[dict[str, Any]]
    notices: Notices
    access: AccessMatrix


# -- Tools -----------------------------------------------------------------------


class ToolParameter(_Model):
    name: str
    type: str
    description: str
    required: bool
    derived: str | None
    pattern: str | None
    values: list[str]
    minimum: int | None
    maximum: int | None


class Tool(_Model):
    id: str
    toolkit: str
    destination: str | None
    version: int
    title: str
    description: str
    category: str
    idempotent: bool
    enabled: bool
    required_scopes: list[str]
    timeout_seconds: int
    max_output_bytes: int
    parameters: list[ToolParameter]
    grantees: list[str]


class RejectedTool(_Model):
    id: str
    reason: str


class ToolList(_Model):
    tools: list[Tool]
    rejected: list[RejectedTool]
    disabled_by_tier1: list[str]
    toolkits: list[MatrixColumn]


class ToolVersion(_Model):
    version: int | None
    created_at: str | None
    created_by: str | None
    superseded: bool | None


class ToolDetail(_Model):
    id: str
    enabled: bool
    current_version: int | None
    versions: list[ToolVersion]
    spec: dict[str, Any]
    yaml: str
    #: The concrete, grantable tools this definition expands to -- one, or
    #: one per destination (FR-8.3h).
    tools: list[Tool]


class IntegrationTool(_Model):
    id: str
    category: str
    description: str
    exists: bool
    #: The definition as YAML, for pre-filling the new-tool editor. It is
    #: saved through the same `POST /tools` as a hand-written one.
    yaml: str


class Integration(_Model):
    key: str
    display_name: str
    notes: str
    credential_kind: str
    toolkit_configured: bool
    tools: list[IntegrationTool]


# -- Identities --------------------------------------------------------------------


class IdentityOut(_Model):
    """No `token_hash`, no `password_hash`, no `token_lookup` -- by
    construction, not by omission."""

    id: str
    role: str
    tools: list[str]
    scopes: list[str]
    console: Literal["access", "no_password", "api_only"]
    unknown_tools: list[str]


# -- Credentials ---------------------------------------------------------------------


class CredentialMeta(_Model):
    """Metadata only (FR-10.2). There is no field a value could ride in."""

    name: str
    kind: str
    header: str | None
    created_at: str
    rotated_at: str | None
    in_overlap: bool
    used_by: list[str]
    probe_url: str | None
    probe_status: str
    probe_checked_at: str | None
    suspect_status: str | None
    suspect_at: str | None


class CredentialList(_Model):
    #: False when no master key is configured -- the store does not exist.
    configured: bool
    credentials: list[CredentialMeta]
    #: Credential names a toolkit or destination refers to that the store
    #: does not hold (a startup warning, not an abort).
    dangling: list[str]


# -- Toolkits (read-only, FR-4.11) -------------------------------------------------------


class ToolkitOut(_Model):
    name: str
    executor: str
    binaries: list[str]
    denied_args: list[str]
    path_roots: list[str]
    protected_resources: list[str]
    max_timeout_seconds: int
    max_output_bytes: int
    destinations: list[str]
    target: str
    credential: str | None
    run_as: str | None
    mailbox_path: str | None
    allowed_agent_operations: list[str]


class ToolkitList(_Model):
    toolkits: list[ToolkitOut]
    destinations: list[str]


class ToolkitReference(_Model):
    key: str
    display_name: str
    notes: str
    toolkit_yaml: str


# -- Requests -------------------------------------------------------------------------------


class ReviewTool(_Model):
    id: str
    #: "+" added, "-" removed, "" neither (a `grant_set` diff).
    marker: str
    state: Literal["enabled", "disabled", "missing"]
    title: str
    category: str


class PendingReview(_Model):
    """What to judge a proposal by, as plain text and data -- rendered as
    text, never as markup."""

    headline: str
    tools: list[ReviewTool]
    #: Unchanged grants in a `grant_set` diff (those not listed in `tools`).
    unchanged: int
    #: Why a `stale` item can no longer be applied.
    stale: str | None


class PendingItem(_Model):
    id: str
    action: str
    actor: str
    payload: dict[str, Any]
    base_rev: str
    status: str
    created_at: str
    decided_by: str | None
    decided_at: str | None
    reason: str | None
    review: PendingReview


class PendingPage(_Model):
    """Decided proposals, newest decision first."""

    entries: list[PendingItem]
    #: Pass as `cursor` for the next, older page; null on the last one.
    next_cursor: str | None
    #: Decided proposals in all, across every page.
    total: int


class ToolkitProposalOut(_Model):
    id: str
    name: str
    spec: dict[str, Any]
    actor: str
    kind: str
    status: str
    created_at: str
    decided_by: str | None
    decided_at: str | None
    reason: str | None
    current: ToolkitOut | None
    #: What deploying writes into toolkits.yaml ("" for delete and bind).
    spec_yaml: str


# -- Writes ------------------------------------------------------------------------------
#
# Request bodies forbid unknown fields: a typo in a field name is an error,
# not a silently ignored edit.


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Written(_Model):
    """What every write answers: the store's revision after the write, the
    `If-Match` for the next one (also sent as `ETag`)."""

    revision: str


class ToolScaffold(_Model):
    yaml: str


class ToolWrite(_Body):
    #: One tool definition as YAML, exactly what the editor shows.
    yaml: str = Field(max_length=262144)


class ToolSaved(Written):
    id: str


class ToolEnabled(_Body):
    enabled: bool


class IdentityWrite(_Body):
    id: str = Field(max_length=64)
    role: str = Field(max_length=32)
    tools: list[str] = Field(default_factory=list, max_length=4096)
    scopes: list[str] = Field(default_factory=list, max_length=1024)
    #: Optional console password. Empty means "leave as is" on an update.
    password: str = Field("", max_length=4096)


class TokenIssued(Written):
    """The only response that carries a secret: the new API token, shown
    once. It is never stored in plaintext and never readable again."""

    identity: str
    token: str


class CredentialCreate(_Body):
    name: str = Field(max_length=128)
    kind: str = Field(max_length=32)
    header: str | None = Field(None, max_length=256)
    value: str = Field(max_length=65536)
    probe_url: str | None = Field(None, max_length=2048)


class CredentialRotate(_Body):
    value: str = Field(max_length=65536)
    overlap_seconds: int = Field(0, ge=0, le=366 * 24 * 3600)


class PasswordChange(_Body):
    current: str = Field(max_length=4096)
    password: str = Field(max_length=4096)


class RejectBody(_Body):
    reason: str = Field("", max_length=240)


class CredentialFill(_Body):
    """The value for an agent's `cred_propose`: the agent proposes the
    name and kind, only a human ever types the secret."""

    value: str = Field(max_length=65536)


class ApproveAll(_Body):
    #: Exactly the proposals the reviewer saw. One filed after the page
    #: loaded is not in this list and stays pending.
    ids: list[str] = Field(max_length=1000)


class Refusal(_Model):
    id: str
    action: str
    reason: str


class ApproveAllResult(_Model):
    applied: int
    refused: list[Refusal]


class DeployBody(_Body):
    #: Must be true: deploying changes Tier 1 at once, with no further
    #: review, and the client has to say it showed that.
    confirm: Literal[True]


class Decided(_Model):
    id: str
    status: str


# -- Stats, docs, OAuth -------------------------------------------------------------------


class StatsWindow(_Model):
    key: str
    label: str


class StatsPoint(_Model):
    #: Start of the hour (24 h) or day, ISO 8601 with offset.
    start: str
    ok: int
    not_ok: int


class StatsTotals(CallCounts):
    error_rate: int


class StatsRow(CallCounts):
    name: str


class AdminCount(_Model):
    action: str
    count: int


class Latency(_Model):
    toolkit: str
    avg_ms: int
    p95_ms: int
    count: int


class Stats(_Model):
    window: str
    label: str
    windows: list[StatsWindow]
    truncated: bool
    totals: StatsTotals
    success_rate: int
    active_identities: int
    active_toolkits: int
    admin_total: int
    series: list[StatsPoint]
    toolkits: list[StatsRow]
    identities: list[StatsRow]
    admin: list[AdminCount]
    latency: list[Latency]


class DocEntry(_Model):
    slug: str
    label: str
    available: bool


class Doc(_Model):
    slug: str
    label: str
    #: Markdown source; the console renders it as elements, never as HTML.
    text: str


class OAuthProvider(_Model):
    key: str
    label: str
    #: The credentials this provider's toolkits name (Tier 1).
    credentials: list[str]
    callback_path: str


class OAuthStartBody(_Body):
    #: Which credential to fill; may be empty when the toolkits name one.
    credential: str = Field("", max_length=128)


class OAuthStart(_Model):
    """Everything the connect page shows. No client secret, no token."""

    provider: str
    label: str
    credential: str
    consent_url: str
    callback_uri: str
    scopes: list[str]
    registration_console: str
    mismatch_error: str


# -- Audit / release notes -----------------------------------------------------------------


class AuditPage(_Model):
    entries: list[dict[str, Any]]
    next_cursor: str | None
    window_truncated: bool


class ReleaseNote(_Model):
    version: str
    notes: str


class ReleaseNotes(_Model):
    version: str
    releases: list[ReleaseNote]
    total: int
