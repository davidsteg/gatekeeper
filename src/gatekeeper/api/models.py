"""Pydantic response models -- the security boundary for API output.

FastAPI serialises every response through its declared model and drops
any field the model does not name. That makes these classes the place
where "what may leave the process" is decided, not the handlers: a
credential model with no value field cannot emit a value, an identity
model with no hash field cannot emit a hash, however the dict feeding it
was built (FR-10.2, FR-11.5).

Free-form `dict[str, Any]` appears only where the legacy console already
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
