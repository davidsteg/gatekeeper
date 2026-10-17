"""The toolkit-proposal queue for the `admin.*` MCP surface (plan
"Follow-up 2": let Hermes draft toolkits, with a one-click human deploy).

A toolkit proposal is a categorically different severity of change from
anything in `pending.py`: Tier 1 (`toolkits.yaml`) is what makes the admin
token *not* equivalent to root (REQUIREMENTS.md §6) -- it defines what is
possible at all, not merely who may do what. This is deliberately its own
file (`toolkit_proposals.yaml`) and its own store, never `PendingStore`, so
a toolkit proposal can never be routed through the same approval surface as
an ordinary tool/grant change, and so `EXPOSED_ACTIONS`/`admin_server.py`'s
drift-check has one fewer place to accidentally expose `deploy`/`reject`
from `/admin/mcp`.

Four proposal ``kind``s share this one queue and one review surface
(`/app/requests`, Toolkit tab), because all four change Tier 1 and none may
ever be reachable through `pending.yaml`'s Tier-2-shaped review path:

- ``"create"`` (`admin.toolkit_propose`) -- drafts a brand-new toolkit.
  ``spec`` is the toolkit's full body; the name must not already exist,
  checked when it is proposed and again at deploy.
- ``"update"`` (`admin.toolkit_update`) -- narrowly-scoped edits to an
  *existing* toolkit's ``executor``/``binaries``/``denied_args``/``run_as``
  and, since 1.10.0, an http/opencode toolkit's ``allowed_hosts``/
  ``allowed_cidrs`` only (``UPDATE_WRITABLE_FIELDS``); ``spec`` holds just the changed fields,
  merged into the toolkit's existing body at deploy time. Every other Tier 1
  field (``path_roots``, ``protected_resources``, limits) stays reachable
  only by a redeploy -- this exists so an executor swap (e.g. `local` ->
  `file`) or a change of the OS user a `file` toolkit runs as doesn't
  require one, not to open a general editing surface. Until 1.10.0 the line
  it held was *reach*: a proposal could change who an operation runs as,
  never where it may go. The two network fields moved that line on purpose
  (see ``UPDATE_WRITABLE_FIELDS``); ``path_roots`` and
  ``protected_resources`` still sit behind it.
- ``"delete"`` (`admin.toolkit_delete`) -- removes an *existing* toolkit.
  ``spec`` is always empty; the name must already exist and, at deploy
  time, must not still be referenced by any non-deleted tool (deleting a
  toolkit out from under a live tool is exactly the "way to bring the
  service down" `catalog.parse_tool_spec` guards against).
- ``"bind"`` (`admin.credential_bind`) -- points an *existing* toolkit at a
  *named* credential slot. ``spec`` is exactly ``{"credential": <name>}``
  and nothing else: a name, never a value, never a destination-level
  override, never a `path_roots`/limits field. FR-10.4 makes the
  toolkit->credential *binding* Tier 1 ("only changeable via redeploy")
  precisely so an admin agent cannot redirect a toolkit at a credential of
  its choosing; what this kind relaxes is the *redeploy*, not the
  human -- the agent may only ever queue the name pair here, and only a
  human clicking Approve & Deploy at `/app/requests` writes it, exactly as
  `"update"` relaxed the redeploy for an executor swap. The value side
  (FR-10.2/10.8) is untouched: no secret material passes through this
  queue in either direction.

`deploy` is the only function that ever writes `toolkits.yaml`:

1. Reads the live file. For ``"create"``, merges the proposed toolkit in
   under its name, which must not collide with an existing one. For
   ``"update"``, merges the proposed fields into the *existing* toolkit's
   body, which must already exist. For ``"delete"``, removes the named
   toolkit's key entirely, refusing if any non-deleted tool still
   references it. For ``"bind"``, sets the *existing* toolkit's
   ``credential:`` to the proposed name.
2. Writes the merged content to a temp file and validates it with the exact
   `load_tier1()` startup uses. Nothing real is touched if this fails. A
   ``"bind"`` additionally re-reads the binding back out of that validated
   Tier 1 through `Tier1.credential_references()` -- the same walk startup
   and the console use -- so a binding that parsed but did not actually
   land is caught before the real file is written.
3. Only then: atomically writes the real file (`_atomic.py`, the same
   primitives `store.py`/`pending.py` use).
4. Calls `Service.reload_config(...)` synchronously, in-process -- the same
   function the existing SIGHUP handler already calls, so the change is
   live with no restart. If it errors (defensive only: step 2 already
   validated the exact bytes just written), the proposal is left `pending`
   and the failure is surfaced -- not silently swallowed.
5. Audits before/after state, marks the proposal `deployed`.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import secrets
import socket
import tempfile
import threading
from typing import Any
from urllib.parse import urlsplit

from ._atomic import atomic_write as _atomic_write
from ._atomic import dump as _dump
from ._atomic import load_cached as _load_cached
from ._atomic import revision as _revision
from ._atomic import safe_load as _yaml_load
from ._atomic import writable as _writable
from ._runas import RunAsError, parse_run_as
from .audit import AuditLog
from .catalog import now_iso
from .errors import ConfigError
from .service import Service
from .tier1 import (
    NETWORK_EXECUTORS,
    _parse_network_allowlist,
    is_public_address,
    load_tier1,
)

#: What a toolkit proposal may be in. No 'stale' state: unlike `pending.py`,
#: `deploy` re-validates the *entire* merged configuration fresh at deploy
#: time (not just a revision fingerprint) -- a moved toolkits.yaml simply
#: surfaces as a collision or a Tier-1 validation error instead.
#: ``"withdrawn"`` is the proposer taking its own proposal back
#: (`withdraw`) -- not a decision, so it is kept apart from ``"rejected"``.
STATUSES = frozenset({"pending", "deployed", "rejected", "withdrawn"})

#: The four shapes a proposal can take -- see the module docstring.
KINDS = frozenset({"create", "update", "delete", "bind"})

#: The one and only field a `"bind"` proposal carries. Not folded into
#: `UPDATE_WRITABLE_FIELDS`: `admin.toolkit_update` takes a free-form
#: `updates` mapping, so adding `credential` there would let one proposal
#: swap an executor *and* redirect the credential in a single card, which
#: is the combination FR-10.4 is least willing to see reviewed at a glance.
#: A bind is its own kind so its card says exactly one thing -- this
#: toolkit, that credential name -- and a reviewer can check that one claim.
BIND_FIELD = "credential"

#: Fields `"update"`-kind proposals may change. Everything else
#: (`path_roots`, `protected_resources`, limits) stays deploy-time only
#: (FR-4.11) -- checked both at `propose()` (immediate feedback to the
#: agent) and again at `deploy()` (the authoritative gate; `propose()`'s
#: check is not itself a security boundary since nothing has been written
#: yet either way).
#:
#: `run_as` is here as of 0.29.0. 0.28.0 introduced it as redeploy-only and
#: refused it in every proposal, on the grounds that it decides *with whose
#: authority* an operation runs rather than what is allowed. What that ban
#: did not survive is that it was bypassable in two steps: a `"create"`
#: proposal already carries a toolkit's *full* body, `path_roots` included,
#: so an agent could propose a broad `file` toolkit and then update it --
#: the ban cost friction and bought no boundary. The boundary that does
#: hold is the one below it in the stack: `run_as` only does anything if
#: the *container* was started privileged enough to change user
#: (`CAP_SETUID`/`CAP_SETGID`, docs/DEPLOYMENT.md), and no proposal can
#: reach that decision. On a deployment that never granted it, a deployed
#: `run_as` makes calls fail rather than escalate.
#:
#: What still requires a redeploy is what a `run_as` can be *pointed at*:
#: `path_roots` and `protected_resources` stay out of this set, so a
#: proposal can change who an operation runs as but never widen where it
#: may reach.
#:
#: `allowed_hosts` and `allowed_cidrs` are here as of 1.10.0, and they are
#: the first fields in this set that change *where* a toolkit may connect.
#: That is a deliberate move of the line above, asked for by the operator:
#: a public API whose addresses drift (api.github.com) otherwise needs a
#: host-side file edit every time it moves. What keeps it safe is what
#: keeps every other update safe -- nothing applies without a human
#: approving the card at /app/requests -- plus what no proposal can lift:
#: `allowed_hosts` takes exact names only (no wildcard, no IP literal), and
#: a hostname toolkit never reaches a non-public address, whatever its
#: `allowed_cidrs` say. Only on toolkits whose executor reads them
#: (`NETWORK_FIELDS`, checked at deploy).
#:
#: 1.11.0 adds an http toolkit's `allowed_methods`/`allowed_path_prefixes`
#: and the two ceilings (`max_timeout_seconds`, `max_output_bytes`), on the
#: same terms: always a human-approved card, the card shows the current
#: value next to the proposed one, and `load_tier1` re-validates the whole
#: merged file before anything is written. `path_roots` and
#: `protected_resources` remain redeploy-only.
UPDATE_WRITABLE_FIELDS = frozenset(
    {
        "executor", "binaries", "denied_args", "run_as",
        "allowed_hosts", "allowed_cidrs",
        "allowed_methods", "allowed_path_prefixes",
        "max_timeout_seconds", "max_output_bytes",
    }
)

#: The update fields that change a toolkit's network reach -- valid only on
#: an executor that connects to a URL (`tier1.NETWORK_EXECUTORS`).
NETWORK_FIELDS = frozenset({"allowed_hosts", "allowed_cidrs"})

#: Executor-specific update fields and the executors that read them. A
#: field outside its executors would be silently ignored by `load_tier1`
#: (it parses only what an executor uses), so `deploy()` refuses it rather
#: than writing a restriction that does not exist.
FIELD_EXECUTORS: dict[str, frozenset[str]] = {
    "allowed_hosts": NETWORK_EXECUTORS,
    "allowed_cidrs": NETWORK_EXECUTORS,
    "allowed_methods": frozenset({"http"}),
    "allowed_path_prefixes": frozenset({"http"}),
}

#: The two ceilings. Positive integers; `load_tier1` enforces the same.
LIMIT_FIELDS = frozenset({"max_timeout_seconds", "max_output_bytes"})

#: A proposed CIDR wider than this (an IPv4 network shorter than /16, an
#: IPv6 one shorter than /48) needs `confirm_broad_cidrs: true` on the
#: proposal. A /8 almost never describes "the one service this toolkit
#: talks to" (FR-8.15); the flag makes the agent say it means it, and the
#: review card shows it in red.
BROAD_PREFIX = {4: 16, 6: 48}

#: Audit `action` names, keyed by `kind` -- one for `propose()`, one for
#: `deploy()`.
_PROPOSE_ACTION_NAMES = {
    "create": "toolkit_propose",
    "update": "toolkit_update_propose",
    "delete": "toolkit_delete_propose",
    "bind": "credential_bind_propose",
}
_DEPLOY_ACTION_NAMES = {
    "create": "toolkit_deploy",
    "update": "toolkit_update_deploy",
    "delete": "toolkit_delete_deploy",
    "bind": "credential_bind_deploy",
}


class ToolkitProposalWriteRefused(ConfigError):
    """A toolkit-proposal write was refused -- with a human-readable reason."""


def name_collision_message(name: str) -> str:
    """Why a ``"create"`` proposal for an existing toolkit name is refused.

    One text for both places that refuse it: `propose()`, so the agent
    learns now and nothing reaches the review queue, and `deploy()`, for a
    name that a redeploy added while the proposal was waiting. It names
    both ways forward, because "pick another name" is only right when a
    second toolkit was the goal -- a fix to the existing one goes through
    an update proposal or, for the fields that have none, the file itself.
    """
    return (
        f"A toolkit named {name!r} already exists in toolkits.yaml -- a "
        "'create' proposal only adds a new toolkit, and deploying this one "
        "would silently overwrite it. If a second, separate toolkit is "
        "what you want, propose it under a different name. If you meant to "
        "change the existing one: executor, binaries, denied_args, run_as, "
        "allowed_hosts, allowed_cidrs, allowed_methods, allowed_path_prefixes "
        "and the two limits go through admin.toolkit_update; path_roots and "
        "protected_resources have no proposal path -- edit "
        "toolkits.yaml and reload (SIGHUP or restart)."
    )


def _tools_referencing_toolkit(tools_path: str, toolkit_name: str) -> set[str]:
    """Tool ids in `tools_path` whose `toolkit` field is `toolkit_name` and
    which are not soft-deleted (`store.py`'s `ConfigStore.delete_tool`) --
    the set `deploy()` must refuse a `"delete"` proposal over, since
    `catalog.parse_tool_spec` treats a dangling `toolkit` reference as a
    Tier 1 violation, not a syntax error.
    """
    if not os.path.exists(tools_path):
        return set()
    with open(tools_path, encoding="utf-8") as handle:
        raw = _yaml_load(handle.read()) or {}
    entries = raw.get("tools")
    if not isinstance(entries, list):
        return set()
    return {
        str(entry.get("id"))
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("toolkit") == toolkit_name
        and not entry.get("deleted", False)
    }


def _resolve_addresses(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address `host` resolves to right now; empty when it does not
    resolve. A module function so tests can pin the answer."""
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        return [literal]
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return [ipaddress.ip_address(str(info[4][0]).split("%", 1)[0]) for info in infos]


def _check_network_policy(
    body: dict[str, Any], *, confirm_broad: bool, where: str, destination_urls: list[str]
) -> None:
    """The two rules a proposed `allowed_cidrs` must meet, beyond shape.

    1. No network wider than `BROAD_PREFIX` without `confirm_broad_cidrs`.
    2. No private, loopback, link-local or otherwise non-public network on
       a toolkit whose target is external -- a `base_url` (or destination)
       whose host is, or right now resolves to, a public address. A private
       range there would let a rebinding answer for a public name reach
       the LAN; a LAN service is the only reason to allow one, and its
       name resolves privately. A host that does not resolve at all is not
       judged here: it cannot be connected to either.

    Applied to proposals only (create and update), at submit and again at
    deploy. `load_tier1` does not run it, so toolkits written by hand --
    and every one deployed before 1.11.0 -- load unchanged.
    """
    cidrs = body.get("allowed_cidrs") or []
    if not isinstance(cidrs, list):
        return  # load_tier1 reports the shape
    networks = []
    for raw in cidrs:
        try:
            networks.append(ipaddress.ip_network(str(raw), strict=False))
        except ValueError:
            return  # load_tier1 reports the bad entry
    broad = [str(n) for n in networks if n.prefixlen < BROAD_PREFIX[n.version]]
    if broad and not confirm_broad:
        raise ToolkitProposalWriteRefused(
            f"{where}: allowed_cidrs {broad} are wider than /16 (IPv4) or "
            "/48 (IPv6). Narrow them to the service's own range, or propose "
            "again with confirm_broad_cidrs: true if this width is intended "
            "-- the reviewer then sees it flagged."
        )
    private = [str(n) for n in networks if not _network_is_public(n)]
    if not private:
        return
    urls = [u for u in [body.get("base_url"), *destination_urls] if isinstance(u, str)]
    for url in urls:
        host = urlsplit(url).hostname or ""
        if not host:
            continue
        addresses = _resolve_addresses(host)
        if addresses and all(is_public_address(a) for a in addresses):
            raise ToolkitProposalWriteRefused(
                f"{where}: allowed_cidrs {private} are private or otherwise "
                f"non-public networks, but this toolkit's target {host!r} is "
                "a public address. A private range is only for a LAN "
                "service; for a public one, list its public range or use "
                "allowed_hosts."
            )


def _network_is_public(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """A network counts as public when both its ends are public addresses."""
    return is_public_address(network.network_address) and is_public_address(
        network.broadcast_address
    )


@dataclasses.dataclass(frozen=True, slots=True)
class ToolkitProposal:
    id: str
    #: The toolkit's name -- the key it would get (or already has) under
    #: `toolkits:` in toolkits.yaml.
    name: str
    #: For `kind="create"`: the toolkit's full body (executor, binaries,
    #: path_roots, ...) -- exactly what would sit under `toolkits.<name>:`.
    #: For `kind="update"`: just the changed fields, a subset of
    #: `UPDATE_WRITABLE_FIELDS`, merged into the existing toolkit's body
    #: at deploy time.
    spec: dict[str, Any]
    actor: str
    #: `"create"` (default, backward-compatible with proposals written
    #: before this field existed) or `"update"` -- see the module docstring.
    kind: str = "create"
    status: str = "pending"
    created_at: str = ""
    decided_by: str | None = None
    decided_at: str | None = None
    reason: str | None = None
    #: The proposer's explicit "yes, this wide" for a CIDR broader than
    #: `BROAD_PREFIX` (see `_check_network_policy`). Not part of `spec`:
    #: it is said about the proposal, never written to toolkits.yaml.
    confirm_broad_cidrs: bool = False

    def to_spec(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "spec": self.spec,
            "actor": self.actor,
            "kind": self.kind,
            "status": self.status,
            "created_at": self.created_at,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "reason": self.reason,
            "confirm_broad_cidrs": self.confirm_broad_cidrs,
        }


def _from_spec(spec: dict[str, Any]) -> ToolkitProposal:
    return ToolkitProposal(
        id=str(spec.get("id")),
        name=str(spec.get("name")),
        spec=dict(spec.get("spec") or {}),
        actor=str(spec.get("actor")),
        kind=str(spec.get("kind") or "create"),
        status=str(spec.get("status") or "pending"),
        created_at=str(spec.get("created_at") or ""),
        decided_by=spec.get("decided_by"),
        decided_at=spec.get("decided_at"),
        reason=spec.get("reason"),
        confirm_broad_cidrs=bool(spec.get("confirm_broad_cidrs", False)),
    )


@dataclasses.dataclass(slots=True)
class ToolkitProposalStore:
    """Owns `toolkit_proposals.yaml` and is the only writer of the real
    `toolkits.yaml` outside of a deploy-time redeploy (see module docstring).
    """

    path: str
    audit: AuditLog
    service: Service
    toolkits_path: str
    tools_path: str
    identities_path: str
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    def revision(self) -> str:
        return _revision(self.path)

    def _load(self) -> list[dict[str, Any]]:
        raw = _load_cached(self.path) or {}
        entries = raw.get("proposals")
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise ConfigError(
                "toolkit_proposals.yaml: section 'proposals' is missing or not a list"
            )
        return [e for e in entries if isinstance(e, dict)]

    def _write(self, entries: list[dict[str, Any]]) -> None:
        _atomic_write(self.path, _dump({"proposals": entries}))

    # -- Reads ---------------------------------------------------------------

    def list(self, *, status: str | None = None) -> list[ToolkitProposal]:
        items = [_from_spec(e) for e in self._load()]
        items.sort(key=lambda i: i.created_at)
        if status:
            items = [i for i in items if i.status == status]
        return items

    def get(self, proposal_id: str) -> ToolkitProposal | None:
        for entry in self._load():
            if entry.get("id") == proposal_id:
                return _from_spec(entry)
        return None

    # -- Writes ----------------------------------------------------------------

    def propose(
        self, *, name: str, spec: dict[str, Any], actor: str, kind: str = "create",
        confirm_broad_cidrs: bool = False,
    ) -> ToolkitProposal:
        if not name or not isinstance(name, str):
            raise ToolkitProposalWriteRefused(
                "A toolkit proposal needs a non-empty 'name'."
            )
        if kind not in KINDS:
            raise ToolkitProposalWriteRefused(f"Unknown proposal kind {kind!r}.")
        if kind == "update":
            if not spec:
                raise ToolkitProposalWriteRefused(
                    "An update proposal needs at least one changed field."
                )
            illegal = set(spec) - UPDATE_WRITABLE_FIELDS
            if illegal:
                raise ToolkitProposalWriteRefused(
                    f"Cannot propose changing {sorted(illegal)} -- only "
                    f"{sorted(UPDATE_WRITABLE_FIELDS)} are writable via an "
                    "update proposal. path_roots and protected_resources "
                    "have no proposal path -- edit toolkits.yaml and reload "
                    "(SIGHUP or restart)."
                )
            for field in LIMIT_FIELDS & set(spec):
                value = spec[field]
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    raise ToolkitProposalWriteRefused(
                        f"Cannot propose {field}={value!r}: it must be a "
                        "positive integer."
                    )
        if "run_as" in spec and spec["run_as"] is not None:
            # Shape only, and only for immediate feedback -- `deploy()` is
            # the authoritative gate (it re-validates the whole merged file
            # with the exact `load_tier1` startup uses, which is also what
            # enforces "only a `file` toolkit may carry this"). Checking it
            # here means an agent learns about a typo now instead of leaving
            # a proposal in the queue that can only ever fail at review.
            try:
                parse_run_as(str(spec["run_as"]))
            except RunAsError as exc:
                raise ToolkitProposalWriteRefused(
                    f"Cannot propose this 'run_as': {exc}"
                ) from None
        for field in NETWORK_FIELDS & set(spec):
            # Shape only, for immediate feedback, exactly like `run_as`
            # above -- a wildcard or an IP literal in allowed_hosts is
            # refused now instead of failing at review. `deploy()`'s full
            # `load_tier1` stays the authoritative gate.
            if spec[field] is None:
                continue
            try:
                _parse_network_allowlist(
                    {field: spec[field], "allowed_cidrs" if field == "allowed_hosts"
                     else "allowed_hosts": None},
                    f"toolkit {name!r}",
                )
            except ConfigError as exc:
                raise ToolkitProposalWriteRefused(
                    f"Cannot propose this {field!r}: {exc}"
                ) from None
        if kind in ("create", "update") and "allowed_cidrs" in spec:
            body = dict(spec)
            if kind == "update":
                body = {**(self._live_toolkit_body(name) or {}), **spec}
            _check_network_policy(
                body, confirm_broad=confirm_broad_cidrs, where=f"toolkit {name!r}",
                destination_urls=self._live_destination_urls(body),
            )
        if kind == "delete" and spec:
            raise ToolkitProposalWriteRefused(
                "A delete proposal takes no 'spec' -- there is nothing to "
                "change, only a toolkit to remove."
            )
        if kind == "bind":
            # Shape only -- `deploy()` re-checks this same set as its own
            # authoritative gate. The point of pinning the spec to exactly
            # one key is that a bind proposal can never grow a second
            # payload: no destination-level override, no `path_roots`, no
            # limits (FR-4.11), and above all nothing value-shaped, which
            # would otherwise reach `toolkit_proposals.yaml` -- a plaintext
            # Tier 1 file -- and sit there in the clear.
            extra = sorted(set(spec) - {BIND_FIELD})
            if extra or BIND_FIELD not in spec:
                raise ToolkitProposalWriteRefused(
                    f"A bind proposal carries exactly {{'{BIND_FIELD}': "
                    "<name>} and nothing else"
                    + (f" -- got {extra} as well." if extra else ".")
                )
            credential = spec[BIND_FIELD]
            if not credential or not isinstance(credential, str):
                raise ToolkitProposalWriteRefused(
                    f"A bind proposal's '{BIND_FIELD}' must be a non-empty "
                    "credential name."
                )
        with self._lock:
            entries = self._load()
            if kind == "create":
                if name in self._live_toolkit_names():
                    raise ToolkitProposalWriteRefused(name_collision_message(name))
                queued = next(
                    (
                        e for e in entries
                        if e.get("name") == name
                        and (e.get("kind") or "create") == "create"
                        and e.get("status") == "pending"
                    ),
                    None,
                )
                if queued is not None:
                    raise ToolkitProposalWriteRefused(
                        f"A 'create' proposal for toolkit {name!r} is already "
                        f"pending ({queued.get('id')}). Only one of the two "
                        "could ever deploy. Withdraw it first with "
                        "admin.proposal_withdraw if this one replaces it."
                    )
            item = ToolkitProposal(
                id=secrets.token_urlsafe(12),
                name=name,
                spec=spec,
                actor=actor,
                kind=kind,
                status="pending",
                created_at=now_iso(),
                confirm_broad_cidrs=bool(confirm_broad_cidrs),
            )
            entries.append(item.to_spec())
            self._write(entries)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": _PROPOSE_ACTION_NAMES[kind],
                    "target": name,
                    "spec": spec,
                    **({"confirm_broad_cidrs": True} if confirm_broad_cidrs else {}),
                }
            )
            return item

    def _live_raw(self) -> dict[str, Any]:
        if not os.path.exists(self.toolkits_path):
            return {}
        with open(self.toolkits_path, encoding="utf-8") as handle:
            raw = _yaml_load(handle.read()) or {}
        return raw if isinstance(raw, dict) else {}

    def _live_toolkit_body(self, name: str) -> dict[str, Any] | None:
        section = self._live_raw().get("toolkits")
        body = section.get(name) if isinstance(section, dict) else None
        return body if isinstance(body, dict) else None

    def _live_destination_urls(self, body: dict[str, Any], raw: dict[str, Any] | None = None) -> list[str]:
        """The base_urls of the destinations `body` names, from toolkits.yaml."""
        names = body.get("destinations") or []
        section = (raw if raw is not None else self._live_raw()).get("destinations")
        if not isinstance(names, list) or not isinstance(section, dict):
            return []
        urls = []
        for dest in names:
            spec = section.get(dest)
            if isinstance(spec, dict) and isinstance(spec.get("base_url"), str):
                urls.append(spec["base_url"])
        return urls

    def _live_toolkit_names(self) -> set[str]:
        """Toolkit names in toolkits.yaml as `deploy()` will see them -- the
        file, not the running Tier 1, so the submit-time collision check
        and the deploy-time guard read the same source. A missing or
        malformed file is `deploy()`'s to report; here it just means
        nothing to collide with.
        """
        if not os.path.exists(self.toolkits_path):
            return set()
        with open(self.toolkits_path, encoding="utf-8") as handle:
            raw = _yaml_load(handle.read()) or {}
        section = raw.get("toolkits") if isinstance(raw, dict) else None
        return set(section) if isinstance(section, dict) else set()

    def withdraw(self, proposal_id: str, *, actor: str) -> ToolkitProposal:
        """The proposer takes its own still-pending proposal back.

        Not a decision: nothing in toolkits.yaml is read or written, and
        only the identity that filed the proposal may withdraw it -- so this
        can only ever shrink the queue that identity itself added to, never
        approve, and never touch anyone else's proposal. That is why it may
        be reachable from `/admin/mcp` while `reject`/`deploy` are not.
        """
        with self._lock:
            entries = self._load()
            match = next((e for e in entries if e.get("id") == proposal_id), None)
            if match is None:
                raise ToolkitProposalWriteRefused(f"No toolkit proposal {proposal_id!r}.")
            if match.get("actor") != actor:
                raise ToolkitProposalWriteRefused(
                    f"Toolkit proposal {proposal_id!r} was filed by "
                    f"{match.get('actor')!r}; only the proposer can withdraw "
                    "it. A human can reject it at /app/requests (Toolkit tab)."
                )
            if match.get("status") != "pending":
                raise ToolkitProposalWriteRefused(
                    f"Toolkit proposal {proposal_id!r} is already {match.get('status')!r}."
                )
            match["status"] = "withdrawn"
            match["decided_by"] = actor
            match["decided_at"] = now_iso()
            self._write(entries)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": actor,
                    "action": "toolkit_withdraw",
                    "target": match.get("name"),
                    "proposal_id": proposal_id,
                }
            )
            return _from_spec(match)

    def reject(
        self, proposal_id: str, *, decided_by: str, reason: str = ""
    ) -> ToolkitProposal:
        with self._lock:
            entries = self._load()
            match = next((e for e in entries if e.get("id") == proposal_id), None)
            if match is None:
                raise ToolkitProposalWriteRefused(f"No toolkit proposal {proposal_id!r}.")
            if match.get("status") != "pending":
                raise ToolkitProposalWriteRefused(
                    f"Toolkit proposal {proposal_id!r} is already {match.get('status')!r}."
                )
            match["status"] = "rejected"
            match["decided_by"] = decided_by
            match["decided_at"] = now_iso()
            match["reason"] = reason
            self._write(entries)
            self.audit.write(
                {
                    "kind": "admin_change",
                    "actor": decided_by,
                    "action": "toolkit_reject",
                    "target": match.get("name"),
                    "proposal_id": proposal_id,
                    "original_actor": match.get("actor"),
                    "reason": reason,
                }
            )
            return _from_spec(match)

    def deploy(self, proposal_id: str, *, decided_by: str) -> ToolkitProposal:
        """Approves and deploys one proposal -- see the module docstring for
        the five steps. Raises `ToolkitProposalWriteRefused` (nothing real
        touched) on a name collision or a Tier-1 validation failure, and
        again (this time with `toolkits.yaml` already written, but the
        proposal left `pending`) if `reload_config` itself errors.
        """
        with self._lock:
            entries = self._load()
            match = next((e for e in entries if e.get("id") == proposal_id), None)
            if match is None:
                raise ToolkitProposalWriteRefused(f"No toolkit proposal {proposal_id!r}.")
            if match.get("status") != "pending":
                raise ToolkitProposalWriteRefused(
                    f"Toolkit proposal {proposal_id!r} is already {match.get('status')!r}."
                )
            item = _from_spec(match)

            if not os.path.exists(self.toolkits_path):
                raise ToolkitProposalWriteRefused(f"{self.toolkits_path} not found.")
            if not _writable(self.toolkits_path):
                raise ToolkitProposalWriteRefused(
                    f"{os.path.basename(self.toolkits_path)} is not writable. The "
                    "file or its directory is mounted read-only."
                )
            with open(self.toolkits_path, encoding="utf-8") as handle:
                raw = _yaml_load(handle.read()) or {}
            toolkit_section = raw.get("toolkits")
            if toolkit_section is None:
                toolkit_section = {}
            if not isinstance(toolkit_section, dict):
                raise ToolkitProposalWriteRefused(
                    "toolkits.yaml: section 'toolkits' is not a mapping."
                )

            merged_toolkits = dict(toolkit_section)
            before_fields: dict[str, Any] | None = None
            if item.kind == "update":
                existing = toolkit_section.get(item.name)
                if not isinstance(existing, dict):
                    raise ToolkitProposalWriteRefused(
                        f"No toolkit named {item.name!r} exists in toolkits.yaml "
                        "-- it may have been renamed or removed by a redeploy "
                        "since this proposal was made. Reject this proposal."
                    )
                illegal = set(item.spec) - UPDATE_WRITABLE_FIELDS
                if illegal:
                    # Defense in depth: propose() already rejected this, but
                    # deploy() re-checks its own authoritative input rather
                    # than trusting a value it merely wrote earlier.
                    raise ToolkitProposalWriteRefused(
                        f"Cannot change {sorted(illegal)} at runtime -- only "
                        f"{sorted(UPDATE_WRITABLE_FIELDS)} are writable via an "
                        "update proposal."
                    )
                merged_body = {**existing, **item.spec}
                network = sorted(NETWORK_FIELDS & set(item.spec))
                executor = merged_body.get("executor")
                for field in sorted(set(FIELD_EXECUTORS) & set(item.spec)):
                    if executor not in FIELD_EXECUTORS[field]:
                        readers = " or ".join(sorted(FIELD_EXECUTORS[field]))
                        raise ToolkitProposalWriteRefused(
                            f"Cannot change {field!r} on toolkit {item.name!r}: "
                            f"its executor {executor!r} does not use it. Only "
                            f"an {readers} toolkit has {field}."
                            + (" (It does not connect to a URL.)"
                               if field in NETWORK_FIELDS else "")
                        )
                if "allowed_cidrs" in item.spec:
                    _check_network_policy(
                        merged_body, confirm_broad=item.confirm_broad_cidrs,
                        where=f"toolkit {item.name!r}",
                        destination_urls=self._live_destination_urls(merged_body, raw),
                    )
                # A null network field removes the key, so the remaining
                # one alone decides -- load_tier1 then refuses the toolkit
                # if that leaves it with neither.
                for field in network:
                    if merged_body.get(field) is None:
                        merged_body.pop(field, None)
                before_fields = {k: existing.get(k) for k in item.spec}
                merged_toolkits[item.name] = merged_body
            elif item.kind == "bind":
                existing = toolkit_section.get(item.name)
                if not isinstance(existing, dict):
                    raise ToolkitProposalWriteRefused(
                        f"No toolkit named {item.name!r} exists in toolkits.yaml "
                        "-- it may have been renamed or removed by a redeploy "
                        "since this proposal was made. Reject this proposal."
                    )
                extra = sorted(set(item.spec) - {BIND_FIELD})
                if extra or BIND_FIELD not in item.spec:
                    # Defense in depth, exactly as the `"update"` branch
                    # re-checks `UPDATE_WRITABLE_FIELDS`: deploy() validates
                    # its own authoritative input rather than trusting a
                    # value it merely wrote earlier.
                    raise ToolkitProposalWriteRefused(
                        f"A bind proposal may only set '{BIND_FIELD}'"
                        + (f" -- this one also carries {extra}." if extra else ".")
                    )
                before_fields = {BIND_FIELD: existing.get(BIND_FIELD)}
                merged_toolkits[item.name] = {**existing, BIND_FIELD: item.spec[BIND_FIELD]}
            elif item.kind == "delete":
                existing = toolkit_section.get(item.name)
                if not isinstance(existing, dict):
                    raise ToolkitProposalWriteRefused(
                        f"No toolkit named {item.name!r} exists in toolkits.yaml "
                        "-- it may already have been removed. Reject this "
                        "proposal."
                    )
                referencing = _tools_referencing_toolkit(self.tools_path, item.name)
                if referencing:
                    raise ToolkitProposalWriteRefused(
                        f"Toolkit {item.name!r} is still referenced by "
                        f"{len(referencing)} tool(s): {sorted(referencing)}. "
                        "Delete or reassign those tools first."
                    )
                before_fields = {item.name: existing}
                del merged_toolkits[item.name]
            else:
                if item.name in toolkit_section:
                    # `propose()` refuses this already; getting here means a
                    # redeploy added the name while the proposal waited.
                    raise ToolkitProposalWriteRefused(
                        f"{name_collision_message(item.name)} Reject this proposal."
                    )
                if "allowed_cidrs" in item.spec:
                    _check_network_policy(
                        item.spec, confirm_broad=item.confirm_broad_cidrs,
                        where=f"toolkit {item.name!r}",
                        destination_urls=self._live_destination_urls(item.spec, raw),
                    )
                merged_toolkits[item.name] = item.spec

            merged = dict(raw)
            merged["toolkits"] = merged_toolkits
            merged_text = _dump(merged)

            # Validate the merged configuration exactly as startup would,
            # before anything real is touched -- Tier 1 has no lenient path
            # (REQUIREMENTS.md §6).
            directory = os.path.dirname(os.path.abspath(self.toolkits_path)) or "."
            fd, tmp_path = tempfile.mkstemp(
                prefix=".gk-toolkit-validate-", suffix=".yaml", dir=directory
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(merged_text)
                try:
                    validated = load_tier1(tmp_path)
                except ConfigError as exc:
                    raise ToolkitProposalWriteRefused(
                        f"Proposed toolkit {item.name!r} is invalid: {exc}"
                    ) from exc
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

            if item.kind == "bind":
                # The file parses; does the *reference* actually resolve?
                # Read it back through `Tier1.credential_references()` --
                # the same single walk the startup check and the console's
                # "Used by" row use -- rather than trusting the dict we
                # merged. This is about the binding landing where Tier 1
                # can see it, not about the credential store having a value
                # for it: a name with no value is a dangling reference,
                # which keeps its existing contract of a startup warning
                # and a note on /app/credentials, never an abort (FR-8.3g).
                credential = item.spec[BIND_FIELD]
                bound = validated.toolkits.get(item.name)
                if bound is None or bound.credential != credential:
                    raise ToolkitProposalWriteRefused(
                        f"Binding {item.name!r} to credential {credential!r} "
                        "did not survive a Tier 1 reload -- toolkits.yaml was "
                        "not touched. Reject this proposal."
                    )
                if item.name not in validated.credential_references().get(credential, ()):
                    raise ToolkitProposalWriteRefused(
                        f"Toolkit {item.name!r} does not appear among the "
                        f"references to credential {credential!r} after "
                        "validation -- toolkits.yaml was not touched. Reject "
                        "this proposal."
                    )

            before_names = sorted(toolkit_section)
            _atomic_write(self.toolkits_path, merged_text)

            error = self.service.reload_config(
                toolkits_path=self.toolkits_path,
                tools_path=self.tools_path,
                identities_path=self.identities_path,
            )
            if error:
                # Defensive only: the block above already validated the
                # exact bytes just written. Left as 'pending' (not marked
                # 'deployed') so a human sees this failed rather than
                # believing the toolkit is live when it might not be.
                raise ToolkitProposalWriteRefused(
                    f"toolkits.yaml was written, but reloading it into this "
                    f"running process failed: {error}. A SIGHUP or restart "
                    "should pick it up; investigate before re-deploying."
                )

            match["status"] = "deployed"
            match["decided_by"] = decided_by
            match["decided_at"] = now_iso()
            self._write(entries)
            record: dict[str, Any] = {
                "kind": "admin_change",
                "actor": decided_by,
                "action": _DEPLOY_ACTION_NAMES[item.kind],
                "target": item.name,
                "proposal_id": proposal_id,
                "original_actor": item.actor,
                "before_toolkits": before_names,
                "after_toolkits": sorted(merged_toolkits),
            }
            if before_fields is not None:
                record["before_fields"] = before_fields
                record["after_fields"] = item.spec
            self.audit.write(record)
            return _from_spec(match)


__all__ = [
    "BIND_FIELD",
    "BROAD_PREFIX",
    "FIELD_EXECUTORS",
    "KINDS",
    "LIMIT_FIELDS",
    "NETWORK_FIELDS",
    "STATUSES",
    "UPDATE_WRITABLE_FIELDS",
    "ToolkitProposal",
    "ToolkitProposalStore",
    "ToolkitProposalWriteRefused",
    "name_collision_message",
]
