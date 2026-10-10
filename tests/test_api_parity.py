"""`/api/v1` parity with properties the legacy `/ui` tests pinned.

When the HTML console went (1.0.0), its tests went with it. Most of what
they proved is asserted in `test_api_*.py` already; this file holds the
rest -- each test names the `/ui` test it replaces, so the property can be
traced back. Security-gate properties (roles, CSRF, sessions) are in
`test_api_auth.py`/`test_api_security.py`; store-level ones in
`test_store_admin.py`.
"""

from __future__ import annotations

import dataclasses

import pytest
import yaml
from api_env import API, client, login, make_env
from conftest import PYTHON

from gatekeeper.catalog import load_catalog
from gatekeeper.credentials import KEY_ENV, generate_master_key
from gatekeeper.integrations import INTEGRATIONS
from gatekeeper.pending import STALE_VANISHED_REASON
from gatekeeper.store import tool_to_yaml
from gatekeeper.tier1 import load_tier1

SECRET_VALUE = "super-secret-sonarr-key-xyz"


@pytest.fixture
def env(tmp_path, tier1, tool_specs):
    return make_env(tmp_path, tier1, tool_specs)


@pytest.fixture
def cred_env(tmp_path, tier1, tool_specs, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    return make_env(tmp_path, tier1, tool_specs)


def _h(info: dict, etag: str | None = None) -> dict:
    headers = {"X-CSRF-Token": info["csrf"]}
    if etag is not None:
        headers["If-Match"] = etag
    return headers


def _remove_tool_entry(env, tool_id):
    """The state a toolkit restructure leaves behind: the tool's entry is no
    longer in tools.yaml at all (not a `delete_tool` tombstone)."""
    store = env["store"]
    specs = yaml.safe_load(open(store.tools_path, encoding="utf-8"))["tools"]
    with open(store.tools_path, "w", encoding="utf-8") as handle:
        handle.write(yaml.safe_dump({"tools": [s for s in specs if s.get("id") != tool_id]}))
    env["service"].catalog = load_catalog(store.tools_path, env["service"].tier1)


def _propose_delete(env, tool_id="demo.show"):
    return env["pending"].propose(
        action="tool_delete", actor="hermes", payload={"id": tool_id},
        base_rev=env["store"].tool_revision(tool_id),
    )


async def _pending(c, item_id):
    items = (await c.get(f"{API}/requests/pending")).json()
    return next(i for i in items if i["id"] == item_id)


# -- Review of a grant_set (test_ui_admin: pending page) -----------------------------


async def test_review_tells_a_real_tool_from_a_missing_one_in_a_grant(env):
    """was test_pending_page_distinguishes_real_from_missing_tools_in_a_grant"""
    item = env["pending"].propose(
        action="grant_set", actor="hermes",
        payload={"identity_id": "bot", "role": "agent",
                 "tools": ["demo.show", "demo.ghost"], "scopes": ["stack:*"]},
        base_rev=env["store"].identities_revision(),
    )
    async with client(env["app"]) as c:
        await login(c, "eye")
        review = (await _pending(c, item.id))["review"]
    states = {t["id"]: t["state"] for t in review["tools"]}
    assert states == {"demo.show": "enabled", "demo.ghost": "missing"}


async def test_review_lists_only_the_delta_of_a_grant_set(env):
    """was test_pending_page_shows_only_the_delta_of_a_grant_set"""
    store = env["store"]
    store.save_identity(
        identity_id="bot", role="agent", tools=["demo.show", "demo.echo"],
        scopes=["stack:*"], actor="root", rev=store.identities_revision(), replaces="bot",
    )
    item = env["pending"].propose(
        action="grant_set", actor="hermes",
        payload={"identity_id": "bot", "role": "agent", "tools": ["demo.echo"],
                 "scopes": ["stack:*"], "prev_tools": ["demo.echo", "demo.show"]},
        base_rev=store.identities_revision(),
    )
    async with client(env["app"]) as c:
        await login(c, "eye")
        review = (await _pending(c, item.id))["review"]
    assert review["headline"] == "identity bot: +0 -1, 1 unchanged"
    assert review["unchanged"] == 1
    # The unchanged, enabled demo.echo collapses into the count.
    assert [(t["id"], t["marker"]) for t in review["tools"]] == [("demo.show", "-")]


# -- Deciding a proposal whose target is gone (test_ui_admin) -------------------------


async def test_reject_closes_a_tool_delete_whose_tool_is_gone(env):
    """was test_reject_closes_a_tool_delete_whose_tool_is_gone: refusing
    never needs a live target."""
    item = _propose_delete(env)
    _remove_tool_entry(env, "demo.show")
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        r = await c.post(
            f"{API}/requests/pending/{item.id}/reject",
            json={"reason": "toolkit restructured"}, headers=_h(admin),
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "rejected"
        # The closed item still lists; the missing target is flagged, not fatal.
        listing = await c.get(f"{API}/requests/pending?status=rejected")
        assert listing.status_code == 200
        (got,) = listing.json()
        assert got["review"]["tools"][0]["state"] == "missing"
    decided = env["pending"].get(item.id)
    assert decided.status == "rejected"
    assert decided.reason == "toolkit restructured"


async def test_listing_requests_self_heals_a_pending_whose_tool_is_gone(env):
    """was test_visiting_requests_self_heals_a_pending_whose_tool_is_gone"""
    item = _propose_delete(env)
    _remove_tool_entry(env, "demo.show")
    async with client(env["app"]) as c:
        await login(c, "eye")
        got = await _pending(c, item.id)
        live = (await c.get(f"{API}/requests/pending?status=pending")).json()
    healed = env["pending"].get(item.id)
    assert healed.status == "stale"
    assert healed.reason == STALE_VANISHED_REASON
    assert got["status"] == "stale"
    # The vanished-target explanation, not "re-propose from the current state".
    assert "no longer exists" in got["review"]["stale"]
    assert live == []


async def test_listing_requests_leaves_a_pending_with_a_live_target_alone(env):
    """was test_visiting_requests_leaves_a_pending_with_a_live_target_alone"""
    item = _propose_delete(env)
    async with client(env["app"]) as c:
        await login(c, "eye")
        await c.get(f"{API}/requests/pending")
        got = await _pending(c, item.id)
    assert got["status"] == "pending"
    assert env["pending"].get(item.id).status == "pending"


# -- Approve-all (test_ui_admin, test_ui_credentials) ----------------------------------


async def test_approve_all_partial_failure_still_applies_the_rest(env):
    """was test_approve_all_partial_failure_still_applies_rest"""
    store, pending = env["store"], env["pending"]
    store.set_tool_enabled("demo.show", False, actor="root", rev=store.tools_revision())
    first = pending.propose(
        action="tool_enable", actor="hermes", payload={"id": "demo.show"},
        base_rev=store.tool_revision("demo.show"),
    )
    second = pending.propose(
        action="tool_enable", actor="hermes", payload={"id": "demo.show"},
        base_rev=store.tool_revision("demo.show"),
    )
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        r = await c.post(
            f"{API}/requests/pending/approve-all", json={"ids": [first.id, second.id]},
            headers=_h(admin),
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["applied"] == 1
    assert [x["id"] for x in body["refused"]] == [second.id]
    assert pending.get(first.id).status == "approved"
    assert pending.get(second.id).status in ("stale", "pending")
    assert env["service"].catalog.tools["demo.show"].enabled


async def test_approve_all_excludes_credential_proposals(cred_env):
    """was test_approve_all_excludes_credential_proposals: a credential
    needs a value a human types, so it is never batched."""
    pending, credentials = cred_env["pending"], cred_env["credentials"]
    items = [
        pending.propose(
            action="cred_propose", actor="hermes",
            payload={"name": name, "kind": "api_key_header", "header": "X-Api-Key"},
            base_rev=credentials.revision(),
        )
        for name in ("sonarr", "radarr")
    ]
    async with client(cred_env["app"]) as c:
        admin = await login(c, "root")
        r = await c.post(
            f"{API}/requests/pending/approve-all", json={"ids": [i.id for i in items]},
            headers=_h(admin),
        )
    assert r.json() == {"applied": 0, "refused": []}
    assert all(pending.get(i.id).status == "pending" for i in items)
    assert credentials.names() == []


# -- Credential fill (test_ui_credentials) ----------------------------------------------


def _propose_credential(env, name="sonarr"):
    return env["pending"].propose(
        action="cred_propose", actor="hermes",
        payload={"name": name, "kind": "api_key_header", "header": "X-Api-Key"},
        base_rev=env["credentials"].revision(),
    )


async def test_credential_fill_creates_what_was_proposed_and_never_echoes(cred_env, tmp_path):
    """was test_credential_fill_approves_proposal_and_creates_credential and
    test_credential_fill_never_echoes_the_value"""
    item = _propose_credential(cred_env)
    async with client(cred_env["app"]) as c:
        admin = await login(c, "root")
        filled = await c.post(
            f"{API}/requests/pending/{item.id}/credential", json={"value": SECRET_VALUE},
            headers=_h(admin),
        )
        assert filled.status_code == 200, filled.text
        assert SECRET_VALUE not in filled.text
        listing = await c.get(f"{API}/credentials")
        assert SECRET_VALUE not in listing.text
    metas = {m.name: m for m in cred_env["credentials"].names()}
    assert metas["sonarr"].kind == "api_key_header"
    assert metas["sonarr"].header == "X-Api-Key"
    assert cred_env["pending"].get(item.id).status == "approved"
    # The value never touched the pending queue's own file.
    assert SECRET_VALUE not in (tmp_path / "pending.yaml").read_text(encoding="utf-8")


async def test_credential_fill_stale_when_name_taken_meanwhile(cred_env):
    """was test_credential_fill_stale_when_name_taken_meanwhile: the fill
    must neither create a second entry nor clobber the existing one."""
    credentials = cred_env["credentials"]
    item = _propose_credential(cred_env)
    credentials.create(
        "sonarr", kind="bearer", value="typed-directly-in-the-meantime", actor="root", rev="",
    )
    async with client(cred_env["app"]) as c:
        admin = await login(c, "root")
        r = await c.post(
            f"{API}/requests/pending/{item.id}/credential", json={"value": SECRET_VALUE},
            headers=_h(admin),
        )
    assert r.status_code == 400, r.text
    assert "already exists" in r.json()["error"]
    assert SECRET_VALUE not in r.text
    (meta,) = credentials.names()
    assert meta.name == "sonarr" and meta.kind == "bearer"
    assert cred_env["pending"].get(item.id).status != "approved"


# -- Credential metadata (test_ui_credentials) ------------------------------------------


async def test_credentials_show_probe_and_suspect_metadata_without_value(cred_env):
    """was test_credentials_page_shows_probe_and_suspect_metadata_without_value"""
    credentials = cred_env["credentials"]
    credentials.create(
        "sonarr", kind="bearer", value=SECRET_VALUE,
        probe_url="https://service.test/me", actor="root", rev="",
    )
    credentials.mark_suspect("sonarr")
    async with client(cred_env["app"]) as c:
        await login(c, "eye")
        listing = await c.get(f"{API}/credentials")
    (meta,) = listing.json()["credentials"]
    assert meta["probe_url"] == "https://service.test/me"
    assert meta["probe_status"] == "no_probe_url"
    assert meta["suspect_status"] == "auth_failed"
    assert meta["suspect_at"]
    assert SECRET_VALUE not in listing.text


def _bound_env(tmp_path, tier1, monkeypatch, *, create_credential: bool) -> dict:
    """A console whose one toolkit carries `credential: sonarr`."""
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump({
            "toolkits": {"demo": {
                "executor": "local", "binaries": [tier1.toolkits["demo"].binaries[0]],
                "credential": "sonarr",
            }},
            "audit": {"dir": str(tmp_path / "logs2")},
        }),
        encoding="utf-8",
    )
    env = make_env(tmp_path, load_tier1(str(path)), [])
    if create_credential:
        env["credentials"].create(
            "sonarr", kind="api_key_header", header="X-Api-Key", value=SECRET_VALUE,
            actor="test", rev="",
        )
    return env


async def test_credentials_name_the_toolkit_using_them(tmp_path, tier1, monkeypatch):
    """was test_used_by_toolkit_shown"""
    env = _bound_env(tmp_path, tier1, monkeypatch, create_credential=True)
    async with client(env["app"]) as c:
        await login(c, "eye")
        listing = await c.get(f"{API}/credentials")
    body = listing.json()
    (meta,) = body["credentials"]
    assert meta["name"] == "sonarr" and meta["used_by"] == ["demo"]
    assert body["dangling"] == []
    assert SECRET_VALUE not in listing.text


async def test_a_dangling_binding_is_reported(tmp_path, tier1, monkeypatch):
    """was test_dangling_binding_named_on_the_page"""
    env = _bound_env(tmp_path, tier1, monkeypatch, create_credential=False)
    async with client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/credentials")).json()
        toolkits = (await c.get(f"{API}/toolkits")).json()["toolkits"]
    assert body["credentials"] == []
    assert body["dangling"] == ["sonarr"]
    # ... and what refers to it.
    assert [(t["name"], t["credential"]) for t in toolkits] == [("demo", "sonarr")]


# -- Toolkit proposals: kind "bind" (test_ui_admin) -------------------------------------


async def test_bind_proposal_deploys_writes_and_reloads(env, tier1):
    """was test_toolkits_bind_proposal_shows_bind_pill_and_the_credential_name,
    test_toolkits_bind_deploy_over_http_writes_and_reloads and
    test_toolkits_bind_to_a_credential_with_no_slot_still_deploys"""
    queue, service = env["toolkit_proposals"], env["service"]
    assert service.tier1.toolkit("demo").credential is None
    item = queue.propose(
        name="demo", spec={"credential": "sonarr-api-key"}, actor="hermes", kind="bind"
    )
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        (listed,) = (await c.get(f"{API}/requests/toolkits")).json()
        assert listed["kind"] == "bind"
        assert listed["spec"] == {"credential": "sonarr-api-key"}
        # An unbound toolkit says so: today's credential is None.
        assert listed["current"]["credential"] is None
        r = await c.post(
            f"{API}/requests/toolkits/{item.id}/deploy", json={"confirm": True}, headers=_h(admin)
        )
        assert r.status_code == 200, r.text
        # No slot behind the name: deployed anyway, reported as dangling (FR-8.3g).
        credentials = (await c.get(f"{API}/credentials")).json()
    assert credentials["dangling"] == ["sonarr-api-key"]
    assert service.tier1.toolkit("demo").credential == "sonarr-api-key"
    assert service.tier1.credential_references() == {"sonarr-api-key": ("demo",)}
    assert queue.get(item.id).status == "deployed"
    on_disk = yaml.safe_load(open(queue.toolkits_path, encoding="utf-8"))["toolkits"]["demo"]
    assert on_disk["credential"] == "sonarr-api-key"
    assert on_disk["path_roots"] == list(service.tier1.toolkit("demo").path_roots)


async def test_toolkit_reject_leaves_toolkits_yaml_unchanged(env):
    """was test_toolkits_reject_leaves_toolkits_yaml_unchanged"""
    queue = env["toolkit_proposals"]
    before = open(queue.toolkits_path, encoding="utf-8").read()
    item = queue.propose(name="zfs", spec={"executor": "local", "binaries": [PYTHON]}, actor="hermes")
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        r = await c.post(
            f"{API}/requests/toolkits/{item.id}/reject", json={"reason": "not now"},
            headers=_h(admin),
        )
    assert r.json()["status"] == "rejected"
    assert "zfs" not in env["service"].tier1.toolkits
    assert open(queue.toolkits_path, encoding="utf-8").read() == before


# -- Decided requests (test_pending: archive) -------------------------------------------


async def test_decided_requests_are_listed_by_status(env):
    """was test_requests_archive_is_opt_in_and_paged. The API has no
    archive pages: `?status=` selects the decided items, oldest first."""
    approved, rejected = _propose_delete(env), _propose_delete(env, "demo.echo")
    waiting = env["pending"].propose(
        action="tool_disable", actor="hermes", payload={"id": "demo.echo"},
        base_rev=env["store"].tool_revision("demo.echo"),
    )
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        await c.post(f"{API}/requests/pending/{approved.id}/approve", headers=_h(admin))
        await c.post(f"{API}/requests/pending/{rejected.id}/reject", json={}, headers=_h(admin))

        async def ids(query=""):
            return [i["id"] for i in (await c.get(f"{API}/requests/pending{query}")).json()]

        assert await ids("?status=approved") == [approved.id]
        assert await ids("?status=rejected") == [rejected.id]
        assert await ids("?status=pending") == [waiting.id]
        assert await ids() == [approved.id, rejected.id, waiting.id]


# -- Integrations (test_ui_integrations) -------------------------------------------------


@pytest.fixture
def integrations_env(tmp_path):
    """A toolkit matching the 'sonarr' integration, so it becomes actionable."""
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        "toolkits:\n" + INTEGRATIONS["sonarr"].toolkit_yaml
        + f"\naudit:\n  dir: {tmp_path / 'logs'}\n",
        encoding="utf-8",
    )
    return make_env(tmp_path, load_tier1(str(path)), [])


async def test_only_a_configured_toolkits_integration_can_be_created(integrations_env):
    """was test_gallery_shows_all_integrations, test_only_configured_toolkit_
    offers_create_action, test_pick_lists_starter_tools, test_new_from_
    integration_prefills_editor_and_saves and test_toolkit_not_configured_
    blocks_integration_creation"""
    env = integrations_env
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        listing = {i["key"]: i for i in (await c.get(f"{API}/integrations")).json()}
        assert set(listing) == set(INTEGRATIONS)
        assert listing["sonarr"]["toolkit_configured"] is True
        assert listing["radarr"]["toolkit_configured"] is False
        sonarr_tools = {t["id"]: t for t in listing["sonarr"]["tools"]}
        assert {"sonarr.list_series", "sonarr.add_series"} <= set(sonarr_tools)

        etag = (await c.get(f"{API}/tools")).headers["etag"]
        saved = await c.post(
            f"{API}/tools", json={"yaml": sonarr_tools["sonarr.list_series"]["yaml"]},
            headers=_h(admin, etag),
        )
        assert saved.status_code == 201, saved.text
        assert "sonarr.list_series" in env["service"].catalog.tools

        radarr = next(t for t in listing["radarr"]["tools"] if t["id"] == "radarr.list_movies")
        refused = await c.post(
            f"{API}/tools", json={"yaml": radarr["yaml"]},
            headers=_h(admin, saved.headers["etag"]),
        )
        assert refused.status_code == 400
    assert "radarr.list_movies" not in env["service"].catalog.tools


async def test_a_broken_integration_spec_is_still_rejected(integrations_env):
    """was test_a_broken_integration_spec_is_still_rejected: an integration
    only pre-fills the editor; the save is the full Tier 1 path."""
    env = integrations_env
    broken = dict(INTEGRATIONS["sonarr"].tool_specs[0])
    broken["method"] = "DELETE"  # not in sonarr's allowed_methods
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        etag = (await c.get(f"{API}/tools")).headers["etag"]
        r = await c.post(
            f"{API}/tools", json={"yaml": tool_to_yaml(broken)}, headers=_h(admin, etag)
        )
    assert r.status_code == 400
    assert r.json()["error"]
    assert broken["id"] not in env["service"].catalog.tools


async def test_reference_lists_every_integrations_toolkit_yaml(integrations_env):
    """was test_reference_page_lists_all_toolkit_yaml_blocks"""
    async with client(integrations_env["app"]) as c:
        await login(c, "eye")
        reference = (await c.get(f"{API}/toolkits/reference")).json()
    assert {r["key"] for r in reference} == set(INTEGRATIONS)
    blocks = "\n".join(r["toolkit_yaml"] for r in reference)
    assert "executor: http" in blocks
    assert "executor: truenas" in blocks


# -- Tools listing with non-mapping templates (test_ui_tools_templates) ---------------


async def test_tools_listing_survives_non_mapping_templates(tmp_path):
    """was test_tools_page_survives_non_mapping_templates: one tool with a
    string `body`/`query_template` must not take the listing down."""
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        f"""
toolkits:
  demo_http:
    executor: http
    base_url: "http://127.0.0.1:9"
    allowed_methods: ["GET", "POST"]
    allowed_path_prefixes: ["/api/"]
    allowed_cidrs: ["127.0.0.1/32"]
audit:
  dir: {tmp_path / "logs"}
""",
        encoding="utf-8",
    )
    param = {"name": {"type": "string", "required": True, "pattern": "^[a-z]+$",
                      "description": "item name"}}
    base = {"toolkit": "demo_http", "version": 1, "required_scopes": [], "parameters": param,
            "path": "/api/items"}
    specs = [
        {**base, "id": "demo_http.normal", "title": "Normal", "description": "Mapping.",
         "category": "read", "idempotent": True, "enabled": True, "method": "GET",
         "query": {"name": "{name}"}},
        {**base, "id": "demo_http.raw_body", "title": "Raw body", "description": "Raw.",
         "category": "write", "idempotent": False, "enabled": True, "method": "POST",
         "body": "{name}"},
    ]
    env = make_env(tmp_path, load_tier1(str(path)), specs)
    catalog = env["service"].catalog
    raw = catalog.tools["demo_http.raw_body"]
    assert isinstance(raw.body_template, str)
    catalog.tools["demo_http.raw_body"] = dataclasses.replace(raw, query_template="name={name}")
    async with client(env["app"]) as c:
        await login(c, "eye")
        listing = await c.get(f"{API}/tools")
        detail = await c.get(f"{API}/tools/demo_http.raw_body")
        overview = await c.get(f"{API}/overview")
    assert listing.status_code == 200
    assert [t["id"] for t in listing.json()["tools"]] == ["demo_http.normal", "demo_http.raw_body"]
    assert detail.status_code == 200
    assert overview.status_code == 200

