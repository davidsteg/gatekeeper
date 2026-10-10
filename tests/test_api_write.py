"""`/api/v1` writes: tools, identities, credentials, own password, and
request decisions.

Each route calls the same store method the 0.x console's forms did; the
store-level outcomes are pinned in `test_store_admin.py`. These tests add
the API's own gate order on every write: session, role, CSRF, If-Match.
"""

from __future__ import annotations

import json

import pytest
import yaml
from api_env import API, PASSWORDS, audit_records, client, login, make_env

from gatekeeper.api.app import build_api_app, openapi_schema
from gatekeeper.credentials import generate_master_key
from gatekeeper.tier1 import load_tier1

_FILL = {
    "{tool_id}": "demo.show", "{identity_id}": "bot", "{name}": "demo-key", "{key}": "sonarr",
    "{item_id}": "nope", "{proposal_id}": "nope",
}


def _write_routes() -> list[tuple[str, str]]:
    schema = openapi_schema(build_api_app(None))
    out = []
    for path, ops in schema["paths"].items():
        for method in ops:
            if method in ("post", "put", "patch", "delete") and path != "/session":
                for key, value in _FILL.items():
                    path = path.replace(key, value)
                out.append((method.upper(), path))
    return sorted(out)


@pytest.fixture
def env(tmp_path, tier1, tool_specs):
    return make_env(tmp_path, tier1, tool_specs)


async def _etag(c, path: str) -> str:
    response = await c.get(f"{API}{path}")
    assert response.status_code == 200, response.text
    return response.headers["etag"]


def _h(info: dict, etag: str | None = None) -> dict:
    headers = {"X-CSRF-Token": info["csrf"]}
    if etag is not None:
        headers["If-Match"] = etag
    return headers


NEW_TOOL = """\
id: demo.hello
toolkit: demo
binary: {python}
version: 1
title: Hello
description: Says hello.
category: read
idempotent: true
enabled: true
argv: ["-c", "print('hello')"]
parameters: {{}}
required_scopes: []
timeout_seconds: 5
max_output_bytes: 1024
"""


def _new_tool(env) -> str:
    python = env["service"].tier1.toolkits["demo"].binaries[0]
    return NEW_TOOL.format(python=python)


# -- The gate, on every write route --------------------------------------------------


def test_the_schema_lists_the_phase_3a_writes():
    assert set(_write_routes()) >= {
        ("POST", "/tools"), ("PUT", "/tools/demo.show"),
        ("PUT", "/tools/demo.show/enabled"), ("DELETE", "/tools/demo.show"),
        ("POST", "/identities"), ("PUT", "/identities/bot"),
        ("POST", "/identities/bot/token"), ("DELETE", "/identities/bot"),
        ("POST", "/credentials"), ("POST", "/credentials/demo-key/rotate"),
        ("DELETE", "/credentials/demo-key"), ("PUT", "/account/password"),
        ("POST", "/requests/pending/nope/approve"), ("POST", "/requests/pending/nope/reject"),
        ("POST", "/requests/pending/nope/credential"), ("POST", "/requests/pending/approve-all"),
        ("POST", "/requests/toolkits/nope/deploy"), ("POST", "/requests/toolkits/nope/reject"),
    }


async def test_every_write_is_gated_in_order(env):
    """No session 401; viewer 403 (except one's own password); no CSRF 403;
    no If-Match 428. Nothing is written by any of these attempts."""
    tools_before = env["store"].tools_revision()
    identities_before = env["store"].identities_revision()
    async with client(env["app"]) as c:
        for method, path in _write_routes():
            assert (await c.request(method, f"{API}{path}", json={})).status_code == 401, path

        viewer = await login(c, "eye")
        for method, path in _write_routes():
            if path == "/account/password":
                continue
            response = await c.request(method, f"{API}{path}", json={}, headers=_h(viewer))
            assert response.status_code == 403, (method, path)
        await c.delete(f"{API}/session", headers=_h(viewer))

        admin = await login(c, "root")
        for method, path in _write_routes():
            response = await c.request(method, f"{API}{path}", json={})
            assert response.status_code == 403, (method, path)
            assert "CSRF" in response.json()["error"]
        for method, path in _write_routes():
            if method == "DELETE" or path.endswith("/token"):
                response = await c.request(method, f"{API}{path}", headers=_h(admin))
                assert response.status_code == 428, (method, path)
    assert env["store"].tools_revision() == tools_before
    assert env["store"].identities_revision() == identities_before


async def test_read_only_mode_refuses_every_write(tmp_path, tier1, tool_specs):
    env = make_env(tmp_path, tier1, tool_specs, read_only=True)
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        for method, path in _write_routes():
            response = await c.request(
                method, f"{API}{path}", json={}, headers=_h(admin, '"x"')
            )
            assert response.status_code == 403, (method, path)


# -- Tools --------------------------------------------------------------------------------


async def test_tool_create_update_toggle_delete(env):
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        etag = await _etag(c, "/tools")
        created = await c.post(
            f"{API}/tools", json={"yaml": _new_tool(env)}, headers=_h(admin, etag)
        )
        assert created.status_code == 201, created.text
        assert created.json()["id"] == "demo.hello"
        etag = created.headers["etag"]
        assert etag == f'"{created.json()["revision"]}"'
        assert "demo.hello" in env["service"].catalog.tools

        edited = _new_tool(env).replace("title: Hello", "title: Hello again")
        updated = await c.put(
            f"{API}/tools/demo.hello", json={"yaml": edited}, headers=_h(admin, etag)
        )
        assert updated.status_code == 200, updated.text
        detail = (await c.get(f"{API}/tools/demo.hello")).json()
        assert detail["spec"]["title"] == "Hello again"

        etag = updated.headers["etag"]
        off = await c.put(
            f"{API}/tools/demo.hello/enabled", json={"enabled": False}, headers=_h(admin, etag)
        )
        assert off.status_code == 200
        assert (await c.get(f"{API}/tools/demo.hello")).json()["enabled"] is False

        gone = await c.delete(f"{API}/tools/demo.hello", headers=_h(admin, off.headers["etag"]))
        assert gone.status_code == 200
        assert (await c.get(f"{API}/tools/demo.hello")).status_code == 404
    actions = [r.get("action") for r in audit_records(env) if r.get("kind") == "admin_change"]
    assert len(actions) >= 4


async def test_a_stale_etag_is_a_412_and_writes_nothing(env):
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        stale = await _etag(c, "/tools")
        first = await c.post(
            f"{API}/tools", json={"yaml": _new_tool(env)}, headers=_h(admin, stale)
        )
        assert first.status_code == 201
        before = env["store"].tools_revision()
        again = await c.put(
            f"{API}/tools/demo.show/enabled", json={"enabled": False}, headers=_h(admin, stale)
        )
        assert again.status_code == 412
        assert env["store"].tools_revision() == before


async def test_tier1_still_decides(env):
    """An API save is the form's save: `parse_tool_spec` against Tier 1."""
    bad = _new_tool(env).replace('argv: ["-c", "print(\'hello\')"]', 'argv: ["--dangerous"]')
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        etag = await _etag(c, "/tools")
        response = await c.post(f"{API}/tools", json={"yaml": bad}, headers=_h(admin, etag))
        assert response.status_code == 400
        assert response.json()["error"]
        broken = await c.post(f"{API}/tools", json={"yaml": "a: [b"}, headers=_h(admin, etag))
        assert broken.status_code == 400
        assert "YAML" in broken.json()["error"]
        extra = await c.post(
            f"{API}/tools", json={"yaml": _new_tool(env), "toolkit": "x"}, headers=_h(admin, etag)
        )
        assert extra.status_code == 422
    assert "demo.hello" not in env["service"].catalog.tools


async def test_scaffold_and_integration_yaml_prefill_the_editor(env):
    async with client(env["app"]) as c:
        await login(c, "eye")
        scaffold = (await c.get(f"{API}/tool-scaffold")).json()["yaml"]
        assert yaml.safe_load(scaffold)["toolkit"] == "demo"
        integrations = (await c.get(f"{API}/integrations")).json()
        first = integrations[0]["tools"][0]
        assert yaml.safe_load(first["yaml"])["id"] == first["id"]


# -- Identities ----------------------------------------------------------------------------


async def test_identity_create_returns_the_token_once(env):
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        etag = await _etag(c, "/identities")
        response = await c.post(
            f"{API}/identities",
            json={"id": "newbot", "role": "agent", "tools": ["demo.show"], "scopes": ["stack:a"]},
            headers=_h(admin, etag),
        )
        assert response.status_code == 201, response.text
        token = response.json()["token"]
        assert env["identities"].authenticate(token).id == "newbot"
        listing = (await c.get(f"{API}/identities")).text
        assert token not in listing
    assert all(token not in json.dumps(r) for r in audit_records(env))


async def test_identity_update_with_a_password_ends_that_identitys_sessions(env):
    async with client(env["app"]) as admin_c, client(env["app"]) as eye_c:
        admin = await login(admin_c, "root")
        await login(eye_c, "eye")
        etag = await _etag(admin_c, "/identities")
        response = await admin_c.put(
            f"{API}/identities/eye",
            json={"id": "eye", "role": "viewer", "password": "a-brand-new-password-1"},
            headers=_h(admin, etag),
        )
        assert response.status_code == 200, response.text
        assert (await eye_c.get(f"{API}/session")).status_code == 401
        assert (await admin_c.get(f"{API}/session")).status_code == 200


async def test_identity_rotate_and_delete(env):
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        etag = await _etag(c, "/identities")
        old = env["tokens"]["bot"]
        rotated = await c.post(f"{API}/identities/bot/token", headers=_h(admin, etag))
        assert rotated.status_code == 200
        new = rotated.json()["token"]
        assert env["identities"].authenticate(old) is None
        assert env["identities"].authenticate(new).id == "bot"

        gone = await c.delete(f"{API}/identities/bot", headers=_h(admin, rotated.headers["etag"]))
        assert gone.status_code == 200
        assert env["identities"].authenticate(new) is None


async def test_deleting_yourself_ends_your_session(env):
    async with client(env["app"]) as c:
        # A second admin, so the store's last-admin guard does not refuse.
        admin = await login(c, "root")
        etag = await _etag(c, "/identities")
        await c.put(
            f"{API}/identities/eye",
            json={"id": "eye", "role": "admin"}, headers=_h(admin, etag),
        )
        etag = await _etag(c, "/identities")
        response = await c.delete(f"{API}/identities/root", headers=_h(admin, etag))
        assert response.status_code == 200, response.text
        assert (await c.get(f"{API}/session")).status_code == 401


# -- Credentials ----------------------------------------------------------------------------


async def test_credential_values_go_in_and_never_come_out(env, monkeypatch):
    monkeypatch.setenv("GATEKEEPER_CREDENTIAL_KEY", generate_master_key())
    first, second = "sk-first-secret-000111222", "sk-second-secret-333444555"
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        etag = await _etag(c, "/credentials")
        created = await c.post(
            f"{API}/credentials",
            json={"name": "demo-key", "kind": "bearer", "value": first},
            headers=_h(admin, etag),
        )
        assert created.status_code == 201, created.text
        rotated = await c.post(
            f"{API}/credentials/demo-key/rotate",
            json={"value": second, "overlap_seconds": 60},
            headers=_h(admin, created.headers["etag"]),
        )
        assert rotated.status_code == 200, rotated.text
        listing = await c.get(f"{API}/credentials")
        (meta,) = listing.json()["credentials"]
        assert meta["in_overlap"] is True
        bodies = created.text + rotated.text + listing.text
        assert first not in bodies and second not in bodies

        bad = await c.post(
            f"{API}/credentials",
            json={"name": "x", "kind": "nope", "value": "v"},
            headers=_h(admin, listing.headers["etag"]),
        )
        assert bad.status_code == 400

        gone = await c.delete(
            f"{API}/credentials/demo-key", headers=_h(admin, listing.headers["etag"])
        )
        assert gone.status_code == 200
        assert (await c.get(f"{API}/credentials")).json()["credentials"] == []
    log = json.dumps(audit_records(env))
    assert first not in log and second not in log


# -- Account -------------------------------------------------------------------------------


async def test_own_password_change(env):
    async with client(env["app"]) as c, client(env["app"]) as other:
        me = await login(c, "eye")
        await login(other, "eye")
        etag = await _etag(c, "/account")
        wrong = await c.put(
            f"{API}/account/password",
            json={"current": "not-it", "password": "a-new-viewer-password"},
            headers=_h(me, etag),
        )
        assert wrong.status_code == 400
        assert any(
            r.get("reason") == "ui_password_change_failed" for r in audit_records(env)
        )
        ok = await c.put(
            f"{API}/account/password",
            json={"current": PASSWORDS["eye"], "password": "a-new-viewer-password"},
            headers=_h(me, etag),
        )
        assert ok.status_code == 200, ok.text
        assert (await c.get(f"{API}/session")).status_code == 200
        assert (await other.get(f"{API}/session")).status_code == 401
        assert env["identities"].authenticate_console("eye", "a-new-viewer-password")


# -- Request decisions (phase 3b) ------------------------------------------------------


def _propose_delete(env, tool_id: str = "demo.show"):
    return env["pending"].propose(
        action="tool_delete", actor="hermes", payload={"id": tool_id},
        base_rev=env["store"].tool_revision(tool_id),
    )


async def test_pending_items_carry_a_review(env):
    store = env["store"]
    env["pending"].propose(
        action="grant_set", actor="hermes",
        payload={"identity_id": "bot", "tools": ["demo.show", "demo.ghost"], "prev_tools": ["demo.show"]},
        base_rev=store.identity_revision("bot"),
    )
    _propose_delete(env)
    async with client(env["app"]) as c:
        await login(c, "eye")
        items = (await c.get(f"{API}/requests/pending")).json()
    by_action = {i["action"]: i["review"] for i in items}
    grant = by_action["grant_set"]
    assert grant["headline"] == "identity bot: +1 -0, 1 unchanged"
    assert grant["tools"] == [
        {"id": "demo.ghost", "marker": "+", "state": "missing", "title": "", "category": ""}
    ]
    assert by_action["tool_delete"]["tools"][0]["state"] == "enabled"


async def test_approve_and_reject_a_proposal(env):
    first, second = _propose_delete(env), _propose_delete(env, "demo.echo")
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        approved = await c.post(f"{API}/requests/pending/{first.id}/approve", headers=_h(admin))
        assert approved.status_code == 200, approved.text
        assert approved.json() == {"id": first.id, "status": "approved"}
        assert env["service"].catalog.flat_spec_of("demo.show") is None

        rejected = await c.post(
            f"{API}/requests/pending/{second.id}/reject", json={"reason": "not now"},
            headers=_h(admin),
        )
        assert rejected.json()["status"] == "rejected"
        assert env["pending"].get(second.id).reason == "not now"

        again = await c.post(f"{API}/requests/pending/{first.id}/approve", headers=_h(admin))
        assert again.status_code == 400
        missing = await c.post(f"{API}/requests/pending/nope/approve", headers=_h(admin))
        assert missing.status_code == 404


async def test_approve_all_applies_only_the_listed_ids(env):
    first, second = _propose_delete(env), _propose_delete(env, "demo.echo")
    late = env["pending"].propose(
        action="tool_enable", actor="hermes", payload={"id": "demo.show"},
        base_rev=env["store"].tool_revision("demo.show"),
    )
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        result = await c.post(
            f"{API}/requests/pending/approve-all", json={"ids": [first.id, second.id]},
            headers=_h(admin),
        )
    assert result.status_code == 200
    assert result.json() == {"applied": 2, "refused": []}
    assert env["pending"].get(late.id).status in ("pending", "stale")
    assert env["pending"].get(late.id).status != "approved"


async def test_a_credential_proposal_is_approved_only_with_a_typed_value(env, monkeypatch):
    monkeypatch.setenv("GATEKEEPER_CREDENTIAL_KEY", generate_master_key())
    item = env["pending"].propose(
        action="cred_propose", actor="hermes",
        payload={"name": "sonarr-key", "kind": "bearer", "header": None, "probe_url": None},
        base_rev=env["credentials"].revision(),
    )
    secret = "sk-typed-by-a-human-42"
    async with client(env["app"]) as c:
        admin = await login(c, "root")
        plain = await c.post(f"{API}/requests/pending/{item.id}/approve", headers=_h(admin))
        assert plain.status_code == 400
        filled = await c.post(
            f"{API}/requests/pending/{item.id}/credential", json={"value": secret},
            headers=_h(admin),
        )
        assert filled.status_code == 200, filled.text
        assert filled.json()["status"] == "approved"
        listing = await c.get(f"{API}/requests/pending")
        assert secret not in listing.text
    assert [m.name for m in env["credentials"].names()] == ["sonarr-key"]
    assert secret not in json.dumps(audit_records(env))


async def test_toolkit_deploy_needs_confirm_and_reloads_tier1(env, tier1):
    queue = env["toolkit_proposals"]
    python = tier1.toolkits["demo"].binaries[0]
    item = queue.propose(name="extra", spec={"executor": "local", "binaries": [python]}, actor="hermes")
    other = queue.propose(name="other", spec={"executor": "local", "binaries": [python]}, actor="hermes")
    async with client(env["app"]) as c:
        await login(c, "eye")
        listing = (await c.get(f"{API}/requests/toolkits")).json()
        assert "extra:" in next(p for p in listing if p["id"] == item.id)["spec_yaml"]
        await c.delete(f"{API}/session")
        admin = await login(c, "root")
        unconfirmed = await c.post(
            f"{API}/requests/toolkits/{item.id}/deploy", json={}, headers=_h(admin)
        )
        assert unconfirmed.status_code == 422
        assert queue.get(item.id).status == "pending"
        deployed = await c.post(
            f"{API}/requests/toolkits/{item.id}/deploy", json={"confirm": True}, headers=_h(admin)
        )
        assert deployed.status_code == 200, deployed.text
        assert deployed.json()["status"] == "deployed"
        assert "extra" in env["service"].tier1.toolkits
        rejected = await c.post(
            f"{API}/requests/toolkits/{other.id}/reject", json={"reason": "no"}, headers=_h(admin)
        )
        assert rejected.json()["status"] == "rejected"
    # Written to the file too, so a restart keeps it.
    assert "extra" in load_tier1(queue.toolkits_path).toolkits
