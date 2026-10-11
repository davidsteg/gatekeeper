"""`/api/v1` reads: the legacy console's pages as data.

Beyond "the numbers match", two properties matter here: a credential
value never leaves the process on any route (FR-10.2), and neither does a
token or password hash. Both are checked by scanning *every* response for
the known plaintext/hash, not by looking at one field.
"""

from __future__ import annotations

import json
import time

import pytest
from api_env import API, audit_records, client, login, make_env

from gatekeeper import __version__
from gatekeeper.credentials import generate_master_key


@pytest.fixture
def env(tmp_path, tier1, tool_specs):
    return make_env(tmp_path, tier1, tool_specs)


def _write_audit(env: dict, records: list[dict]) -> None:
    with open(env["audit_path"], "a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


async def test_overview(env):
    _write_audit(env, [
        {"ts": _now(), "kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "ok"},
        {"ts": _now(), "kind": "call", "identity": "bot", "tool": "demo.show", "outcome": "denied"},
    ])
    async with client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/overview")).json()
    assert body["stats"] == {
        "tools_active": 2, "identities": 3, "protected_resources": 2, "tools_disabled": 0,
    }
    assert body["outcomes"]["ok"] == 1 and body["outcomes"]["denied"] == 1
    assert body["outcomes"]["success_pct"] == 50
    assert len(body["activity"]) == 12
    assert body["activity"][-1]["ok"] == 1 and body["activity"][-1]["not_ok"] == 1
    assert body["notices"]["pending_changes"] == 0
    (row,) = body["access"]["rows"]
    assert row["identity"] == "bot"
    (cell,) = row["cells"]
    assert cell == {
        "toolkit": "demo", "granted": ["demo.show"],
        "calls": {"ok": 1, "denied": 1, "failed": 0, "total": 2},
    }
    # Newest first; the sign-in that opened this session is newer still.
    calls = [r for r in body["recent"] if r.get("kind") == "call"]
    assert [r["outcome"] for r in calls] == ["denied", "ok"]


async def test_tools_list_and_detail(env):
    async with client(env["app"]) as c:
        await login(c, "eye")
        response = await c.get(f"{API}/tools")
        assert response.headers["etag"] == f'"{env["store"].tools_revision()}"'
        body = response.json()
        ids = [t["id"] for t in body["tools"]]
        assert ids == ["demo.echo", "demo.show"]
        show = body["tools"][1]
        assert show["grantees"] == ["bot"]
        params = {p["name"]: p for p in show["parameters"]}
        assert params["compose_path"]["derived"]
        assert params["stack"]["pattern"] == "^[a-z0-9][a-z0-9_-]{0,62}$"

        detail = (await c.get(f"{API}/tools/demo.show")).json()
        assert detail["id"] == "demo.show"
        assert "id: demo.show" in detail["yaml"]
        assert detail["current_version"] == 1
        assert [t["id"] for t in detail["tools"]] == ["demo.show"]

        missing = await c.get(f"{API}/tools/demo.nope")
        assert missing.status_code == 404
        assert "demo.nope" in missing.json()["error"]


async def test_identities_never_carry_a_hash(env):
    async with client(env["app"]) as c:
        await login(c, "eye")
        response = await c.get(f"{API}/identities")
    assert response.headers["etag"] == f'"{env["store"].identities_revision()}"'
    body = response.json()
    assert [(i["id"], i["role"], i["console"]) for i in body] == [
        ("bot", "agent", "api_only"), ("eye", "viewer", "access"), ("root", "admin", "access"),
    ]
    for ident in env["identities"].identities.values():
        for secret in (ident.token_hash, ident.password_hash, ident.token_lookup):
            if secret:
                assert secret not in response.text
    assert "hash" not in response.text


async def test_unknown_grants_are_flagged(env, tmp_path):
    import yaml

    path = env["store"].identities_path
    data = yaml.safe_load(open(path, encoding="utf-8"))
    data["identities"][2]["tools"].append("demo.ghost")
    open(path, "w", encoding="utf-8").write(yaml.safe_dump(data))
    from gatekeeper.identity import load_identities

    env["identities"].identities = load_identities(path).identities
    async with client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/identities")).json()
    bot = next(i for i in body if i["id"] == "bot")
    assert bot["unknown_tools"] == ["demo.ghost"]


async def test_no_route_ever_returns_a_credential_value(env, monkeypatch):
    """FR-10.2, as a negative test over the whole read surface: create a
    credential with a known plaintext and look for it in every response."""
    monkeypatch.setenv("GATEKEEPER_CREDENTIAL_KEY", generate_master_key())
    plaintext = "sk-very-secret-value-0123456789"
    credentials = env["credentials"]
    credentials.create(
        "demo-key", kind="bearer", value=plaintext, actor="root", rev=credentials.revision()
    )
    from test_api_auth import _get_paths

    async with client(env["app"]) as c:
        await login(c, "root")
        listing = await c.get(f"{API}/credentials")
        assert listing.status_code == 200
        body = listing.json()
        assert body["configured"] is True
        (meta,) = body["credentials"]
        assert meta["name"] == "demo-key" and meta["kind"] == "bearer"
        assert "value" not in meta
        assert listing.headers["etag"] == f'"{credentials.revision()}"'
        for path in _get_paths(streams=False) + ["/openapi.json"]:
            response = await c.get(f"{API}{path}")
            assert response.status_code == 200, path
            assert plaintext not in response.text, path
            # Nor any of the ciphertext, which is one key away from it.
            raw = open(credentials.path, encoding="utf-8").read()
            for line in raw.splitlines():
                token = line.split(":", 1)[-1].strip()
                if token.startswith("gAAAA"):
                    assert token not in response.text, path


async def test_credentials_report_dangling_references(env):
    async with client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/credentials")).json()
    assert body == {"configured": True, "credentials": [], "dangling": []}


async def test_toolkits_are_readable(env):
    async with client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/toolkits")).json()
        (demo,) = body["toolkits"]
        assert demo["name"] == "demo" and demo["executor"] == "local"
        assert demo["protected_resources"] == ["gatekeeper", "dockhand"]
        reference = (await c.get(f"{API}/toolkits/reference")).json()
        assert reference and all("toolkits" not in r["key"] for r in reference)
        assert all(r["toolkit_yaml"] for r in reference)


async def test_integrations_and_logo(env):
    async with client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/integrations")).json()
        assert body and all(not i["toolkit_configured"] for i in body)
        key = body[0]["key"]
        logo = await c.get(f"{API}/integrations/{key}/logo.svg")
        assert logo.status_code == 200
        assert logo.headers["content-type"].startswith("image/svg+xml")
        assert "sandbox" in logo.headers["content-security-policy"]
        assert (await c.get(f"{API}/integrations/nope/logo.svg")).status_code == 404


async def test_pending_requests(env):
    pending = env["pending"]
    item = pending.propose(
        action="tool_enable", actor="root",
        payload={"id": "demo.echo", "enabled": False},
        base_rev=env["store"].tools_revision(),
    )
    async with client(env["app"]) as c:
        await login(c, "eye")
        response = await c.get(f"{API}/requests/pending")
        assert response.headers["etag"] == f'"{pending.revision()}"'
        (got,) = response.json()
        assert got["id"] == item.id and got["status"] == "pending"
        assert (await c.get(f"{API}/requests/pending?status=approved")).json() == []
        overview = (await c.get(f"{API}/overview")).json()
        assert overview["notices"]["pending_changes"] == 1


async def test_toolkit_proposals(env):
    """A proposal comes with the live toolkit it would change, for the
    reviewer's diff -- and `None` for a toolkit that does not exist yet."""
    proposals = env["toolkit_proposals"]
    update = proposals.propose(
        name="demo", kind="update", spec={"denied_args": ["--dangerous", "rm", "--force"]}, actor="root"
    )
    async with client(env["app"]) as c:
        await login(c, "eye")
        response = await c.get(f"{API}/requests/toolkits")
        assert response.headers["etag"] == f'"{proposals.revision()}"'
        (item,) = response.json()
    assert item["id"] == update.id and item["kind"] == "update"
    assert item["spec"] == {"denied_args": ["--dangerous", "rm", "--force"]}
    assert item["current"]["name"] == "demo"
    assert item["current"]["denied_args"] == ["--dangerous", "rm"]


async def test_audit_pagination(env):
    _write_audit(env, [
        {"ts": _now(), "kind": "call", "identity": "bot", "tool": "demo.show",
         "outcome": "ok" if i % 2 else "denied", "n": i}
        for i in range(25)
    ])
    async with client(env["app"]) as c:
        await login(c, "eye")
        seen: list[int] = []
        cursor = None
        while True:
            url = f"{API}/audit?limit=10&tool=demo.show" + (f"&cursor={cursor}" if cursor else "")
            page = (await c.get(url)).json()
            seen.extend(r["n"] for r in page["entries"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert seen == list(range(24, -1, -1))

        denied = (await c.get(f"{API}/audit?outcome=denied&limit=500")).json()
        assert {r["outcome"] for r in denied["entries"]} == {"denied"}
        assert len(denied["entries"]) == 13

        assert (await c.get(f"{API}/audit?cursor=not-a-cursor")).status_code == 400
        assert (await c.get(f"{API}/audit?outcome=bogus")).status_code == 422
        assert (await c.get(f"{API}/audit?limit=0")).status_code == 422


async def test_release_notes(env):
    async with client(env["app"]) as c:
        await login(c, "eye")
        body = (await c.get(f"{API}/release-notes?limit=1")).json()
    assert body["version"] == __version__
    assert len(body["releases"]) == 1
    assert body["releases"][0]["version"] == __version__


async def test_reads_work_in_read_only_mode(tmp_path, tier1, tool_specs):
    env = make_env(tmp_path, tier1, tool_specs, read_only=True)
    from test_api_auth import _get_paths

    async with client(env["app"]) as c:
        await login(c, "eye")
        for path in _get_paths(streams=False):
            assert (await c.get(f"{API}{path}")).status_code == 200, path
        account = (await c.get(f"{API}/account")).json()
        assert account["can_change_password"] is False


async def test_reads_write_no_audit_records(env):
    """Only the login and the session itself may be logged by a read."""
    async with client(env["app"]) as c:
        await login(c, "root")
        before = len(audit_records(env))
        from test_api_auth import _get_paths

        for path in _get_paths(streams=False):
            await c.get(f"{API}{path}")
    assert len(audit_records(env)) == before
