"""`admin.cred_update`: change a credential slot's kind/header/name in place.

The case behind it: a `jellyfin` slot created with header `X-Emby-Token`
for a server that wants `Authorization`. The token was fine; the header
was wrong; and the only repair was a throwaway anchor slot, two binds, a
delete and a human pasting the same secret again. These tests pin that a
proposal now carries no value, waits for a human, keeps the stored secret
byte for byte, and refuses the changes that would quietly break something
(a rename under a binding, a token turned into a TLS bundle).
"""

from __future__ import annotations

import json

import pytest
import yaml
from api_env import API, client, login, make_env

from gatekeeper.admin_service import AdminActionError, AdminService, apply_pending
from gatekeeper.credentials import KEY_ENV, WriteRefused, generate_master_key
from gatekeeper.pending import STALE_CHANGED_REASON, STALE_TAKEN_REASON, PendingWriteRefused
from gatekeeper.store import WriteRefused as StoreWriteRefused
from gatekeeper.tier1 import load_tier1

SECRET = "jellyfin-token-0123456789abcdef"


def _tier1(tmp_path, *, bound: bool):
    toolkit = {
        "executor": "http",
        "base_url": "https://jellyfin.lan",
        "allowed_methods": ["GET", "POST"],
        "allowed_path_prefixes": ["/Library/"],
        "allowed_cidrs": ["10.0.0.0/8"],
        "max_timeout_seconds": 10,
        "max_output_bytes": 65536,
    }
    if bound:
        toolkit["credential"] = "jellyfin"
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {"toolkits": {"jellyfin": toolkit}, "audit": {"dir": str(tmp_path / "logs")}}
        ),
        encoding="utf-8",
    )
    return load_tier1(str(path))


@pytest.fixture
def make(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())

    def _make(*, bound: bool = True):
        env = make_env(tmp_path, _tier1(tmp_path, bound=bound), [])
        env["credentials"].create(
            "jellyfin", kind="api_key_header", header="X-Emby-Token", value=SECRET,
            actor="root", rev="",
        )
        env["admin"] = AdminService(
            store=env["store"], pending=env["pending"],
            toolkit_proposals=env["toolkit_proposals"], credentials=env["credentials"],
        )
        return env

    return _make


def _meta(env, name="jellyfin"):
    return next(m for m in env["credentials"].names() if m.name == name)


def _approve(env, item_id):
    return apply_pending(
        env["store"], env["pending"], item_id, decided_by="root",
        credentials=env["credentials"],
    )


def _audit(env):
    with open(env["audit_path"], encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def test_header_repair_on_a_bound_slot_keeps_the_value(make):
    env = make()
    credentials = env["credentials"]
    credentials.mark_suspect("jellyfin")
    result = env["admin"].cred_update("hermes", {"name": "jellyfin", "header": "Authorization"})
    assert result["applied"] is False and result["pending"] is True
    # Nothing changes until a human approves.
    assert _meta(env).header == "X-Emby-Token"

    _approve(env, result["pending_id"])

    meta = _meta(env)
    assert (meta.kind, meta.header) == ("api_key_header", "Authorization")
    # The old 401 was about the old header; a repaired slot starts clean.
    assert meta.suspect_status is None
    assert credentials._resolve("jellyfin").value == SECRET
    assert env["pending"].get(result["pending_id"]).status == "approved"


def test_proposal_and_audit_carry_no_value(make):
    env = make()
    result = env["admin"].cred_update("hermes", {"name": "jellyfin", "header": "Authorization"})
    _approve(env, result["pending_id"])
    lines = _audit(env)
    assert all(SECRET not in json.dumps(line) for line in lines)
    (update,) = [line for line in lines if line.get("action") == "credential_update"]
    assert update["target"] == "jellyfin"
    assert update["header"] == "Authorization"
    assert update["changed"] == ["header"]
    assert SECRET not in open(env["pending"].path, encoding="utf-8").read()


@pytest.mark.parametrize("arg", ["value", "secret", "token", "api_key"])
def test_value_shaped_arguments_are_refused(make, arg):
    env = make()
    with pytest.raises(AdminActionError, match=arg) as caught:
        env["admin"].cred_update("hermes", {"name": "jellyfin", arg: "sneaked-in"})
    assert "sneaked-in" not in str(caught.value)
    assert env["pending"].list() == []


def test_unknown_slot_is_refused_by_name(make):
    env = make()
    with pytest.raises(AdminActionError, match="nope"):
        env["admin"].cred_update("hermes", {"name": "nope", "header": "Authorization"})


def test_a_proposal_that_changes_nothing_is_refused(make):
    env = make()
    with pytest.raises(AdminActionError, match="Nothing to change"):
        env["admin"].cred_update("hermes", {"name": "jellyfin", "header": "X-Emby-Token"})
    assert env["pending"].list() == []


def test_kind_changes_only_within_one_value_shape(make):
    env = make()
    with pytest.raises(AdminActionError, match="docker_tls"):
        env["admin"].cred_update("hermes", {"name": "jellyfin", "kind": "docker_tls"})
    # The store refuses it too, whoever calls it.
    with pytest.raises(WriteRefused, match="oauth2"):
        env["credentials"].update(
            "jellyfin", kind="oauth2", header=None, probe_url=None, actor="root",
            rev=env["credentials"].revision(),
        )


def test_switching_to_a_headerless_kind_drops_the_header(make):
    env = make()
    result = env["admin"].cred_update("hermes", {"name": "jellyfin", "kind": "bearer"})
    assert env["pending"].get(result["pending_id"]).payload["header"] is None
    _approve(env, result["pending_id"])
    meta = _meta(env)
    assert (meta.kind, meta.header) == ("bearer", None)
    with pytest.raises(AdminActionError, match="takes no 'header'"):
        env["admin"].cred_update(
            "hermes", {"name": "jellyfin", "kind": "url_path", "header": "X-Token"}
        )


@pytest.mark.parametrize("header", ["X-Token\r\nX-Evil: 1", "Bad Header", "a:b"])
def test_a_header_that_is_not_a_header_name_is_refused(make, header):
    env = make()
    with pytest.raises(AdminActionError, match="not a valid header"):
        env["admin"].cred_update("hermes", {"name": "jellyfin", "header": header})


def test_rename_is_refused_while_bound(make):
    env = make(bound=True)
    with pytest.raises(AdminActionError, match="still referenced"):
        env["admin"].cred_update("hermes", {"name": "jellyfin", "new_name": "jellyfin2"})
    assert env["pending"].list() == []


def test_rename_of_an_unbound_slot_keeps_the_value(make):
    env = make(bound=False)
    result = env["admin"].cred_update(
        "hermes", {"name": "jellyfin", "new_name": "jellyfin-main", "header": "Authorization"}
    )
    _approve(env, result["pending_id"])
    assert [m.name for m in env["credentials"].names()] == ["jellyfin-main"]
    assert env["credentials"]._resolve("jellyfin-main").value == SECRET
    (update,) = [line for line in _audit(env) if line.get("action") == "credential_update"]
    assert update["new_name"] == "jellyfin-main"
    assert update["changed"] == ["name", "header"]


def test_rename_onto_a_taken_name_is_refused_and_later_closed(make):
    env = make(bound=False)
    credentials = env["credentials"]
    credentials.create("emby", kind="bearer", value="other", actor="root", rev="")
    with pytest.raises(AdminActionError, match="already exists"):
        env["admin"].cred_update("hermes", {"name": "jellyfin", "new_name": "emby"})
    # Free at propose time, taken before anyone approves: the sweep closes it.
    result = env["admin"].cred_update("hermes", {"name": "jellyfin", "new_name": "media"})
    credentials.create("media", kind="bearer", value="x", actor="root", rev="")
    env["admin"].pending_list("hermes", {})
    closed = env["pending"].get(result["pending_id"])
    assert closed.status == "stale" and closed.reason == STALE_TAKEN_REASON


def test_a_slot_changed_meanwhile_makes_the_proposal_stale(make):
    env = make()
    first = env["admin"].cred_update("hermes", {"name": "jellyfin", "header": "Authorization"})
    second = env["admin"].cred_update("hermes", {"name": "jellyfin", "header": "X-Token"})
    _approve(env, first["pending_id"])
    with pytest.raises(PendingWriteRefused, match="stale"):
        _approve(env, second["pending_id"])
    item = env["pending"].get(second["pending_id"])
    assert item.status == "stale" and item.reason == STALE_CHANGED_REASON
    assert _meta(env).header == "Authorization"


def test_a_failing_call_meanwhile_does_not_make_the_repair_stale(make):
    """The repair is proposed *because* calls fail with 401, and every such
    call marks the slot suspect. That must not stale the fix for it."""
    env = make()
    result = env["admin"].cred_update("hermes", {"name": "jellyfin", "header": "Authorization"})
    env["credentials"].mark_suspect("jellyfin")
    _approve(env, result["pending_id"])
    assert _meta(env).header == "Authorization"


def test_a_deleted_slot_closes_the_proposal_on_listing(make):
    env = make(bound=False)
    result = env["admin"].cred_update("hermes", {"name": "jellyfin", "header": "Authorization"})
    env["credentials"].delete("jellyfin", actor="root", rev=env["credentials"].revision())
    env["admin"].pending_list("hermes", {})
    assert env["pending"].get(result["pending_id"]).status == "stale"


def test_approving_without_a_credential_store_refuses_and_keeps_it_pending(make):
    env = make()
    result = env["admin"].cred_update("hermes", {"name": "jellyfin", "header": "Authorization"})
    with pytest.raises(StoreWriteRefused):
        apply_pending(env["store"], env["pending"], result["pending_id"], decided_by="root")
    assert env["pending"].get(result["pending_id"]).status == "pending"


async def test_console_approves_it_and_shows_the_diff(make):
    env = make()
    result = env["admin"].cred_update("hermes", {"name": "jellyfin", "header": "Authorization"})
    async with client(env["app"]) as c:
        info = await login(c, "root")
        items = (await c.get(f"{API}/requests/pending")).json()
        (item,) = [i for i in items if i["id"] == result["pending_id"]]
        assert item["review"]["headline"] == (
            "credential jellyfin: header X-Emby-Token -> Authorization (stored value kept)"
        )
        r = await c.post(
            f"{API}/requests/pending/{result['pending_id']}/approve",
            headers={"X-CSRF-Token": info["csrf"]},
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "approved"
        assert SECRET not in r.text
    assert _meta(env).header == "Authorization"


# -- header_format: a header value that wraps the secret (Jellyfin) ---------


def test_header_format_is_proposed_and_applied_with_the_header(make):
    env = make()
    result = env["admin"].cred_update(
        "hermes",
        {
            "name": "jellyfin", "header": "Authorization",
            "header_format": 'MediaBrowser Token="{value}"',
        },
    )
    _approve(env, result["pending_id"])
    meta = _meta(env)
    assert (meta.header, meta.header_format) == (
        "Authorization", 'MediaBrowser Token="{value}"',
    )
    assert env["credentials"]._resolve("jellyfin").value == SECRET
    (update,) = [line for line in _audit(env) if line.get("action") == "credential_update"]
    assert update["changed"] == ["header", "header_format"]
    assert all(SECRET not in json.dumps(line) for line in _audit(env))


@pytest.mark.parametrize(
    ("header_format", "reason"),
    [
        ("MediaBrowser Token=x", "exactly once"),
        ("{value} {value}", "exactly once"),
        ('MediaBrowser Token="{value}"\r\nX-Evil: 1', "one line"),
    ],
)
def test_a_header_format_must_be_one_line_with_one_placeholder(make, header_format, reason):
    env = make()
    with pytest.raises(AdminActionError, match=reason):
        env["admin"].cred_update(
            "hermes", {"name": "jellyfin", "header_format": header_format}
        )
    assert env["pending"].list() == []


def test_a_header_format_only_fits_an_api_key_header(make):
    env = make()
    with pytest.raises(AdminActionError, match="api_key_header"):
        env["admin"].cred_update(
            "hermes",
            {"name": "jellyfin", "kind": "bearer", "header_format": "Token {value}"},
        )


def test_switching_away_from_api_key_header_drops_the_format(make):
    env = make()
    first = env["admin"].cred_update(
        "hermes", {"name": "jellyfin", "header_format": "Token {value}"}
    )
    _approve(env, first["pending_id"])
    second = env["admin"].cred_update("hermes", {"name": "jellyfin", "kind": "bearer"})
    assert env["pending"].get(second["pending_id"]).payload["header_format"] is None
    _approve(env, second["pending_id"])
    assert _meta(env).header_format is None


def test_cred_propose_carries_a_header_format_to_the_created_slot(make):
    env = make()
    result = env["admin"].cred_propose(
        "hermes",
        {
            "name": "emby", "kind": "api_key_header", "header": "Authorization",
            "header_format": 'MediaBrowser Token="{value}"',
        },
    )
    item = env["pending"].get(result["pending_id"])
    assert item.payload["header_format"] == 'MediaBrowser Token="{value}"'
    with pytest.raises(AdminActionError, match="exactly once"):
        env["admin"].cred_propose(
            "hermes",
            {"name": "emby2", "kind": "api_key_header", "header": "X", "header_format": "x"},
        )


async def test_console_fill_creates_the_slot_with_its_header_format(make):
    env = make()
    result = env["admin"].cred_propose(
        "hermes",
        {
            "name": "emby", "kind": "api_key_header", "header": "Authorization",
            "header_format": 'MediaBrowser Token="{value}"',
        },
    )
    async with client(env["app"]) as c:
        info = await login(c, "root")
        items = (await c.get(f"{API}/requests/pending")).json()
        (item,) = [i for i in items if i["id"] == result["pending_id"]]
        assert 'value format MediaBrowser Token="{value}"' in item["review"]["headline"]
        r = await c.post(
            f"{API}/requests/pending/{result['pending_id']}/credential",
            json={"value": "emby-secret"}, headers={"X-CSRF-Token": info["csrf"]},
        )
        assert r.status_code == 200, r.text
        listed = (await c.get(f"{API}/credentials")).json()
    (emby,) = [m for m in listed["credentials"] if m["name"] == "emby"]
    assert emby["header_format"] == 'MediaBrowser Token="{value}"'
    assert "emby-secret" not in json.dumps(listed)
