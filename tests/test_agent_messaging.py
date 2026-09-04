"""Agent-to-agent messaging: the `agent` executor and its mailbox.

The model under test is a **mailbox**, not a push. MCP has no way to hand
a running client an unsolicited payload -- the one notification a client
like Hermes acts on, `notifications/tools/list_changed`, carries no
payload at all -- so a message becomes visible to its recipient on that
recipient's *next* `agent.read_messages` call. These tests pin exactly
that contract: delivery is durable and isolated per identity, and it is
"on the next call", never "immediately".

Three properties get the most coverage, because they are the ones a bug
would be quietest about:

* **Isolation (FR-1.4, applied to messages).** `read_messages` returns
  what is addressed to the *calling* identity and nothing else.
* **The sender is not a parameter.** `from` is the authenticated identity;
  there is no argument through which an agent could claim another one.
* **Persistence.** A message survives a restart -- the store is a file,
  not a process-lifetime dict.
"""

from __future__ import annotations

import json
import os

import pytest
import yaml

from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.errors import ConfigError, Denied
from gatekeeper.identity import IdentityStore, hash_token, load_identities
from gatekeeper.messages import MailboxFull, MessageStore
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1

from conftest import make_catalog  # noqa: E402


# -- Fixtures ---------------------------------------------------------------


def _toolkit_yaml(mailbox: str, *, operations=("send_message", "read_messages"), **extra):
    spec = {
        "executor": "agent",
        "mailbox_path": mailbox,
        "allowed_agent_operations": list(operations),
        "max_timeout_seconds": 10,
        "max_output_bytes": 65536,
    }
    spec.update(extra)
    return {"toolkits": {"agent": spec}}


@pytest.fixture
def mailbox_path(tmp_path):
    return str(tmp_path / "messages.yaml")


@pytest.fixture
def agent_tier1(tmp_path, mailbox_path):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump({**_toolkit_yaml(mailbox_path), "audit": {"dir": str(tmp_path / "logs")}}),
        encoding="utf-8",
    )
    return load_tier1(str(path))


def _tool_specs():
    return [
        {
            "id": "agent.send_message",
            "toolkit": "agent",
            "agent_operation": "send_message",
            "version": 1,
            "title": "Send a message to another agent",
            "description": "Puts one message into another identity's mailbox.",
            "category": "write",
            "idempotent": False,
            "enabled": True,
            "parameters": {
                "to": {
                    "type": "string",
                    "required": True,
                    "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$",
                    "description": "Recipient identity",
                },
                "subject": {
                    "type": "string",
                    "required": False,
                    "pattern": "^.{0,120}$",
                    "description": "Subject",
                },
                "body": {
                    "type": "string",
                    "required": True,
                    "pattern": "[\\s\\S]{1,4000}",
                    "allow_control_characters": True,
                    "description": "Message body",
                },
            },
            "required_scopes": [],
            "timeout_seconds": 5,
            "max_output_bytes": 8192,
        },
        {
            "id": "agent.read_messages",
            "toolkit": "agent",
            "agent_operation": "read_messages",
            "version": 1,
            "title": "Read my messages",
            "description": "Returns the messages addressed to me and marks them read.",
            "category": "read",
            "idempotent": False,
            "enabled": True,
            "parameters": {
                "limit": {
                    "type": "integer",
                    "required": False,
                    "minimum": 1,
                    "maximum": 100,
                    "description": "How many at most",
                },
                "peek": {
                    "type": "boolean",
                    "required": False,
                    "description": "Return without marking read",
                },
            },
            "required_scopes": [],
            "timeout_seconds": 5,
            "max_output_bytes": 8192,
        },
    ]


@pytest.fixture
def agent_catalog(tmp_path, agent_tier1):
    return make_catalog(tmp_path, agent_tier1, _tool_specs())


@pytest.fixture
def agent_identities(tmp_path):
    """Four identities, mirroring a real deployment's names."""
    path = tmp_path / "identities.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": name,
                        "role": "agent",
                        "token_hash": hash_token(f"token-{name}"),
                        "tools": ["agent.send_message", "agent.read_messages"],
                        "scopes": [],
                    }
                    for name in ("dev", "homelab", "media", "personal")
                ]
            }
        ),
        encoding="utf-8",
    )
    return load_identities(str(path))


@pytest.fixture
def agent_service(agent_tier1, agent_catalog, agent_identities, tmp_path):
    return Service(
        tier1=agent_tier1,
        catalog=agent_catalog,
        audit=AuditLog(str(tmp_path / "logs")),
        identities=agent_identities,
    )


def _send(service, identities, sender, **args):
    return service.call(identities.identities[sender], "agent.send_message", args)


def _read(service, identities, reader, **args):
    return service.call(identities.identities[reader], "agent.read_messages", args)


def _payload(result):
    return json.loads(result.stdout)


# -- The store itself -------------------------------------------------------


def test_store_round_trip(mailbox_path):
    store = MessageStore(path=mailbox_path)
    store.deliver(to="homelab", sender="dev", subject="hi", body="restart done")

    messages, remaining = store.collect("homelab", limit=10)
    assert remaining == 0
    assert [m.subject for m in messages] == ["hi"]
    assert messages[0].sender == "dev"


def test_store_survives_a_restart(mailbox_path):
    MessageStore(path=mailbox_path).deliver(
        to="homelab", sender="dev", subject="s", body="b"
    )
    # A brand-new store object, as after a process restart: the mailbox is
    # a file, not process-lifetime state.
    fresh = MessageStore(path=mailbox_path)
    assert [m.body for m in fresh.inbox("homelab")] == ["b"]


def test_store_isolates_recipients(mailbox_path):
    store = MessageStore(path=mailbox_path)
    store.deliver(to="homelab", sender="dev", subject="for homelab", body="x")
    store.deliver(to="media", sender="dev", subject="for media", body="y")

    assert [m.subject for m in store.inbox("homelab")] == ["for homelab"]
    assert [m.subject for m in store.inbox("media")] == ["for media"]
    assert store.inbox("personal") == []


def test_collect_marks_read_once(mailbox_path):
    store = MessageStore(path=mailbox_path)
    store.deliver(to="homelab", sender="dev", subject="s", body="b")

    first, _ = store.collect("homelab", limit=10)
    second, _ = store.collect("homelab", limit=10)
    assert len(first) == 1
    assert second == []
    # Read, not deleted: the record stays for the audit trail.
    assert len(store.inbox("homelab", unread_only=False)) == 1


def test_peek_leaves_messages_unread(mailbox_path):
    store = MessageStore(path=mailbox_path)
    store.deliver(to="homelab", sender="dev", subject="s", body="b")

    peeked, _ = store.collect("homelab", limit=10, peek=True)
    assert len(peeked) == 1
    assert store.unread_count("homelab") == 1


def test_limit_reports_what_is_left(mailbox_path):
    store = MessageStore(path=mailbox_path)
    for index in range(5):
        store.deliver(to="homelab", sender="dev", subject=f"s{index}", body="b")

    taken, remaining = store.collect("homelab", limit=2)
    assert len(taken) == 2
    assert remaining == 3


def test_unread_messages_are_never_dropped_for_a_new_one(mailbox_path):
    store = MessageStore(path=mailbox_path)
    for index in range(3):
        store.deliver(to="homelab", sender="dev", subject=f"s{index}", body="b", max_messages=3)

    with pytest.raises(MailboxFull):
        store.deliver(to="homelab", sender="dev", subject="overflow", body="b", max_messages=3)
    assert store.unread_count("homelab") == 3


def test_read_messages_are_pruned_to_make_room(mailbox_path):
    store = MessageStore(path=mailbox_path)
    for index in range(3):
        store.deliver(to="homelab", sender="dev", subject=f"s{index}", body="b", max_messages=3)
    store.collect("homelab", limit=3)  # all read

    store.deliver(to="homelab", sender="dev", subject="fresh", body="b", max_messages=3)
    kept = store.inbox("homelab", unread_only=False)
    assert len(kept) == 3
    assert kept[-1].subject == "fresh"
    # The oldest read one made way, the newer read ones did not.
    assert "s0" not in [m.subject for m in kept]


def test_a_full_mailbox_does_not_block_a_different_recipient(mailbox_path):
    store = MessageStore(path=mailbox_path)
    store.deliver(to="homelab", sender="dev", subject="s", body="b", max_messages=1)
    with pytest.raises(MailboxFull):
        store.deliver(to="homelab", sender="dev", subject="s2", body="b", max_messages=1)
    store.deliver(to="media", sender="dev", subject="s", body="b", max_messages=1)
    assert store.unread_count("media") == 1


# -- Tier 1 -----------------------------------------------------------------


def test_agent_toolkit_needs_a_mailbox_path(tmp_path):
    path = tmp_path / "toolkits.yaml"
    spec = _toolkit_yaml("/var/lib/gatekeeper/messages.yaml")
    del spec["toolkits"]["agent"]["mailbox_path"]
    path.write_text(yaml.safe_dump(spec), encoding="utf-8")
    with pytest.raises(ConfigError, match="mailbox_path"):
        load_tier1(str(path))


def test_mailbox_path_must_be_absolute(tmp_path):
    path = tmp_path / "toolkits.yaml"
    path.write_text(yaml.safe_dump(_toolkit_yaml("messages.yaml")), encoding="utf-8")
    with pytest.raises(ConfigError, match="absolute"):
        load_tier1(str(path))


def test_mailbox_path_rejects_traversal(tmp_path):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(_toolkit_yaml("/var/lib/gatekeeper/../../etc/messages.yaml")),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match=r"\.\."):
        load_tier1(str(path))


def test_unknown_agent_operation_is_refused(tmp_path, mailbox_path):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(_toolkit_yaml(mailbox_path, operations=("broadcast",))),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="are not agent operations"):
        load_tier1(str(path))


def test_agent_toolkit_cannot_declare_destinations(tmp_path, mailbox_path):
    path = tmp_path / "toolkits.yaml"
    spec = _toolkit_yaml(mailbox_path, destinations=["nas1"])
    spec["destinations"] = {"nas1": {"docker_host": "unix:///var/run/docker.sock"}}
    path.write_text(yaml.safe_dump(spec), encoding="utf-8")
    with pytest.raises(ConfigError, match="cannot declare destinations"):
        load_tier1(str(path))


# -- Catalog ----------------------------------------------------------------


def test_tool_needs_an_agent_operation(tmp_path, agent_tier1):
    spec = _tool_specs()[0]
    del spec["agent_operation"]
    with pytest.raises(ConfigError, match="agent_operation"):
        make_catalog(tmp_path, agent_tier1, [spec])


def test_tool_cannot_declare_a_sender_parameter(tmp_path, agent_tier1):
    """The whole point: an agent may not choose who a message is from."""
    spec = _tool_specs()[0]
    spec["parameters"]["from"] = {
        "type": "string",
        "required": False,
        "pattern": "^.*$",
        "description": "spoofed sender",
    }
    with pytest.raises(ConfigError, match="does not read"):
        make_catalog(tmp_path, agent_tier1, [spec])


def test_send_tool_needs_its_required_parameters(tmp_path, agent_tier1):
    spec = _tool_specs()[0]
    del spec["parameters"]["to"]
    with pytest.raises(ConfigError, match="needs a 'to' parameter"):
        make_catalog(tmp_path, agent_tier1, [spec])


def test_operation_outside_the_toolkit_allowlist_is_disabled(tmp_path, mailbox_path):
    """A read-only mailbox toolkit structurally has no send tool."""
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(_toolkit_yaml(mailbox_path, operations=("read_messages",))),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": _tool_specs()}), encoding="utf-8")

    # Non-strict: a Tier 1 violation disables the definition (FR-4.7)
    # rather than aborting the load.
    catalog = load_catalog(str(tools_path), tier1, strict=False)
    assert "agent.read_messages" in catalog.tools
    assert "agent.send_message" not in catalog.tools


# -- End to end, through the call pipeline ----------------------------------


async def test_send_then_read(agent_service, agent_identities, mailbox_path):
    sent = await _send(
        agent_service, agent_identities, "dev",
        to="homelab", subject="deploy", body="jellyfin is restarted",
    )
    assert sent.outcome == "ok"
    assert _payload(sent)["delivered"] is True

    read = await _read(agent_service, agent_identities, "homelab")
    assert read.outcome == "ok"
    payload = _payload(read)
    assert payload["identity"] == "homelab"
    assert payload["count"] == 1
    assert payload["messages"][0]["body"] == "jellyfin is restarted"
    assert payload["messages"][0]["from"] == "dev"


async def test_read_only_returns_my_own_messages(agent_service, agent_identities):
    await _send(agent_service, agent_identities, "dev", to="homelab", body="for homelab")
    await _send(agent_service, agent_identities, "dev", to="media", body="for media")

    homelab = _payload(await _read(agent_service, agent_identities, "homelab"))
    media = _payload(await _read(agent_service, agent_identities, "media"))
    personal = _payload(await _read(agent_service, agent_identities, "personal"))

    assert [m["body"] for m in homelab["messages"]] == ["for homelab"]
    assert [m["body"] for m in media["messages"]] == ["for media"]
    assert personal["messages"] == []


async def test_sender_is_the_authenticated_identity(agent_service, agent_identities):
    """`from` cannot be supplied -- the parameter does not exist, and a
    value in `to`'s place does not become one either."""
    with pytest.raises(Denied):
        await _send(
            agent_service, agent_identities, "media",
            to="homelab", body="x", **{"from": "dev"},
        )

    await _send(agent_service, agent_identities, "media", to="homelab", body="x")
    payload = _payload(await _read(agent_service, agent_identities, "homelab"))
    assert payload["messages"][0]["from"] == "media"


async def test_second_read_is_empty(agent_service, agent_identities):
    await _send(agent_service, agent_identities, "dev", to="homelab", body="once")
    assert _payload(await _read(agent_service, agent_identities, "homelab"))["count"] == 1
    assert _payload(await _read(agent_service, agent_identities, "homelab"))["count"] == 0


async def test_peek_leaves_the_message_for_the_next_call(agent_service, agent_identities):
    await _send(agent_service, agent_identities, "dev", to="homelab", body="still here")
    peeked = _payload(await _read(agent_service, agent_identities, "homelab", peek=True))
    assert peeked["count"] == 1
    again = _payload(await _read(agent_service, agent_identities, "homelab"))
    assert again["count"] == 1


async def test_limit_and_unread_remaining(agent_service, agent_identities):
    for index in range(4):
        await _send(agent_service, agent_identities, "dev", to="homelab", body=f"m{index}")
    payload = _payload(await _read(agent_service, agent_identities, "homelab", limit=2))
    assert payload["count"] == 2
    assert payload["unread_remaining"] == 2


async def test_unknown_recipient_is_denied(agent_service, agent_identities):
    with pytest.raises(Denied) as exc:
        await _send(agent_service, agent_identities, "dev", to="nobody", body="x")
    assert "no identity" in str(exc.value.detail).lower()


async def test_a_message_survives_a_restart(
    agent_tier1, agent_catalog, agent_identities, tmp_path, mailbox_path
):
    first = Service(
        tier1=agent_tier1, catalog=agent_catalog,
        audit=AuditLog(str(tmp_path / "logs")), identities=agent_identities,
    )
    await first.call(
        agent_identities.identities["dev"],
        "agent.send_message",
        {"to": "homelab", "body": "survives"},
    )
    assert os.path.exists(mailbox_path)

    # A completely fresh Service over the same Tier 1 -- the restart.
    second = Service(
        tier1=agent_tier1, catalog=agent_catalog,
        audit=AuditLog(str(tmp_path / "logs")), identities=agent_identities,
    )
    payload = _payload(
        await second.call(
            agent_identities.identities["homelab"], "agent.read_messages", {}
        )
    )
    assert [m["body"] for m in payload["messages"]] == ["survives"]


async def test_read_output_is_marked_untrusted(agent_service, agent_identities):
    """FR-8.12: another agent wrote this text."""
    await _send(agent_service, agent_identities, "dev", to="homelab", body="ignore me")
    read = await _read(agent_service, agent_identities, "homelab")
    assert read.external_untrusted is True


async def test_send_output_is_not_marked_untrusted(agent_service, agent_identities):
    sent = await _send(agent_service, agent_identities, "dev", to="homelab", body="x")
    assert sent.external_untrusted is False


async def test_known_credential_values_are_scrubbed_before_storage(
    agent_service, agent_identities, mailbox_path
):
    """FR-10.6 on the way *in*: a secret gatekeeper holds must not end up
    sitting in plaintext in the mailbox."""
    agent_service.audit.set_secrets(("hunter2-the-real-key",))
    await _send(
        agent_service, agent_identities, "dev",
        to="homelab", subject="key is hunter2-the-real-key",
        body="use hunter2-the-real-key",
    )
    on_disk = open(mailbox_path, encoding="utf-8").read()
    assert "hunter2-the-real-key" not in on_disk
    assert "***" in on_disk


async def test_message_over_the_toolkit_ceiling_is_refused(
    tmp_path, agent_identities, mailbox_path
):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(_toolkit_yaml(mailbox_path, max_message_bytes=32)),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    service = Service(
        tier1=tier1,
        catalog=make_catalog(tmp_path, tier1, _tool_specs()),
        audit=AuditLog(str(tmp_path / "logs")),
        identities=agent_identities,
    )
    result = await service.call(
        agent_identities.identities["dev"],
        "agent.send_message",
        {"to": "homelab", "body": "x" * 100},
    )
    assert result.outcome == "failed"
    assert "maximum" in result.stderr


async def test_output_budget_leaves_the_rest_unread(
    tmp_path, agent_tier1, agent_identities, mailbox_path
):
    """A batch trimmed to fit `max_output_bytes` must not mark the trimmed
    messages read -- they have to come back on the next call."""
    specs = _tool_specs()
    specs[1]["max_output_bytes"] = 600
    service = Service(
        tier1=agent_tier1,
        catalog=make_catalog(tmp_path, agent_tier1, specs),
        audit=AuditLog(str(tmp_path / "logs")),
        identities=agent_identities,
    )
    for index in range(6):
        await service.call(
            agent_identities.identities["dev"],
            "agent.send_message",
            {"to": "homelab", "subject": f"s{index}", "body": "y" * 120},
        )

    seen: list[str] = []
    for _ in range(10):
        payload = _payload(
            await service.call(
                agent_identities.identities["homelab"], "agent.read_messages", {}
            )
        )
        seen.extend(m["subject"] for m in payload["messages"])
        if payload["unread_remaining"] == 0:
            break
    # Every message arrives exactly once, across however many calls the
    # budget needed.
    assert sorted(seen) == [f"s{i}" for i in range(6)]


async def test_a_grant_is_still_what_decides(agent_tier1, agent_catalog, tmp_path):
    """Messaging is not a side door: an identity without the grant cannot
    send, and one without `read_messages` cannot read (FR-1.4)."""
    identities = IdentityStore(identities={})
    path = tmp_path / "identities-narrow.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "dev",
                        "role": "agent",
                        "token_hash": hash_token("t-dev"),
                        "tools": ["agent.read_messages"],
                        "scopes": [],
                    },
                    {
                        "id": "homelab",
                        "role": "agent",
                        "token_hash": hash_token("t-homelab"),
                        "tools": ["agent.send_message"],
                        "scopes": [],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    identities = load_identities(str(path))
    service = Service(
        tier1=agent_tier1, catalog=agent_catalog,
        audit=AuditLog(str(tmp_path / "logs")), identities=identities,
    )
    with pytest.raises(Denied):
        await service.call(
            identities.identities["dev"], "agent.send_message",
            {"to": "homelab", "body": "x"},
        )
    with pytest.raises(Denied):
        await service.call(
            identities.identities["homelab"], "agent.read_messages", {}
        )


async def test_visible_tools_follow_the_grant(agent_service, agent_identities):
    names = [v.name for v in agent_service.visible_tools(agent_identities.identities["dev"])]
    assert names == ["agent.read_messages", "agent.send_message"]


# -- The shipped example ----------------------------------------------------


def test_example_agent_tools_load_against_the_example_toolkit(repo_config_dir):
    """`examples/agent-tools.yaml` must load strictly against
    `examples/toolkits.yaml` -- it is what an operator copies from, and a
    typo in it would otherwise only surface on their host.
    """
    tier1 = load_tier1(os.path.join(repo_config_dir, "toolkits.yaml"))
    assert tier1.toolkit("agent").executor == "agent"
    catalog = load_catalog(
        os.path.join(repo_config_dir, "agent-tools.yaml"), tier1, strict=True
    )
    assert sorted(catalog.tools) == ["agent.read_messages", "agent.send_message"]
    # Shipped inert (FR-3.x): enabling is the operator's separate decision.
    assert not any(t.enabled for t in catalog.tools.values())
