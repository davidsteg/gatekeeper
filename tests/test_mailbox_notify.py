"""Mailbox delivery webhook notify (`execute_agent._notify_delivery`).

The webhook is an operator's opt-in side channel, not part of the
mailbox contract: `GATEKEEPER_NOTIFY_URL` decides whether a POST happens
at all, and the two properties worth pinning are that it happens with a
correct HMAC signature when configured, and that an unconfigured
deployment stays exactly as network-free as before -- no POST, and a
delivery that never raises because the webhook did.

Patched at `urllib.request.urlopen` -- the single seam the notify path
has. The delivery itself runs against a real `MessageStore`, so these
tests still exercise the full `_send` return path the webhook hangs off.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest import mock

import pytest
import yaml

from gatekeeper import execute_agent
from gatekeeper.messages import MessageStore
from gatekeeper.tier1 import load_tier1

URL = "https://ops.example.internal/hooks/gatekeeper-mailbox"
SECRET = "notify-secret"


@pytest.fixture
def store(tmp_path):
    return MessageStore(path=str(tmp_path / "messages.yaml"))


@pytest.fixture
def toolkit(tmp_path):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "agent": {
                        "executor": "agent",
                        "mailbox_path": str(tmp_path / "messages.yaml"),
                        "allowed_agent_operations": ["send_message"],
                        "max_timeout_seconds": 10,
                        "max_output_bytes": 65536,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    return load_tier1(str(path)).toolkit("agent")


async def _send(toolkit, store):
    return await execute_agent.run(
        operation="send_message",
        sender="dev",
        values={"to": "homelab", "subject": "deploy", "body": "jellyfin restarted"},
        toolkit=toolkit,
        store=store,
        max_output_bytes=65536,
    )


async def test_delivery_posts_signed_webhook_when_configured(
    tmp_path, monkeypatch, toolkit, store
):
    monkeypatch.setenv("GATEKEEPER_NOTIFY_URL", URL)
    monkeypatch.setenv("GATEKEEPER_NOTIFY_SECRET", SECRET)

    with mock.patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__ = mock.Mock(return_value=mock.Mock())
        urlopen.return_value.__exit__ = mock.Mock(return_value=False)
        result = await _send(toolkit, store)

    assert result.outcome == "ok"
    urlopen.assert_called_once()
    request = urlopen.call_args.args[0]
    assert request.full_url == URL
    raw_body = request.data
    expected_sig = hmac.new(SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    assert request.get_header("X-gatekeeper-signature") == expected_sig
    assert request.get_header("Content-type") == "application/json"
    payload = json.loads(raw_body.decode("utf-8"))
    assert payload["from"] == "dev"
    assert payload["to"] == "homelab"
    assert payload["subject"] == "deploy"
    assert payload["body"] == "jellyfin restarted"
    assert payload["id"]
    assert payload["created_at"]
    # The delivered result is the same as ever -- the webhook is not part
    # of the agent's contract.
    assert json.loads(result.stdout)["delivered"] is True


async def test_no_webhook_and_no_exception_when_url_unset(
    monkeypatch, toolkit, store
):
    monkeypatch.delenv("GATEKEEPER_NOTIFY_URL", raising=False)
    monkeypatch.delenv("GATEKEEPER_NOTIFY_SECRET", raising=False)

    with mock.patch("urllib.request.urlopen") as urlopen:
        result = await _send(toolkit, store)

    urlopen.assert_not_called()
    assert result.outcome == "ok"
    assert json.loads(result.stdout)["delivered"] is True
    # The message is in the mailbox even though nobody was told out of band.
    assert store.unread_count("homelab") == 1