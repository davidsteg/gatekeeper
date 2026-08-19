"""The `truenas` executor (REQUIREMENTS.md §8, FR-8.3a-f).

Against a real JSON-RPC-over-WebSocket server, not a mock: the property
that matters -- a method not on the allowlist is refused by gatekeeper
itself, before anything is sent -- is exactly what a mocked send() would
assume away.
"""

from __future__ import annotations

import asyncio
import json

import pytest
import websockets

from gatekeeper import execute_truenas
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN
from gatekeeper.tier1 import load_tier1


async def _fake_truenas(websocket):
    async for raw in websocket:
        request = json.loads(raw)
        method = request.get("method")
        request_id = request.get("id")
        if method == "auth.login_with_api_key":
            key = request["params"][0]
            ok = key == "correct-key"
            await websocket.send(
                json.dumps({"jsonrpc": "2.0", "id": request_id, "result": ok})
            )
            continue
        if method == "pool.query":
            await websocket.send(
                json.dumps(
                    {"jsonrpc": "2.0", "id": request_id, "result": [{"name": "tank"}]}
                )
            )
            continue
        if method == "pool.dataset.create":
            name = request["params"][0] if request.get("params") else None
            await websocket.send(
                json.dumps({"jsonrpc": "2.0", "id": request_id, "result": {"name": name}})
            )
            continue
        if method == "slow.method":
            await asyncio.sleep(2)
            await websocket.send(
                json.dumps({"jsonrpc": "2.0", "id": request_id, "result": True})
            )
            continue
        await websocket.send(
            json.dumps(
                {
                    "jsonrpc": "2.0", "id": request_id,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            )
        )


@pytest.fixture
async def ws_server():
    server = await websockets.serve(_fake_truenas, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield f"ws://127.0.0.1:{port}"
    server.close()
    await server.wait_closed()


@pytest.fixture
def toolkit(tmp_path, ws_server):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        f"""
toolkits:
  demo_truenas:
    executor: truenas
    ws_url: "{ws_server}"
    allowed_rpc_methods: ["pool.query", "pool.dataset.create"]
    credential: demo_cred
audit:
  dir: {tmp_path / "logs"}
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    return tier1.toolkit("demo_truenas")


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.audit import AuditLog

    audit = AuditLog(str(tmp_path / "logs2"))
    store = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    store.create(
        "demo_cred", kind="ws_api_key", value="correct-key", actor="test", rev="",
    )
    return store


async def test_allowed_method_succeeds(toolkit, credentials):
    result = await execute_truenas.run(
        method="pool.query", params={}, toolkit=toolkit, credentials=credentials,
        timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )
    assert result.outcome == OUTCOME_OK
    assert json.loads(result.stdout) == [{"name": "tank"}]


async def test_params_sent_positionally_in_declared_order(toolkit, credentials):
    result = await execute_truenas.run(
        method="pool.dataset.create", params={"name": "tank/raid/dev-1"},
        toolkit=toolkit, credentials=credentials,
        timeout_seconds=5, max_output_bytes=65536, idempotent=False,
    )
    assert result.outcome == OUTCOME_OK
    assert json.loads(result.stdout)["name"] == "tank/raid/dev-1"


async def test_disallowed_method_denied_before_send(toolkit, credentials):
    result = await execute_truenas.run(
        method="pool.dataset.delete", params={}, toolkit=toolkit,
        credentials=credentials, timeout_seconds=5, max_output_bytes=65536,
        idempotent=False,
    )
    assert result.outcome == OUTCOME_FAILED
    assert "not allowed" in result.stderr.lower() or "denied" in result.stderr.lower()


async def test_wrong_credential_denied(tmp_path, toolkit, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.audit import AuditLog

    audit = AuditLog(str(tmp_path / "logs3"))
    store = CredentialStore(path=str(tmp_path / "credentials-wrong.yaml"), audit=audit)
    store.create("demo_cred", kind="ws_api_key", value="wrong-key", actor="test", rev="")
    result = await execute_truenas.run(
        method="pool.query", params={}, toolkit=toolkit, credentials=store,
        timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED


async def test_missing_credential_store_denied(toolkit):
    result = await execute_truenas.run(
        method="pool.query", params={}, toolkit=toolkit, credentials=None,
        timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )
    assert result.outcome == OUTCOME_FAILED


async def test_timeout_on_non_idempotent_is_unknown(tmp_path, ws_server, credentials):
    path = tmp_path / "toolkits2.yaml"
    path.write_text(
        f"""
toolkits:
  demo_truenas:
    executor: truenas
    ws_url: "{ws_server}"
    allowed_rpc_methods: ["slow.method"]
    credential: demo_cred
audit:
  dir: {tmp_path / "logs"}
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    tk = tier1.toolkit("demo_truenas")
    result = await execute_truenas.run(
        method="slow.method", params={}, toolkit=tk, credentials=credentials,
        timeout_seconds=0.2, max_output_bytes=65536, idempotent=False,
    )
    assert result.outcome == OUTCOME_UNKNOWN


async def test_redaction_scrubs_credential_from_response(toolkit, credentials):
    result = await execute_truenas.run(
        method="pool.dataset.create", params={"name": "correct-key-leak"},
        toolkit=toolkit, credentials=credentials,
        timeout_seconds=5, max_output_bytes=65536, idempotent=False,
        redact=lambda text: text.replace("correct-key", "***"),
    )
    assert "correct-key" not in result.stdout


async def test_probe_reachable(toolkit):
    assert await execute_truenas.probe(toolkit) is True


async def test_probe_unreachable(tmp_path):
    path = tmp_path / "toolkits3.yaml"
    path.write_text(
        """
toolkits:
  demo_truenas:
    executor: truenas
    ws_url: "ws://127.0.0.1:1"
    allowed_rpc_methods: ["pool.query"]
audit:
  dir: /tmp/gk-test-logs
""",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    tk = tier1.toolkit("demo_truenas")
    assert await execute_truenas.probe(tk) is False
