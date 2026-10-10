"""Shared setup for the `/api/v1` tests (`test_api_*.py`).

Builds the same application `__main__` would: one Starlette app with
`/mcp`, `/admin/mcp`, the legacy `/ui` and the API, sharing every store.
Three identities -- an admin and a viewer with console passwords, and an
agent with only an API token.
"""

from __future__ import annotations

import httpx2
import yaml

from gatekeeper.api import API_PREFIX
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.credentials import CredentialStore
from gatekeeper.identity import generate_token, hash_token, load_identities
from gatekeeper.pending import PendingStore
from gatekeeper.server import build_app
from gatekeeper.service import Service
from gatekeeper.store import ConfigStore
from gatekeeper.toolkit_proposals import ToolkitProposalStore

BASE = "http://gatekeeper.test"
API = API_PREFIX
PASSWORDS = {"root": "admin-console-password", "eye": "viewer-console-password"}


def make_env(tmp_path, tier1, tool_specs, *, read_only: bool = False) -> dict:
    tools_path = tmp_path / "tools-rw.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": tool_specs}), encoding="utf-8")
    tokens = {"root": generate_token(), "eye": generate_token(), "bot": generate_token()}
    identities_path = tmp_path / "identities-rw.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "root", "role": "admin",
                        "token_hash": hash_token(tokens["root"]),
                        "password_hash": hash_token(PASSWORDS["root"]),
                        "tools": [], "scopes": [],
                    },
                    {
                        "id": "eye", "role": "viewer",
                        "token_hash": hash_token(tokens["eye"]),
                        "password_hash": hash_token(PASSWORDS["eye"]),
                        "tools": [], "scopes": [],
                    },
                    {
                        "id": "bot", "role": "agent",
                        "token_hash": hash_token(tokens["bot"]),
                        "tools": ["demo.show"], "scopes": ["stack:*"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    identities = load_identities(str(identities_path))
    audit = AuditLog(tier1.audit_dir)
    service = Service(tier1=tier1, catalog=load_catalog(str(tools_path), tier1), audit=audit)
    credentials = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    store = pending = toolkit_proposals = None
    if not read_only:
        store = ConfigStore(
            service=service, identities=identities, audit=audit,
            tools_path=str(tools_path), identities_path=str(identities_path),
        )
        pending = PendingStore(path=str(tmp_path / "pending.yaml"), audit=audit)
        toolkit_proposals = ToolkitProposalStore(
            path=str(tmp_path / "toolkit-proposals.yaml"), audit=audit, service=service,
            toolkits_path=str(tmp_path / "toolkits.yaml"),
            tools_path=str(tools_path), identities_path=str(identities_path),
        )
    app = build_app(
        service=service, identities=identities, audit=audit, ui=True, store=store,
        credentials=credentials, pending=pending, toolkit_proposals=toolkit_proposals,
    )
    return {
        "app": app, "store": store, "pending": pending,
        "toolkit_proposals": toolkit_proposals, "credentials": credentials,
        "service": service, "identities": identities, "tokens": tokens,
        "audit_path": f"{tier1.audit_dir}/audit.jsonl", "audit": audit,
    }


def client(app) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=BASE, timeout=30.0
    )


async def login(c: httpx2.AsyncClient, identity: str = "root") -> dict:
    """Signs in through the API; returns the session info (with `csrf`)."""
    response = await c.post(
        f"{API}/session", json={"identity": identity, "password": PASSWORDS[identity]}
    )
    assert response.status_code == 200, response.text
    return response.json()


def audit_records(env: dict) -> list[dict]:
    import json
    import os

    path = env["audit_path"]
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
