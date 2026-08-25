"""The `google` executor (REQUIREMENTS.md §8, FR-8.3a-f counterpart).

A real stub script standing in for google_api.py, not a mock: the
properties that matter here -- the subprocess actually runs with
``shell=False``, the token file actually lands at
``$HOME/.hermes/google_token.json``, the JSON output is actually capped
-- are exactly the kind of thing a mock of the subprocess would silently
assume away.
"""

from __future__ import annotations

import json
import os
import textwrap

import pytest
import yaml
from conftest import make_catalog

from gatekeeper import execute_google, validate
from gatekeeper.catalog import parse_tool_spec
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.errors import Denied
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN
from gatekeeper.tier1 import load_tier1

# -- A stub script standing in for google_api.py ---------------------------
#
# Reads $HOME/.hermes/google_token.json (the same path google_api.py
# reads), echoes a JSON response on stdout, and exits 0. The script is
# written to a temp file per test module so the executor's `probe`
# finds a real file on disk. Behaviours (token-expired, scope-denied,
# large output) are selected by the action string the executor passes.


def _write_stub(path: str) -> None:
    """Writes the stub google_api.py replacement.

    The stub inspects sys.argv to decide what to emit:
    - ``gmail search``: a list of messages (capped by --max)
    - ``gmail send``: a success confirmation
    - ``gmail labels``: a list of labels
    - ``gmail get``: a single message
    - ``calendar list``: a list of events
    - ``drive search``: a list of files
    - any action containing ``expire``: exits 1 with a 401 JSON error
    - any action containing ``scope``: exits 1 with a 403 JSON error
    - any action containing ``slow``: sleeps 2s (for timeout tests)
    - any action containing ``big``: emits a list of 1000 items (for capping)
    """
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            textwrap.dedent(
                """\
                import json, os, sys, time

                # Confirm the token file is where the executor said it would be.
                token_path = os.path.join(os.environ.get("HOME", ""), ".hermes", "google_token.json")
                if not os.path.isfile(token_path):
                    print(json.dumps({"error": "token file not found", "code": 401}))
                    sys.exit(1)

                action = " ".join(sys.argv[1:])

                if "expire" in action:
                    print(json.dumps({"error": "invalid_grant", "message": "Token expired"}, file=sys.stderr))
                    sys.exit(1)

                if "scope" in action:
                    print(json.dumps({"error": "Request had insufficient permissions", "code": 403}, file=sys.stderr))
                    sys.exit(1)

                if "slow" in action:
                    time.sleep(2)

                if "big" in action:
                    print(json.dumps([{"id": str(i)} for i in range(1000)]))
                    sys.exit(0)

                if action.startswith("gmail search"):
                    print(json.dumps([{"id": "msg1", "snippet": "hello"}, {"id": "msg2", "snippet": "world"}]))
                elif action.startswith("gmail send"):
                    print(json.dumps({"id": "sent1", "status": "sent"}))
                elif action.startswith("gmail labels"):
                    print(json.dumps([{"id": "INBOX", "name": "INBOX"}, {"id": "UNREAD", "name": "UNREAD"}]))
                elif action.startswith("gmail get"):
                    print(json.dumps({"id": "msg1", "body": "hello world"}))
                elif action.startswith("calendar list"):
                    print(json.dumps([{"id": "evt1", "summary": "Meeting"}]))
                elif action.startswith("drive search"):
                    print(json.dumps([{"id": "file1", "name": "doc.txt"}]))
                else:
                    print(json.dumps({"ok": True, "action": action}))
                sys.exit(0)
                """
            )
        )


@pytest.fixture(scope="module")
def google_script(tmp_path_factory):
    """The stub script path, guaranteed to exist and be readable."""
    d = tmp_path_factory.mktemp("google-api")
    path = os.path.join(str(d), "google_api.py")
    _write_stub(path)
    os.chmod(path, 0o755)
    return path


@pytest.fixture
def toolkit(tmp_path, google_script):
    """A google toolkit pointing at the stub script."""
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": {
                        "executor": "google",
                        "google_script": google_script,
                        "allowed_google_actions": [
                            "gmail search", "gmail get", "gmail send", "gmail reply",
                            "gmail labels", "gmail modify",
                            "gmail search expire", "gmail search scope",
                            "gmail search slow", "gmail search big",
                        ],
                        "credential": "google",
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 131072,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    return tier1.toolkit("gmail"), tier1


def _tool(tier1, **overrides):
    spec = {
        "id": "gmail.search",
        "toolkit": "gmail",
        "version": 1,
        "title": "Search mail",
        "description": "Searches Gmail.",
        "category": "read",
        "idempotent": True,
        "enabled": True,
        "google_action": "gmail search",
        "google_args": {
            "query": {"positional": True},
            "max_results": {"flag": "--max"},
        },
        "parameters": {
            "query": {"type": "string", "required": True, "pattern": "^.{1,500}$",
                       "description": "Search query."},
            "max_results": {"type": "integer", "required": False, "minimum": 1,
                             "maximum": 500, "description": "Max results."},
        },
        "required_scopes": ["gmail.readonly"],
        "timeout_seconds": 10,
        "max_output_bytes": 65536,
    }
    spec.update(overrides)
    return parse_tool_spec(spec, tier1)


@pytest.fixture
def google_env(tmp_path):
    """A HOME env with a token file, for direct execute_google.run calls
    that bypass service.call's token materialization.
    """
    home = tmp_path / "fake-home"
    hermes = home / ".hermes"
    hermes.mkdir(parents=True)
    (hermes / "google_token.json").write_text(
        json.dumps({
            "client_id": "test-client-id",
            "client_secret": "test-secret",
            "refresh_token": "test-refresh-token",
        }),
        encoding="utf-8",
    )
    return {"HOME": str(home)}


@pytest.fixture
def credentials(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.audit import AuditLog

    audit = AuditLog(str(tmp_path / "logs2"))
    store = CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)
    store.create(
        "google",
        kind="oauth2",
        value=json.dumps({
            "client_id": "test-client-id.apps.googleusercontent.com",
            "client_secret": "test-secret",
            "refresh_token": "test-refresh-token",
        }),
        actor="test",
        rev="",
    )
    return store


# -- Basic execution -------------------------------------------------------


async def test_successful_search(toolkit, credentials, google_env):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    args = validate.build_google_call(tool, {"query": "is:unread", "max_results": "10"}, tk)
    result = await execute_google.run(
        google_action="gmail search",
        args=args,
        toolkit=tk,
        timeout_seconds=10,
        max_output_bytes=65536,
        idempotent=True,
        env=google_env,  # the stub does not need a real token here
    )
    assert result.outcome == OUTCOME_OK
    payload = json.loads(result.stdout)
    assert isinstance(payload, list)
    assert payload[0]["id"] == "msg1"
    assert result.external_untrusted is True


async def test_json_output_capped_at_max_items(toolkit, credentials, google_env):
    tk, tier1 = toolkit
    tool = _tool(
        tier1,
        id="gmail.search_big",
        google_action="gmail search big",
        google_args={},
        parameters={},
    )
    args = validate.build_google_call(tool, {}, tk)
    result = await execute_google.run(
        google_action="gmail search big",
        args=args,
        toolkit=tk,
        timeout_seconds=10,
        max_output_bytes=65536,
        idempotent=True,
        env=google_env,
    )
    assert result.outcome == OUTCOME_OK
    payload = json.loads(result.stdout)
    # MAX_JSON_ITEMS is 500 (execute_http.py:34) -- the stub emits 1000.
    assert len(payload) <= 500


async def test_positional_arg_is_one_argv_element(toolkit):
    """FR-5.4: a parameter value cannot produce an additional argument.

    A query with spaces is still one positional argv element -- the
    subprocess receives it as one sys.argv entry, not split.
    """
    tk, tier1 = toolkit
    tool = _tool(tier1)
    args = validate.build_google_call(tool, {"query": "from:david is:unread", "max_results": "5"}, tk)
    # positional: one element; flag: two elements (--max, value)
    assert args == ["from:david is:unread", "--max", "5"]


async def test_missing_arg_denied(toolkit):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    with pytest.raises(Denied):
        validate.build_google_call(tool, {"query": "is:unread"}, tk)  # max_results missing


async def test_token_expired_clear_message(toolkit, credentials, google_env):
    tk, tier1 = toolkit
    tool = _tool(
        tier1,
        id="gmail.search_expire",
        google_action="gmail search expire",
        google_args={},
        parameters={},
    )
    args = validate.build_google_call(tool, {}, tk)
    result = await execute_google.run(
        google_action="gmail search expire",
        args=args,
        toolkit=tk,
        timeout_seconds=10,
        max_output_bytes=65536,
        idempotent=True,
        env=google_env,
    )
    assert result.outcome == OUTCOME_FAILED
    assert "expired" in result.stderr.lower() or "token" in result.stderr.lower()


async def test_scope_denied_clear_message(toolkit, credentials, google_env):
    tk, tier1 = toolkit
    tool = _tool(
        tier1,
        id="gmail.search_scope",
        google_action="gmail search scope",
        google_args={},
        parameters={},
    )
    args = validate.build_google_call(tool, {}, tk)
    result = await execute_google.run(
        google_action="gmail search scope",
        args=args,
        toolkit=tk,
        timeout_seconds=10,
        max_output_bytes=65536,
        idempotent=True,
        env=google_env,
    )
    assert result.outcome == OUTCOME_FAILED
    assert "scope" in result.stderr.lower() or "permission" in result.stderr.lower()


async def test_timeout_on_non_idempotent_is_unknown(toolkit, google_env):
    tk, tier1 = toolkit
    tool = _tool(
        tier1,
        id="gmail.search_slow",
        google_action="gmail search slow",
        google_args={},
        parameters={},
        category="write_external",
        idempotent=False,
    )
    args = validate.build_google_call(tool, {}, tk)
    result = await execute_google.run(
        google_action="gmail search slow",
        args=args,
        toolkit=tk,
        timeout_seconds=1,
        max_output_bytes=65536,
        idempotent=False,
        env=google_env,
    )
    assert result.outcome == OUTCOME_UNKNOWN


async def test_timeout_on_idempotent_is_failed(toolkit, google_env):
    tk, tier1 = toolkit
    tool = _tool(
        tier1,
        id="gmail.search_slow2",
        google_action="gmail search slow",
        google_args={},
        parameters={},
    )
    args = validate.build_google_call(tool, {}, tk)
    result = await execute_google.run(
        google_action="gmail search slow",
        args=args,
        toolkit=tk,
        timeout_seconds=1,
        max_output_bytes=65536,
        idempotent=True,
        env=google_env,
    )
    assert result.outcome == OUTCOME_FAILED


async def test_external_untrusted_always_set(toolkit, google_env):
    tk, tier1 = toolkit
    tool = _tool(tier1)
    args = validate.build_google_call(tool, {"query": "is:unread", "max_results": "10"}, tk)
    result = await execute_google.run(
        google_action="gmail search",
        args=args,
        toolkit=tk,
        timeout_seconds=10,
        max_output_bytes=65536,
        idempotent=True,
        env=google_env,
    )
    assert result.external_untrusted is True


async def test_response_truncated_at_max_output_bytes(toolkit, google_env):
    tk, tier1 = toolkit
    tool = _tool(
        tier1,
        id="gmail.search_big",
        google_action="gmail search big",
        google_args={},
        parameters={},
    )
    args = validate.build_google_call(tool, {}, tk)
    result = await execute_google.run(
        google_action="gmail search big",
        args=args,
        toolkit=tk,
        timeout_seconds=10,
        max_output_bytes=50,
        idempotent=True,
        env=google_env,
    )
    assert result.truncated is True


async def test_action_not_in_allowlist_denied(toolkit, google_env):
    tk, tier1 = toolkit
    result = await execute_google.run(
        google_action="gmail delete",
        args=[],
        toolkit=tk,
        timeout_seconds=10,
        max_output_bytes=65536,
        idempotent=True,
        env=google_env,
    )
    assert result.outcome == OUTCOME_FAILED
    assert "not allowed" in result.stderr.lower()


# -- Tier 1 loading --------------------------------------------------------


def test_google_toolkit_loads(tmp_path, google_script):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": {
                        "executor": "google",
                        "google_script": google_script,
                        "allowed_google_actions": ["gmail search", "gmail get"],
                        "credential": "google",
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 65536,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    tk = tier1.toolkit("gmail")
    assert tk.executor == "google"
    assert tk.google_script == google_script
    assert "gmail search" in tk.allowed_google_actions
    assert tk.allows_google_action("gmail search")
    assert not tk.allows_google_action("gmail delete")


def test_google_toolkit_requires_script(tmp_path):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": {
                        "executor": "google",
                        "allowed_google_actions": ["gmail search"],
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 65536,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(Exception, match="google_script"):
        load_tier1(str(path))


def test_google_toolkit_requires_absolute_script(tmp_path):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": {
                        "executor": "google",
                        "google_script": "relative/path.py",
                        "allowed_google_actions": ["gmail search"],
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 65536,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(Exception, match="absolute"):
        load_tier1(str(path))


def test_google_toolkit_requires_actions(tmp_path, google_script):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": {
                        "executor": "google",
                        "google_script": google_script,
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 65536,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(Exception, match="allowed_google_actions"):
        load_tier1(str(path))


def test_google_toolkit_with_container(tmp_path, google_script):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": {
                        "executor": "google",
                        "google_script": google_script,
                        "google_container": "hermes-personal",
                        "allowed_google_actions": ["gmail search"],
                        "credential": "google",
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 65536,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    tk = tier1.toolkit("gmail")
    assert tk.google_container == "hermes-personal"


# -- Tool spec parsing -----------------------------------------------------


def test_tool_spec_parses_google_action(toolkit):
    _, tier1 = toolkit
    tool = _tool(tier1)
    assert tool.google_action == "gmail search"
    assert tool.google_args is not None
    assert tool.google_args["query"]["positional"] is True
    assert tool.google_args["max_results"]["flag"] == "--max"


def test_tool_spec_rejects_positional_with_flag(toolkit):
    _, tier1 = toolkit
    with pytest.raises(Exception, match="positional"):
        _tool(
            tier1,
            id="gmail.bad",
            google_args={
                "query": {"positional": True, "flag": "--query"},
            },
            parameters={
                "query": {"type": "string", "required": True, "pattern": "^.{1,200}$",
                           "description": "q"},
            },
        )


def test_tool_spec_rejects_non_positional_without_flag(toolkit):
    _, tier1 = toolkit
    with pytest.raises(Exception, match="flag"):
        _tool(
            tier1,
            id="gmail.bad2",
            google_args={
                "query": {"positional": False},
            },
            parameters={
                "query": {"type": "string", "required": True, "pattern": "^.{1,200}$",
                           "description": "q"},
            },
        )


def test_tool_validate_against_tier1_rejects_unknown_action(toolkit):
    _, tier1 = toolkit
    with pytest.raises(Exception, match="gmail delete"):
        _tool(
            tier1,
            id="gmail.delete",
            google_action="gmail delete",
            google_args={},
            parameters={},
        )


# -- Credential store ------------------------------------------------------


def test_oauth2_kind_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv(KEY_ENV, generate_master_key())
    from gatekeeper.audit import AuditLog

    audit = AuditLog(str(tmp_path / "logs3"))
    store = CredentialStore(path=str(tmp_path / "cred.yaml"), audit=audit)
    store.create(
        "google", kind="oauth2",
        value=json.dumps({"client_id": "a", "client_secret": "b", "refresh_token": "c"}),
        actor="test", rev="",
    )
    resolved = store._resolve("google")
    assert resolved is not None
    assert resolved.kind == "oauth2"
    bundle = json.loads(resolved.value)
    assert bundle["client_id"] == "a"


# -- Token tempfile materialization (through service.call) -----------------


def _service_for(tmp_path, tier1, credentials, *, name):
    from gatekeeper.audit import AuditLog
    from gatekeeper.identity import Identity, hash_token
    from gatekeeper.service import Service

    catalog = make_catalog(tmp_path, tier1, [_tool_spec()])
    audit = AuditLog(str(tmp_path / name))
    identity = Identity(
        id="agent",
        role="agent",
        token_hash=hash_token("unused"),
        tools=frozenset({"gmail.search"}),
        scopes=frozenset({"gmail.readonly"}),
    )
    service = Service(tier1=tier1, catalog=catalog, audit=audit, credentials=credentials)
    return service, identity, tmp_path / name / "audit.jsonl"


def _tool_spec():
    return {
        "id": "gmail.search",
        "toolkit": "gmail",
        "version": 1,
        "title": "Search mail",
        "description": "Searches Gmail.",
        "category": "read",
        "idempotent": True,
        "enabled": True,
        "google_action": "gmail search",
        "google_args": {
            "query": {"positional": True},
            "max_results": {"flag": "--max"},
        },
        "parameters": {
            "query": {"type": "string", "required": True, "pattern": "^.{1,500}$",
                       "description": "Search query."},
            "max_results": {"type": "integer", "required": False, "minimum": 1,
                             "maximum": 500, "description": "Max results."},
        },
        "required_scopes": ["gmail.readonly"],
        "timeout_seconds": 10,
        "max_output_bytes": 65536,
    }


async def test_service_call_materializes_token_and_runs(toolkit, credentials, tmp_path):
    tk, tier1 = toolkit
    service, identity, log_path = _service_for(
        tmp_path, tier1, credentials, name="logs-google"
    )
    result = await service.call(
        identity, "gmail.search", {"query": "is:unread", "max_results": 10}
    )
    assert result.outcome == OUTCOME_OK
    # The token tempfile dir was created and is still on disk (cached for
    # reuse, cleaned on rotation -- not per-call). Confirm it exists and
    # contains the token file.
    assert service._google_token_dirs
    token_home = next(iter(service._google_token_dirs.values()))
    assert os.path.isfile(os.path.join(token_home, ".hermes", "google_token.json"))


async def test_service_call_audit_records_credential_name_not_value(
    toolkit, credentials, tmp_path
):
    _, tier1 = toolkit
    service, identity, log_path = _service_for(
        tmp_path, tier1, credentials, name="logs-audit"
    )
    result = await service.call(
        identity, "gmail.search", {"query": "is:unread", "max_results": 10}
    )
    assert result.outcome == OUTCOME_OK
    written = log_path.read_text(encoding="utf-8")
    record = json.loads(written.splitlines()[-1])
    assert record["credentials"] == ["google"]
    # The secret values never appear in the audit log (FR-10.7).
    assert "test-secret" not in written
    assert "test-refresh-token" not in written


async def test_service_call_missing_credential_denied(toolkit, tmp_path):
    tk, tier1 = toolkit
    # A service with no credential store configured.
    from gatekeeper.audit import AuditLog
    from gatekeeper.identity import Identity, hash_token
    from gatekeeper.service import Service

    catalog = make_catalog(tmp_path, tier1, [_tool_spec()])
    audit = AuditLog(str(tmp_path / "logs-nocred"))
    identity = Identity(
        id="agent",
        role="agent",
        token_hash=hash_token("unused"),
        tools=frozenset({"gmail.search"}),
        scopes=frozenset({"gmail.readonly"}),
    )
    service = Service(tier1=tier1, catalog=catalog, audit=audit, credentials=None)
    # service.call raises Denied for a missing credential (analogous to
    # test_audit_records_credential_name_on_denial in test_execute_http.py).
    with pytest.raises(Denied):
        await service.call(
            identity, "gmail.search", {"query": "is:unread", "max_results": 10}
        )


async def test_invalidate_google_token_cache_removes_dirs(toolkit, credentials, tmp_path):
    tk, tier1 = toolkit
    service, identity, _ = _service_for(
        tmp_path, tier1, credentials, name="logs-invalidate"
    )
    await service.call(
        identity, "gmail.search", {"query": "is:unread", "max_results": 10}
    )
    token_home = next(iter(service._google_token_dirs.values()))
    assert os.path.isdir(token_home)
    service.invalidate_google_token_cache()
    assert not service._google_token_dirs
    assert not os.path.isdir(token_home)


# -- Probe -----------------------------------------------------------------


async def test_probe_reports_reachable(toolkit):
    tk, _ = toolkit
    assert await execute_google.probe(tk) is True


async def test_probe_reports_unreachable_for_missing_script(tmp_path):
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": {
                        "executor": "google",
                        "google_script": str(tmp_path / "nonexistent.py"),
                        "allowed_google_actions": ["gmail search"],
                        "credential": "google",
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 65536,
                    }
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    tk = tier1.toolkit("gmail")
    assert await execute_google.probe(tk) is False