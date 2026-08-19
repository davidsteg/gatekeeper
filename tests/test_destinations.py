"""Multi-destination toolkits (REQUIREMENTS.md FR-8.3g-j).

A toolkit may declare several named destinations, sharing its Tier 1
boundary but each connecting to a different host. Covers: Tier 1 parsing
and validation, catalog expansion into destination-qualified tool IDs,
grant isolation between destinations, the docker executor's per-destination
DOCKER_HOST/TLS environment, and per-destination health probing.
"""

from __future__ import annotations

import json
import os

import pytest
import yaml

from conftest import PYTHON, make_catalog
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog
from gatekeeper.credentials import KEY_ENV, CredentialStore, generate_master_key
from gatekeeper.errors import ConfigError, Denied, Tier1Violation
from gatekeeper.identity import Identity
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1

# -- Tier 1: parsing and validation -----------------------------------------


def _write_tier1(tmp_path, toolkits_yaml: str):
    path = tmp_path / "toolkits.yaml"
    path.write_text(toolkits_yaml + f"\naudit:\n  dir: {tmp_path / 'logs'}\n", encoding="utf-8")
    return path


def test_destination_expands_docker_toolkit(tmp_path):
    path = _write_tier1(
        tmp_path,
        "destinations:\n"
        "  nas1:\n"
        '    docker_host: "unix:///var/run/docker.sock"\n'
        "  nas2:\n"
        '    docker_host: "tcp://nas2.lan:2376"\n'
        "    docker_tls: true\n"
        "    credential: docker-nas2-tls\n"
        "toolkits:\n"
        "  docker:\n"
        "    executor: docker\n"
        "    destinations: [nas1, nas2]\n"
        f"    binaries: [{json.dumps(PYTHON)}]\n",
    )
    tier1 = load_tier1(str(path))
    docker = tier1.toolkit("docker")
    assert docker.destinations == ("nas1", "nas2")
    nas1 = tier1.destination("nas1")
    assert nas1.docker_host == "unix:///var/run/docker.sock"
    # Not declared on nas1 -- None, not False, so it's distinguishable from
    # an explicit "docker_tls: false" (see test_resolve_toolkit_* below).
    assert nas1.docker_tls is None
    nas2 = tier1.destination("nas2")
    assert nas2.docker_host == "tcp://nas2.lan:2376"
    assert nas2.docker_tls is True
    assert nas2.credential == "docker-nas2-tls"


def test_toolkit_without_destinations_is_unaffected(tmp_path):
    """Back-compat: no `destinations:` section, no per-toolkit field."""
    path = _write_tier1(
        tmp_path,
        "toolkits:\n"
        "  demo:\n"
        "    executor: local\n"
        f"    binaries: [{json.dumps(PYTHON)}]\n",
    )
    tier1 = load_tier1(str(path))
    assert tier1.destinations == {}
    assert tier1.toolkit("demo").destinations == ()
    assert tier1.toolkit("demo").docker_host is None


def test_unknown_destination_reference_rejected(tmp_path):
    path = _write_tier1(
        tmp_path,
        "destinations:\n"
        "  nas1:\n"
        '    docker_host: "unix:///var/run/docker.sock"\n'
        "toolkits:\n"
        "  docker:\n"
        "    executor: docker\n"
        "    destinations: [nas1, ghost]\n"
        f"    binaries: [{json.dumps(PYTHON)}]\n",
    )
    with pytest.raises(ConfigError, match="ghost"):
        load_tier1(str(path))


def test_local_toolkit_cannot_declare_destinations(tmp_path):
    """Nothing remote to connect to -- FR-8.3g."""
    path = _write_tier1(
        tmp_path,
        "destinations:\n"
        "  nas1:\n"
        '    docker_host: "unix:///var/run/docker.sock"\n'
        "toolkits:\n"
        "  demo:\n"
        "    executor: local\n"
        "    destinations: [nas1]\n"
        f"    binaries: [{json.dumps(PYTHON)}]\n",
    )
    with pytest.raises(ConfigError, match="local"):
        load_tier1(str(path))


def test_docker_destination_without_docker_host_rejected(tmp_path):
    path = _write_tier1(
        tmp_path,
        "destinations:\n"
        "  nas1:\n"
        '    base_url: "http://example.invalid"\n'  # wrong field for docker
        "toolkits:\n"
        "  docker:\n"
        "    executor: docker\n"
        "    destinations: [nas1]\n"
        f"    binaries: [{json.dumps(PYTHON)}]\n",
    )
    with pytest.raises(ConfigError, match="docker_host"):
        load_tier1(str(path))


def test_http_destination_without_base_url_rejected(tmp_path):
    path = _write_tier1(
        tmp_path,
        "destinations:\n"
        "  instance2:\n"
        '    docker_host: "unix:///var/run/docker.sock"\n'  # wrong field for http
        "toolkits:\n"
        "  sonarr:\n"
        "    executor: http\n"
        "    destinations: [instance2]\n"
        '    base_url: "http://sonarr.lan:8989"\n'
        '    allowed_methods: ["GET"]\n'
        '    allowed_path_prefixes: ["/api/"]\n'
        '    allowed_cidrs: ["127.0.0.1/32"]\n',
    )
    with pytest.raises(ConfigError, match="base_url"):
        load_tier1(str(path))


def test_truenas_destination_without_ws_url_rejected(tmp_path):
    path = _write_tier1(
        tmp_path,
        "destinations:\n"
        "  secondary:\n"
        '    base_url: "http://example.invalid"\n'  # wrong field for truenas
        "toolkits:\n"
        "  truenas:\n"
        "    executor: truenas\n"
        "    destinations: [secondary]\n"
        '    ws_url: "wss://truenas.lan/api/current"\n'
        '    allowed_rpc_methods: ["pool.query"]\n',
    )
    with pytest.raises(ConfigError, match="ws_url"):
        load_tier1(str(path))


def test_invalid_docker_host_scheme_rejected(tmp_path):
    path = _write_tier1(
        tmp_path,
        "destinations:\n"
        "  nas1:\n"
        '    docker_host: "not-a-url"\n'
        "toolkits:\n"
        "  docker:\n"
        "    executor: docker\n"
        "    destinations: [nas1]\n"
        f"    binaries: [{json.dumps(PYTHON)}]\n",
    )
    with pytest.raises(ConfigError):
        load_tier1(str(path))


# -- Catalog: destination-qualified tool ID expansion -------------------------


def _docker_tier1(tmp_path, *, destinations=("nas1", "nas2")):
    dest_yaml = "".join(
        f"  {d}:\n    docker_host: \"unix:///var/run/{d}.sock\"\n" for d in destinations
    )
    dest_list = ", ".join(destinations)
    path = _write_tier1(
        tmp_path,
        f"destinations:\n{dest_yaml}"
        "toolkits:\n"
        "  docker:\n"
        "    executor: docker\n"
        f"    destinations: [{dest_list}]\n"
        f"    binaries: [{json.dumps(PYTHON)}]\n"
        "    denied_args: []\n"
        "    path_roots: []\n",
    )
    return load_tier1(str(path))


def _compose_up_spec():
    return {
        "id": "docker.compose_up",
        "toolkit": "docker",
        "binary": PYTHON,
        "version": 1,
        "title": "Compose up",
        "description": "Brings a stack up.",
        "category": "write",
        "idempotent": True,
        "enabled": True,
        "argv": ["-c", "print('up')"],
        "parameters": {},
        "required_scopes": [],
        "timeout_seconds": 10,
        "max_output_bytes": 4096,
    }


def test_tool_expands_into_one_id_per_destination(tmp_path):
    tier1 = _docker_tier1(tmp_path)
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    assert set(catalog.tools) == {"docker.compose_up@nas1", "docker.compose_up@nas2"}
    assert catalog.tools["docker.compose_up@nas1"].destination == "nas1"
    assert catalog.tools["docker.compose_up@nas2"].destination == "nas2"
    # Every field besides id/destination is shared.
    a, b = catalog.tools["docker.compose_up@nas1"], catalog.tools["docker.compose_up@nas2"]
    assert a.argv == b.argv
    assert a.toolkit == b.toolkit == "docker"


def test_raw_spec_stays_unexpanded(tmp_path):
    """The persisted YAML keeps the bare id -- expansion is load-time only."""
    tier1 = _docker_tier1(tmp_path)
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    assert catalog.raw_of("docker.compose_up") == _compose_up_spec()
    assert catalog.raw_of("docker.compose_up@nas1") is None


def test_toolkit_without_destinations_produces_single_tool(tmp_path):
    tier1 = _docker_tier1(tmp_path, destinations=())
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        "toolkits:\n"
        "  docker:\n"
        "    executor: docker\n"
        f"    binaries: [{json.dumps(PYTHON)}]\n"
        "    denied_args: []\n"
        "    path_roots: []\n"
        f"audit:\n  dir: {tmp_path / 'logs2'}\n",
        encoding="utf-8",
    )
    tier1 = load_tier1(str(path))
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    assert set(catalog.tools) == {"docker.compose_up"}
    assert catalog.tools["docker.compose_up"].destination is None


# -- Grant isolation and call resolution --------------------------------------


@pytest.fixture
def destination_service(tmp_path):
    tier1 = _docker_tier1(tmp_path)
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    audit = AuditLog(str(tmp_path / "logs"))
    return Service(tier1=tier1, catalog=catalog, audit=audit)


def _identity(tool_id: str) -> Identity:
    return Identity(
        id="agent1", role="agent", token_hash="x",
        tools=frozenset({tool_id}), scopes=(),
    )


async def test_grant_on_one_destination_does_not_reach_the_other(destination_service):
    """FR-8.3i: no parameter or grant lets a call to @nas1 reach @nas2."""
    nas1_only = _identity("docker.compose_up@nas1")
    with pytest.raises(Denied):
        await destination_service.call(nas1_only, "docker.compose_up@nas2", {})


async def test_grant_on_correct_destination_succeeds(destination_service, monkeypatch):
    from gatekeeper import execute

    captured_env: dict[str, str] | None = None

    async def fake_run(argv, *, timeout_seconds, max_output_bytes, idempotent, env=None):
        nonlocal captured_env
        captured_env = env
        return execute.Result(
            outcome=execute.OUTCOME_OK, exit_code=0, stdout="up", stderr="",
            truncated=False, duration_ms=1,
        )

    monkeypatch.setattr(execute, "run", fake_run)
    nas2_only = _identity("docker.compose_up@nas2")
    result = await destination_service.call(nas2_only, "docker.compose_up@nas2", {})
    assert result.outcome == execute.OUTCOME_OK
    assert captured_env is not None
    assert captured_env["DOCKER_HOST"] == "unix:///var/run/nas2.sock"


def test_resolve_toolkit_overrides_and_falls_back(destination_service):
    toolkit = destination_service.tier1.toolkit("docker")
    resolved_nas1 = destination_service._resolve_toolkit(toolkit, "nas1")
    assert resolved_nas1.docker_host == "unix:///var/run/nas1.sock"
    # Fields not overridden by the destination fall back to the toolkit's own.
    assert resolved_nas1.binaries == toolkit.binaries
    assert destination_service._resolve_toolkit(toolkit, None) is toolkit


def test_destination_can_opt_out_of_toolkit_level_tls(tmp_path):
    """A destination's explicit `docker_tls: false` must win over a

    toolkit-level `docker_tls: true` -- not be swallowed by an `or`
    fallback that can't tell "unset" from "explicitly false" apart.
    """
    path = _write_tier1(
        tmp_path,
        "destinations:\n"
        "  plain:\n"
        '    docker_host: "unix:///var/run/plain.sock"\n'
        "    docker_tls: false\n"
        "toolkits:\n"
        "  docker:\n"
        "    executor: docker\n"
        "    docker_tls: true\n"  # toolkit-level default: TLS on
        "    destinations: [plain]\n"
        f"    binaries: [{json.dumps(PYTHON)}]\n",
    )
    tier1 = load_tier1(str(path))
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)

    resolved = service._resolve_toolkit(tier1.toolkit("docker"), "plain")
    assert resolved.docker_tls is False


def test_destination_inherits_toolkit_level_tls_when_unset(tmp_path):
    """No `docker_tls` on the destination at all -- inherits the toolkit's."""
    path = _write_tier1(
        tmp_path,
        "destinations:\n"
        "  secure:\n"
        '    docker_host: "tcp://secure.lan:2376"\n'
        "toolkits:\n"
        "  docker:\n"
        "    executor: docker\n"
        "    docker_tls: true\n"
        "    destinations: [secure]\n"
        f"    binaries: [{json.dumps(PYTHON)}]\n",
    )
    tier1 = load_tier1(str(path))
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)

    resolved = service._resolve_toolkit(tier1.toolkit("docker"), "secure")
    assert resolved.docker_tls is True


def test_resolve_toolkit_converts_missing_destination_to_denied(destination_service):
    """A destination name with no matching Tier1 entry is a Denied, audited

    like any other rejection -- not a bare ConfigError escaping call().
    This shouldn't happen given catalog/tier1 are always loaded together,
    but must fail safe if it ever does.
    """
    toolkit = destination_service.tier1.toolkit("docker")
    with pytest.raises(Denied):
        destination_service._resolve_toolkit(toolkit, "does-not-exist")


async def test_probe_executors_reports_per_destination(destination_service, monkeypatch):
    from gatekeeper import execute

    async def fake_run(argv, *, timeout_seconds, max_output_bytes, idempotent, env=None):
        return execute.Result(
            outcome=execute.OUTCOME_OK, exit_code=0, stdout="v1", stderr="",
            truncated=False, duration_ms=1,
        )

    monkeypatch.setattr(execute, "run", fake_run)
    ready = await destination_service.probe_executors()
    assert ready == {"docker@nas1": True, "docker@nas2": True}


# -- TLS-secured docker destinations (docker_tls credential kind) ------------


@pytest.fixture
def master_key(monkeypatch):
    key = generate_master_key()
    monkeypatch.setenv(KEY_ENV, key)
    return key


@pytest.fixture
def credential_store(tmp_path, master_key):
    audit = AuditLog(str(tmp_path / "logs"))
    return CredentialStore(path=str(tmp_path / "credentials.yaml"), audit=audit)


def _tls_bundle(**overrides):
    bundle = {"cert": "CERT-PEM", "key": "KEY-PEM", "ca": "CA-PEM"}
    bundle.update(overrides)
    return json.dumps(bundle)


def test_docker_tls_kind_accepted(credential_store):
    credential_store.create(
        "docker-nas2-tls", kind="docker_tls", value=_tls_bundle(),
        actor="admin", rev="",
    )
    resolved = credential_store._resolve("docker-nas2-tls")
    assert resolved.kind == "docker_tls"
    assert json.loads(resolved.value)["cert"] == "CERT-PEM"


async def test_docker_tls_env_materializes_temp_files(tmp_path, credential_store):
    tier1 = _docker_tier1(tmp_path)
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    audit = AuditLog(str(tmp_path / "logs2"))
    credential_store.create(
        "docker-nas2-tls", kind="docker_tls", value=_tls_bundle(),
        actor="admin", rev="",
    )
    service = Service(tier1=tier1, catalog=catalog, audit=audit, credentials=credential_store)

    env = service._docker_tls_env("docker-nas2-tls")
    cert_path = env["DOCKER_CERT_PATH"]
    assert env["DOCKER_TLS_VERIFY"] == "1"
    assert open(os.path.join(cert_path, "cert.pem"), encoding="utf-8").read() == "CERT-PEM"
    assert open(os.path.join(cert_path, "key.pem"), encoding="utf-8").read() == "KEY-PEM"
    assert open(os.path.join(cert_path, "ca.pem"), encoding="utf-8").read() == "CA-PEM"

    # Cached: a second call returns the same directory without re-writing.
    assert service._docker_tls_env("docker-nas2-tls")["DOCKER_CERT_PATH"] == cert_path

    # Rotation invalidates the cache -- the next materialization picks up
    # the new value instead of serving the stale one.
    service.invalidate_docker_tls_cache()
    credential_store.rotate(
        "docker-nas2-tls", value=_tls_bundle(cert="NEW-CERT"), actor="admin",
        rev=credential_store.revision(),
    )
    new_env = service._docker_tls_env("docker-nas2-tls")
    new_cert_path = new_env["DOCKER_CERT_PATH"]
    assert open(os.path.join(new_cert_path, "cert.pem"), encoding="utf-8").read() == "NEW-CERT"


def test_docker_tls_env_missing_credential_denied(tmp_path):
    tier1 = _docker_tier1(tmp_path)
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    audit = AuditLog(str(tmp_path / "logs3"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)  # no credential store
    with pytest.raises(Denied):
        service._docker_tls_env("docker-nas2-tls")


def test_docker_tls_env_wrong_kind_denied(tmp_path, credential_store):
    tier1 = _docker_tier1(tmp_path)
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    audit = AuditLog(str(tmp_path / "logs4"))
    credential_store.create(
        "not-tls", kind="bearer", value="a-bearer-token", actor="admin", rev="",
    )
    service = Service(tier1=tier1, catalog=catalog, audit=audit, credentials=credential_store)
    with pytest.raises(Denied):
        service._docker_tls_env("not-tls")


def test_docker_tls_env_no_credential_name_denied(tmp_path):
    tier1 = _docker_tier1(tmp_path)
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    audit = AuditLog(str(tmp_path / "logs5"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    with pytest.raises(Denied):
        service._docker_tls_env(None)


# -- UI rendering (smoke) ------------------------------------------------------


def test_ui_renders_destination_pills_and_third_tier(tmp_path):
    from gatekeeper import ui
    from gatekeeper.identity import IdentityStore

    tier1 = _docker_tier1(tmp_path)
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    identities = IdentityStore(identities={"agent1": _identity("docker.compose_up@nas1")})

    svg, _ = ui._access_graph(service, identities)
    assert "nas1" in svg and "nas2" in svg
    assert "DESTINATIONS" in svg

    matrix = ui._tool_matrix(service, identities)
    assert "@nas1" in matrix and "@nas2" in matrix

    class _Session:
        can_write = False

    tools_html = ui._view_tools(service, identities, _Session(), None)
    assert "nas1" in tools_html and "nas2" in tools_html


# -- Admin-UI write path: edit/toggle/delete must target the raw, --------
# -- un-expanded definition, not a destination-qualified id --------------


def test_base_tool_id_strips_destination_suffix(tmp_path):
    from gatekeeper.ui import _base_tool_id

    tier1 = _docker_tier1(tmp_path)
    catalog = make_catalog(tmp_path, tier1, [_compose_up_spec()])
    nas1_tool = catalog.tools["docker.compose_up@nas1"]
    assert _base_tool_id(nas1_tool) == "docker.compose_up"

    tier1_bare = _docker_tier1(tmp_path, destinations=())
    catalog_bare = make_catalog(tmp_path, tier1_bare, [_compose_up_spec()])
    bare_tool = catalog_bare.tools["docker.compose_up"]
    assert _base_tool_id(bare_tool) == "docker.compose_up"


def test_identity_holds_definition_matches_destination_grants():
    only_nas1 = _identity("docker.compose_up@nas1")
    assert only_nas1.holds_definition("docker.compose_up")
    assert not only_nas1.holds_definition("docker.compose_down")
    # Exact bare-id grant (a toolkit with no destinations) still matches.
    bare = _identity("diag.uptime")
    assert bare.holds_definition("diag.uptime")
    # A sibling with a longer name sharing the same prefix must not match.
    sibling = _identity("docker.compose_up_extra@nas1")
    assert not sibling.holds_definition("docker.compose_up")


@pytest.fixture
def destination_store(tmp_path):
    """A ConfigStore over a destination-bearing docker toolkit, mirroring

    the shipped example config's shape (config/examples/toolkits.yaml).
    """
    from gatekeeper.identity import IdentityStore, hash_token
    from gatekeeper.store import ConfigStore

    tier1 = _docker_tier1(tmp_path)
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": [_compose_up_spec()]}), encoding="utf-8")
    catalog = load_catalog(str(tools_path), tier1)
    audit = AuditLog(str(tmp_path / "logs"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)

    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(
        yaml.safe_dump(
            {
                "identities": [
                    {
                        "id": "agent1",
                        "role": "agent",
                        "token_hash": hash_token("x" * 20),
                        "tools": ["docker.compose_up@nas1", "docker.compose_up@nas2"],
                        "scopes": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    identities = IdentityStore(
        identities={"agent1": _identity("docker.compose_up@nas1")}
    )
    store = ConfigStore(
        service=service, identities=identities, audit=audit,
        tools_path=str(tools_path), identities_path=str(identities_path),
    )
    return store, service


def test_disable_by_base_id_succeeds(destination_store):
    """Regression: the UI used to send the @destination-qualified id here,

    which never matches a raw spec's bare id and always raised
    WriteRefused -- disable/delete were unusable for any multi-destination
    toolkit (FR-8.3h).
    """
    store, service = destination_store
    store.set_tool_enabled("docker.compose_up", False, actor="admin", rev="")
    assert service.catalog.tools["docker.compose_up@nas1"].enabled is False
    assert service.catalog.tools["docker.compose_up@nas2"].enabled is False


def test_disable_by_destination_qualified_id_is_refused(destination_store):
    """The destination-qualified id has no raw spec of its own -- it must

    keep being rejected, not silently do nothing.
    """
    from gatekeeper.store import WriteRefused

    store, _service = destination_store
    with pytest.raises(WriteRefused):
        store.set_tool_enabled("docker.compose_up@nas1", False, actor="admin", rev="")


def test_delete_by_base_id_warns_about_destination_qualified_holders(destination_store):
    """`_orphan_warning` must catch grants on the expanded ids too, or a

    destination-qualified dangling grant goes unrecorded (FR-8.3h).
    """
    store, _service = destination_store
    store.delete_tool("docker.compose_up", actor="admin", rev="")
    records = [json.loads(line) for line in _read_audit_lines(store.audit)]
    dangling = [r for r in records if r.get("action") == "dangling_grant"]
    assert dangling, "expected a dangling_grant audit entry"
    assert "agent1" in dangling[-1]["identities"]


def _read_audit_lines(audit):
    path = os.path.join(audit._dir, "audit.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [line for line in handle if line.strip()]
