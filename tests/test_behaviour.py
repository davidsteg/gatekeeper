"""Positive tests: what must work.

The negative corpus shows that the boundaries hold. Here it is about
gatekeeper actually accomplishing something within the boundaries -- a
protection that rejects everything would be trivial and useless.
"""

from __future__ import annotations

import os
import sys
from unittest import mock

import pytest

from conftest import PYTHON, make_catalog
from gatekeeper import execute
from gatekeeper.catalog import load_catalog
from gatekeeper.errors import Denied, DenialReason
from gatekeeper.identity import load_identities
from gatekeeper.tier1 import load_tier1
from gatekeeper.validate import build_argv, resolve_parameters, resolve_scopes


async def test_successful_call(service, identities):
    store, _ = identities
    result = await service.call(
        store.identities["full"], "demo.show", {"stack": "media-jellyfin"}
    )
    assert result.outcome == execute.OUTCOME_OK
    assert result.exit_code == 0
    assert "media-jellyfin" in result.stdout


async def test_narrow_identity_within_scope(service, identities):
    store, _ = identities
    result = await service.call(
        store.identities["narrow"], "demo.show", {"stack": "media-jellyfin"}
    )
    assert result.outcome == execute.OUTCOME_OK


def test_scope_wildcard_requires_dash_boundary():
    """The `-` in `stack:dev-*` is literal, not a naive prefix.

    This is the foundational guarantee of the permission profile: `dev` may
    only touch `dev-*`, not `devtools` or `dev_x`. `fnmatch` treats
    `-` as a normal character -- this test pins that down, so a
    future switch to a prefix comparison does not silently
    open the boundary.
    """
    from gatekeeper.identity import Identity

    dev = Identity(
        id="dev", role="agent", token_hash="x",
        tools=frozenset({"docker.compose_ps"}), scopes=("stack:dev-*",),
    )
    assert dev.covers_scope("stack:dev-argus")
    assert dev.covers_scope("stack:dev-argus-extra")
    # The critical case: same prefix, but no hyphen.
    assert not dev.covers_scope("stack:devtools")
    assert not dev.covers_scope("stack:dev_x")
    assert not dev.covers_scope("stack:dev")
    assert not dev.covers_scope("stack:media-jellyfin")


async def test_scope_mismatch_rejects_sibling_prefix(service, identities):
    """A stack with the same prefix but no hyphen is rejected.

    The negative case for the wildcard boundary: `devtools` must not
    pass for a `dev-*` identity -- neither in scope resolution
    nor in the real call path.
    """
    store, _ = identities
    narrow = store.identities["narrow"]  # scopes: stack:media-*
    with pytest.raises(Denied) as exc:
        await service.call(narrow, "demo.show", {"stack": "mediatools"})
    assert exc.value.reason is DenialReason.SCOPE_MISMATCH


def test_derived_path_resolves(catalog, sandbox):
    tool = catalog.get("demo.show")
    values = resolve_parameters(tool, {"stack": "media-jellyfin"})
    assert values["compose_path"] == os.path.realpath(
        str(sandbox / "media-jellyfin" / "compose.yaml")
    )
    assert resolve_scopes(tool, values) == ["stack:media-jellyfin"]


def test_input_schema_hides_derived_parameters(catalog):
    """The agent sees only what it is allowed to set."""
    schema = catalog.get("demo.show").input_schema()
    assert set(schema["properties"]) == {"stack"}
    assert schema["required"] == ["stack"]
    assert schema["additionalProperties"] is False


def test_integer_bounds(tmp_path, tier1):
    catalog = make_catalog(
        tmp_path,
        tier1,
        [
            {
                "id": "demo.tail",
                "toolkit": "demo",
                "binary": PYTHON,
                "title": "x",
                "description": "x",
                "category": "read",
                "idempotent": True,
                "enabled": True,
                "argv": ["-c", "print(1)", "{n}"],
                "parameters": {
                    "n": {
                        "type": "integer",
                        "required": True,
                        "minimum": 1,
                        "maximum": 1000,
                        "description": "x",
                    }
                },
                "required_scopes": [],
                "timeout_seconds": 5,
                "max_output_bytes": 1024,
            }
        ],
    )
    tool = catalog.get("demo.tail")
    assert resolve_parameters(tool, {"n": 500})["n"] == "500"
    for bad in (0, 1001, -1):
        with pytest.raises(Denied) as exc:
            resolve_parameters(tool, {"n": bad})
        assert exc.value.reason is DenialReason.PARAM_INVALID
    # Booleans are integers in Python - here they must not be.
    with pytest.raises(Denied):
        resolve_parameters(tool, {"n": True})


# -- Execution -------------------------------------------------------------


async def test_output_is_capped():
    result = await execute.run(
        [PYTHON, "-c", "print('x' * 100000)"],
        timeout_seconds=20,
        max_output_bytes=1024,
        idempotent=True,
    )
    assert result.truncated
    assert len(result.stdout) <= 1024


async def test_timeout_on_idempotent_tool_is_a_failure():
    result = await execute.run(
        [PYTHON, "-c", "import time; time.sleep(30)"],
        timeout_seconds=1,
        max_output_bytes=1024,
        idempotent=True,
    )
    assert result.outcome == execute.OUTCOME_FAILED


async def test_timeout_on_non_idempotent_tool_is_unknown():
    """FR-6.9: the most important distinction in the execution path.

    A timeout reported as an error provokes the retry that, on an
    already-completed write, produces the duplicate.
    """
    result = await execute.run(
        [PYTHON, "-c", "import time; time.sleep(30)"],
        timeout_seconds=1,
        max_output_bytes=1024,
        idempotent=False,
    )
    assert result.outcome == execute.OUTCOME_UNKNOWN
    assert "UNKNOWN" in result.stderr
    assert "Do not retry" in result.stderr


async def test_no_shell_interpretation():
    """The value stays a value -- there is no interpreter."""
    result = await execute.run(
        [PYTHON, "-c", "import sys; print(sys.argv[1])", "$(id); `whoami`"],
        timeout_seconds=10,
        max_output_bytes=4096,
        idempotent=True,
    )
    assert result.stdout.strip() == "$(id); `whoami`"


async def test_missing_binary_is_reported(tmp_path):
    with pytest.raises(Denied) as exc:
        await execute.run(
            [str(tmp_path / "does-not-exist")],
            timeout_seconds=5,
            max_output_bytes=1024,
            idempotent=True,
        )
    assert exc.value.reason is DenialReason.EXECUTOR_UNAVAILABLE


# -- Rate-Limiting ---------------------------------------------------------


async def test_rate_limit_applies(tier1, catalog, tmp_path, identities):
    from gatekeeper.audit import AuditLog
    from gatekeeper.ratelimit import RateLimiter
    from gatekeeper.service import Service
    from gatekeeper.tier1 import RateLimit

    store, _ = identities
    service = Service(
        tier1=tier1, catalog=catalog, audit=AuditLog(str(tmp_path / "logs2"))
    )
    service.limiter = RateLimiter({"read": RateLimit(count=1, window_seconds=60)})

    await service.call(store.identities["full"], "demo.show", {"stack": "media-jellyfin"})
    with pytest.raises(Denied) as exc:
        await service.call(
            store.identities["full"], "demo.show", {"stack": "media-jellyfin"}
        )
    assert exc.value.reason is DenialReason.RATE_LIMITED


# -- Audit -----------------------------------------------------------------


async def test_audit_records_denial_reason(service, identities, tmp_path):
    import json

    store, _ = identities
    with pytest.raises(Denied):
        await service.call(store.identities["narrow"], "demo.echo", {"text": "x"})

    lines = (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[-1])
    assert record["outcome"] == "denied"
    # The agent got an uninformative response - the log knows the reason.
    assert record["denial_reason"] == DenialReason.NOT_GRANTED.value
    assert record["identity"] == "narrow"


async def test_audit_records_version_and_duration(service, identities, tmp_path):
    import json

    store, _ = identities
    await service.call(store.identities["full"], "demo.show", {"stack": "media-jellyfin"})
    lines = (tmp_path / "logs" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[-1])
    assert record["tool_version"] == 1
    assert isinstance(record["duration_ms"], int)
    assert record["outcome"] == "ok"


def test_audit_rotates(tmp_path):
    from gatekeeper.audit import AuditLog

    log = AuditLog(str(tmp_path / "rot"), max_bytes=512, keep_files=3)
    for index in range(200):
        log.write({"kind": "test", "index": index, "filler": "x" * 50})
    assert os.path.exists(str(tmp_path / "rot" / "audit.jsonl.1"))


# -- Shipped state and examples --------------------------------------------


def test_nothing_active_is_shipped():
    """gatekeeper ships no configuration -- only examples.

    A shipped `tools.yaml` would be a capability that nobody
    decided on: after installation, tools would be ready that have
    no author in the audit log. The shipped state is therefore empty.
    """
    config = os.path.join(os.path.dirname(__file__), "..", "config")
    present = sorted(
        name for name in os.listdir(config) if name.endswith((".yaml", ".yml"))
    )
    assert present == [], f"active configuration in repo: {present}"
    assert os.path.isdir(os.path.join(config, "examples"))


def test_missing_catalog_is_an_empty_catalog(tier1, tmp_path):
    """The normal state after `init`, not an error condition."""
    catalog = load_catalog(str(tmp_path / "does-not-exist.yaml"), tier1)
    assert catalog.tools == {}
    assert catalog.raw == []


def test_empty_catalog_file_loads(tier1, tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("tools: []\n", encoding="utf-8")
    assert load_catalog(str(path), tier1).tools == {}
    # Also the case where the key stands without content.
    path.write_text("tools:\n", encoding="utf-8")
    assert load_catalog(str(path), tier1).tools == {}


def test_missing_tier1_names_the_way_out(tmp_path):
    """Tier 1 has no empty state -- the message must point the way forward."""
    from gatekeeper.errors import ConfigError

    with pytest.raises(ConfigError) as exc:
        load_tier1(str(tmp_path / "missing.yaml"))
    assert "gatekeeper init" in str(exc.value)


def test_shipped_config_is_valid(repo_config_dir):
    """The examples must load strictly -- including Tier 1 checks.

    They are what someone copies from. A typo in them would otherwise
    only surface on a foreign host.
    """
    tier1 = load_tier1(os.path.join(repo_config_dir, "toolkits.yaml"))
    catalog = load_catalog(
        os.path.join(repo_config_dir, "tools.yaml"), tier1, strict=True
    )
    assert "docker.compose_up" in catalog.tools
    assert "diag.uptime" in catalog.tools
    assert catalog.disabled_by_tier1 == []

    # All Docker tools must claim a stack scope, otherwise neither
    # the permission profile nor the block list from FR-4.12 applies.
    for tool in catalog.tools.values():
        if tool.toolkit == "docker":
            assert tool.required_scopes == ("stack:{stack}",), tool.id


def test_shipped_docker_toolkit_protects_itself(repo_config_dir):
    tier1 = load_tier1(os.path.join(repo_config_dir, "toolkits.yaml"))
    docker = tier1.toolkit("docker")
    for critical in ("gatekeeper", "dockhand", "ix-dockhand"):
        assert docker.is_protected(critical)


def test_shipped_docker_toolkit_blocks_volume_removal(repo_config_dir):
    """'compose down -v' deletes volumes - no tool needs that."""
    tier1 = load_tier1(os.path.join(repo_config_dir, "toolkits.yaml"))
    docker = tier1.toolkit("docker")
    for flag in ("-v", "--volumes", "--rmi", "rm", "prune"):
        assert docker.check_args(["compose", flag]) == flag


async def test_local_executor_probe_does_not_execute(service):
    """NFR-9: `local` is checked via file permissions, not by execution.

    Regression: the first version started the first binary of the toolkit
    without arguments. With an interpreter that waits for input, and
    /health/ready permanently reported 'degraded'.
    """
    ready = await service.probe_executors()
    assert ready == {"local": True}


# -- init ------------------------------------------------------------------


def _run_init(tmp_path, *extra):
    """Calls the CLI like a human -- including argument parsing."""
    import contextlib
    import io

    from gatekeeper.__main__ import main

    argv = ["gatekeeper", "init", "--config-dir", str(tmp_path), *extra]
    out = io.StringIO()
    err = io.StringIO()
    with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(
        out
    ), contextlib.redirect_stderr(err):
        code = main()
    return code, out.getvalue(), err.getvalue()


def _init_secrets(out: str) -> tuple[str, str]:
    """Console password and API token from the output of `init`.

    `init` outputs both, and in this order -- first that
    with which a human signs in.
    """
    parts = out.split("shown once):")
    assert len(parts) == 3, f"init must output two secrets:\n{out}"
    password = parts[1].split("\n\n")[0].strip()
    token = parts[2].strip()
    return password, token


def test_init_creates_a_runnable_but_empty_state(tmp_path):
    """After `init` the server starts -- and can do nothing.

    That is exactly the intention. gatekeeper makes no assumption about
    which binaries an agent should be able to reach: only someone who
    knows the system knows that. A shipped toolkit would be a capability
    that nobody decided on.
    """
    code, out, _ = _run_init(tmp_path)
    assert code == 0

    tier1 = load_tier1(str(tmp_path / "toolkits.yaml"))
    catalog = load_catalog(str(tmp_path / "tools.yaml"), tier1, strict=True)
    identities = load_identities(str(tmp_path / "identities.yaml"))

    assert tier1.toolkits == {}, "Tier 1 must not preset anything"
    assert catalog.tools == {}, "the shipped state must not know any tool"
    assert list(identities.identities) == ["admin"]
    assert identities.identities["admin"].role == "admin"
    assert identities.identities["admin"].tools == frozenset()

    # init may set operational parameters -- they permit nothing, they limit.
    assert tier1.rate_limits["read"].count > 0
    assert tier1.audit_dir

    password, token = _init_secrets(out)
    assert identities.authenticate(token).id == "admin"
    # And the second, separate proof: the console password. It opens the
    # UI; the token does not.
    assert identities.authenticate_console("admin", password).id == "admin"
    assert identities.authenticate_console("admin", token) is None


def test_empty_tier1_is_valid(tmp_path):
    """Tier 1 without toolkits is a valid statement: nothing is possible."""
    path = tmp_path / "toolkits.yaml"
    for body in ("toolkits: {}\n", "toolkits:\n"):
        path.write_text(body + "audit:\n  dir: /tmp/x\n", encoding="utf-8")
        assert load_tier1(str(path)).toolkits == {}


def test_tool_for_a_removed_toolkit_is_disabled_not_fatal(tmp_path, tier1, tool_specs):
    """FR-4.7: if a toolkit disappears, its tool falls away -- not the startup.

    Otherwise, removing a toolkit would be a way to bring the service down:
    the next startup would abort, and before anyone could reach the UI
    to repair the catalog.
    """
    import yaml as _yaml

    from gatekeeper.errors import Tier1Violation

    empty_path = tmp_path / "empty-tier1.yaml"
    empty_path.write_text("toolkits: {}\n", encoding="utf-8")
    empty = load_tier1(str(empty_path))

    tools_path = tmp_path / "orphaned.yaml"
    tools_path.write_text(_yaml.safe_dump({"tools": tool_specs}), encoding="utf-8")

    catalog = load_catalog(str(tools_path), empty)
    assert catalog.tools == {}
    assert len(catalog.disabled_by_tier1) == len(tool_specs)
    assert "Unknown toolkit" in catalog.disabled_by_tier1[0]

    with pytest.raises(Tier1Violation):
        load_catalog(str(tools_path), empty, strict=True)


def test_init_refuses_to_clobber(tmp_path):
    assert _run_init(tmp_path)[0] == 0
    before = (tmp_path / "identities.yaml").read_text(encoding="utf-8")

    code, _, err = _run_init(tmp_path)
    assert code == 1
    assert "Refusing to overwrite" in err
    assert (tmp_path / "identities.yaml").read_text(encoding="utf-8") == before

    assert _run_init(tmp_path, "--force")[0] == 0
    assert (tmp_path / "identities.yaml").read_text(encoding="utf-8") != before


def test_init_secrets_appear_once_and_only_as_hashes_on_disk(tmp_path):
    _, out, _ = _run_init(tmp_path)
    password, token = _init_secrets(out)
    on_disk = (tmp_path / "identities.yaml").read_text(encoding="utf-8")

    assert token.startswith("gk_")
    assert out.count(token) == 1
    assert token not in on_disk

    # The password deliberately does not carry 'gk_': in plain text one
    # should be able to distinguish the API token from the console password.
    assert not password.startswith("gk_")
    assert password != token
    assert out.count(password) == 1
    assert password not in on_disk
    assert "password_hash" in on_disk


def test_example_compose_ps_asks_for_json(repo_config_dir):
    """`docker compose ps` should answer structured, not as a text table.

    An agent that counts columns misreads on the first long container
    name. '--format json' is fixed in the template and therefore not
    an attack surface -- a parameter value cannot produce it (FR-5.4).
    """
    tier1 = load_tier1(os.path.join(repo_config_dir, "toolkits.yaml"))
    catalog = load_catalog(os.path.join(repo_config_dir, "tools.yaml"), tier1, strict=True)
    argv = catalog.tools["docker.compose_ps"].argv
    assert argv[-2:] == ("--format", "json")

    # The format must not come from a parameter -- otherwise an
    # agent could redirect it.
    assert "{" not in "".join(argv[-2:])


def test_directory_instead_of_file_says_what_happened(tmp_path):
    """The Docker trap: mounted file missing on the host -> directory.

    Without special handling this breaks through as a raw IsADirectoryError --
    a message about a file that is seemingly present. The cause
    is in the mount, and that is exactly what must be stated.
    """
    from gatekeeper.errors import ConfigError

    (tmp_path / "toolkits.yaml").mkdir()
    with pytest.raises(ConfigError) as exc:
        load_tier1(str(tmp_path / "toolkits.yaml"))
    message = str(exc.value)
    assert "is a directory" in message
    assert "bind-mounted file does not exist" in message

    (tmp_path / "identities.yaml").mkdir()
    with pytest.raises(ConfigError) as exc:
        load_identities(str(tmp_path / "identities.yaml"))
    assert "is a directory" in str(exc.value)


def test_state_dir_separates_the_two_tiers(tmp_path, monkeypatch):
    """Tier 1 and Tier 2 may reside in separate mounts."""
    from gatekeeper.__main__ import _config_path

    monkeypatch.setenv("GATEKEEPER_CONFIG_DIR", str(tmp_path / "conf"))
    monkeypatch.setenv("GATEKEEPER_STATE_DIR", str(tmp_path / "state"))
    assert _config_path("toolkits.yaml", None).startswith(str(tmp_path / "conf"))
    assert _config_path("tools.yaml", None).startswith(str(tmp_path / "state"))
    assert _config_path("identities.yaml", None).startswith(str(tmp_path / "state"))

    # Without STATE_DIR everything is together -- one mount suffices.
    monkeypatch.delenv("GATEKEEPER_STATE_DIR")
    assert _config_path("tools.yaml", None).startswith(str(tmp_path / "conf"))


# -- First start -------------------------------------------------------------


def test_first_start_creates_everything_from_an_empty_directory(tmp_path):
    """Mount a folder, start -- that should be all it takes."""
    from gatekeeper.__main__ import _bootstrap_on_first_start

    empty = tmp_path / "config"
    empty.mkdir()
    _bootstrap_on_first_start(str(empty), str(empty))

    tier1 = load_tier1(str(empty / "toolkits.yaml"))
    identities = load_identities(str(empty / "identities.yaml"))
    assert tier1.toolkits == {}
    assert load_catalog(str(empty / "tools.yaml"), tier1).tools == {}
    assert [i.role for i in identities.identities.values()] == ["admin"]


def test_unwritable_directory_names_the_real_cause(tmp_path, monkeypatch):
    """The case that actually occurred in operation.

    Docker creates a missing bind-mount source as root; the container
    runs as 568 and may not enter it. Previously, the first start
    exited silently here, and the loader then reported 'not found' -- the wrong
    cause, because the directory was there. It just belonged to nobody.
    """
    from gatekeeper import __main__ as cli

    monkeypatch.setattr(
        cli, "bootstrap", mock.Mock(side_effect=PermissionError(13, "Permission denied"))
    )
    message = cli._bootstrap_on_first_start(str(tmp_path), str(tmp_path))
    assert message is not None
    assert "Cannot create the configuration" in message
    assert "chown" in message
    assert "root" in message


def test_first_start_does_not_touch_a_partial_configuration(tmp_path):
    """The important case: if something is already there, nothing is created.

    A slipped mount otherwise looks like a first installation. Laying
    a fresh configuration over it would cover up the error and give
    the impression that the catalog had disappeared -- along with a new
    administrator token that nobody requested.
    """
    from gatekeeper.__main__ import _bootstrap_on_first_start

    partial = tmp_path / "config"
    partial.mkdir()
    (partial / "toolkits.yaml").write_text("toolkits: {}\n", encoding="utf-8")

    _bootstrap_on_first_start(str(partial), str(partial))

    assert not (partial / "identities.yaml").exists()
    assert not (partial / "tools.yaml").exists()
    assert (partial / "toolkits.yaml").read_text(encoding="utf-8") == "toolkits: {}\n"


def test_first_start_leaves_a_complete_configuration_alone(tmp_path):
    from gatekeeper.__main__ import _bootstrap_on_first_start, bootstrap

    directory = tmp_path / "config"
    directory.mkdir()
    token, password = bootstrap(str(directory), str(directory))
    before = (directory / "identities.yaml").read_text(encoding="utf-8")

    _bootstrap_on_first_start(str(directory), str(directory))

    assert (directory / "identities.yaml").read_text(encoding="utf-8") == before
    fresh = load_identities(str(directory / "identities.yaml"))
    assert fresh.authenticate(token)
    assert fresh.authenticate_console("admin", password)


def test_unwritable_audit_directory_refuses_to_start(tmp_path, capsys):
    """Without an audit log, startup is refused.

    A service that mediates host operations and cannot record them
    is worse than none: the calls take place, but afterwards
    nobody knows which. Previously this broke through as a raw OSError.
    """
    from gatekeeper import __main__ as cli

    cli.bootstrap(str(tmp_path), str(tmp_path))
    argv = [
        "gatekeeper",
        "--toolkits", str(tmp_path / "toolkits.yaml"),
        "--tools", str(tmp_path / "tools.yaml"),
        "--identities", str(tmp_path / "identities.yaml"),
        "serve", "--no-bootstrap",
    ]
    with mock.patch.object(sys, "argv", argv), mock.patch.object(
        cli, "AuditLog", side_effect=PermissionError(13, "Permission denied")
    ):
        code = cli.main()

    assert code == 2
    message = capsys.readouterr().err
    assert "audit directory" in message
    assert "chown" in message


# -- Console password on the command line --------------------------------


def _run_cli(*argv):
    """Calls the CLI like a human and captures both streams."""
    import contextlib
    import io

    from gatekeeper.__main__ import main

    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(sys, "argv", ["gatekeeper", *argv]), (
        contextlib.redirect_stdout(out)
    ), contextlib.redirect_stderr(err):
        code = main()
    return code, out.getvalue(), err.getvalue()


def test_password_command_sets_a_console_password(tmp_path):
    """The way back in when nobody can get in anymore."""
    from gatekeeper.__main__ import bootstrap

    bootstrap(str(tmp_path), str(tmp_path))
    path = tmp_path / "identities.yaml"

    code, out, _ = _run_cli(
        "--identities", str(path), "password", "--identity", "admin"
    )
    assert code == 0
    password = out.split("shown once):")[1].split("\n\n")[0].strip()

    identities = load_identities(str(path))
    assert identities.authenticate_console("admin", password).role == "admin"
    # Only the plain text is new; on disk there is a hash.
    assert password not in path.read_text(encoding="utf-8")


def test_password_command_leaves_the_api_token_alone(tmp_path):
    """Two proofs, two changes: touching one must not invalidate the other."""
    from gatekeeper.__main__ import bootstrap

    token, _ = bootstrap(str(tmp_path), str(tmp_path))
    path = tmp_path / "identities.yaml"

    assert _run_cli("--identities", str(path), "password", "--identity", "admin")[0] == 0
    assert load_identities(str(path)).authenticate(token).id == "admin"


def test_password_command_refuses_an_agent(tmp_path):
    from gatekeeper.__main__ import bootstrap
    from gatekeeper.identity import generate_token, hash_token

    bootstrap(str(tmp_path), str(tmp_path))
    path = tmp_path / "identities.yaml"
    path.write_text(
        path.read_text(encoding="utf-8")
        + "  - id: bot\n"
        + "    role: agent\n"
        + f'    token_hash: "{hash_token(generate_token())}"\n'
        + "    tools: []\n"
        + "    scopes: []\n",
        encoding="utf-8",
    )

    code, _, err = _run_cli("--identities", str(path), "password", "--identity", "bot")
    assert code == 1
    assert "does not sign in" in err


def test_password_command_names_the_known_identities(tmp_path):
    from gatekeeper.__main__ import bootstrap

    bootstrap(str(tmp_path), str(tmp_path))
    code, _, err = _run_cli(
        "--identities", str(tmp_path / "identities.yaml"),
        "password", "--identity", "typo",
    )
    assert code == 1
    assert "Known: admin" in err


def test_a_short_password_is_refused_on_the_command_line(tmp_path):
    from gatekeeper.__main__ import bootstrap

    bootstrap(str(tmp_path), str(tmp_path))
    code, _, err = _run_cli(
        "--identities", str(tmp_path / "identities.yaml"),
        "password", "--identity", "admin", "--password", "short",
    )
    assert code == 1
    assert "at least" in err


# -- Upgrade from a version without console passwords --------------------


def _legacy_identities(tmp_path):
    """An identities.yaml as it looked before console login existed."""
    from gatekeeper.identity import generate_token, hash_token

    path = tmp_path / "identities.yaml"
    path.write_text(
        "identities:\n"
        "  - id: root\n"
        "    role: admin\n"
        f'    token_hash: "{hash_token(generate_token())}"\n'
        "    tools: []\n"
        "    scopes: []\n",
        encoding="utf-8",
    )
    return path


def test_an_old_configuration_still_loads(tmp_path):
    """Without 'password_hash' the file remains valid.

    The MCP endpoint does not depend on the console: a version without
    passwords must continue to start and serve agents. Whether console
    access is available is decided by startup with --ui, not by the loader.
    """
    store = load_identities(str(_legacy_identities(tmp_path)))
    assert store.identities["root"].role == "admin"
    assert store.identities["root"].password_hash == ""
    assert not store.identities["root"].can_sign_in


def test_the_first_ui_start_hands_out_a_password(tmp_path, caplog):
    """The upgrade path: generated once, written to the log once.

    The alternative would be a deployment that stands still after an
    image change -- for a change that nobody requested.
    """
    import logging

    from gatekeeper.__main__ import _ensure_console_passwords

    path = _legacy_identities(tmp_path)
    identities = load_identities(str(path))
    with caplog.at_level(logging.WARNING):
        assert _ensure_console_passwords(str(path), identities) is None

    password = caplog.text.split("shown once, and only here): ")[1].split(" --")[0]
    assert identities.identities["root"].can_sign_in
    assert identities.authenticate_console("root", password) is not None
    assert password not in path.read_text(encoding="utf-8")

    # A second start generates nothing new.
    before = path.read_text(encoding="utf-8")
    assert _ensure_console_passwords(str(path), identities) is None
    assert path.read_text(encoding="utf-8") == before


def test_a_read_only_configuration_names_the_way_out(tmp_path, monkeypatch):
    """If nothing can be written, startup is refused -- with instructions."""
    from gatekeeper import store as store_module
    from gatekeeper.__main__ import _ensure_console_passwords

    path = _legacy_identities(tmp_path)
    identities = load_identities(str(path))
    monkeypatch.setattr(store_module, "writable", lambda _path: False)

    message = _ensure_console_passwords(str(path), identities)
    assert message is not None
    assert "gatekeeper password --identity root" in message
    assert not identities.identities["root"].can_sign_in