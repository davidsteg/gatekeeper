"""The `google` executor's fallback to the script baked into the image.

0.40.1 moved `google_api.py` into the image (`/opt/gatekeeper/google/`);
toolkits written in the 0.38/0.40.0 era still name the host path that was
mounted in back then. Those toolkits parse clean -- Tier 1 checks a
`google_script` for shape, never for existence -- so the first report used
to be a failing call naming only the path that is wrong.

A real stub script and a real subprocess here, for `test_execute_google.py`'s
reason: "the fallback path was used" is exactly the kind of claim a mocked
subprocess would assert about itself rather than about what ran.
"""

from __future__ import annotations

import json
import logging
import os
import textwrap

import pytest
import yaml

from gatekeeper import execute_google
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK
from gatekeeper.tier1 import load_tier1, missing_google_script

#: What a pre-0.40.1 toolkit names: a host path mounted into the container
#: back then, absent from every image since.
LEGACY_SCRIPT = "/etc/nonexistent/google_api.py"


def _write_stub(path: str) -> None:
    """A stand-in for google_api.py that reports which file it is."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            textwrap.dedent(
                """\
                import json, os, sys

                print(json.dumps({"ran": os.path.abspath(__file__),
                                  "action": " ".join(sys.argv[1:])}))
                sys.exit(0)
                """
            )
        )
    os.chmod(path, 0o755)


@pytest.fixture
def baked_script(tmp_path, monkeypatch):
    """The image's own copy, relocated into tmp_path.

    The real path is baked into the image and absent from a dev checkout,
    so the constant is monkeypatched rather than the file created --
    `_resolve_script` reads the module global, which is the same thing the
    image's absolute path is at runtime.
    """
    path = tmp_path / "baked_google_api.py"
    _write_stub(str(path))
    monkeypatch.setattr(execute_google, "GOOGLE_FALLBACK_SCRIPT", str(path))
    return str(path)


def _toolkit(tmp_path, *, script: str, container: str | None = None, name="gmail"):
    spec = {
        "executor": "google",
        "google_script": script,
        "allowed_google_actions": ["gmail search"],
        "max_timeout_seconds": 20,
        "max_output_bytes": 65536,
    }
    if container is not None:
        spec["google_container"] = container
    path = tmp_path / f"toolkits-{name}.yaml"
    path.write_text(
        yaml.safe_dump(
            {"toolkits": {name: spec}, "audit": {"dir": str(tmp_path / "logs")}}
        ),
        encoding="utf-8",
    )
    return load_tier1(str(path)).toolkit(name)


async def _run(toolkit):
    return await execute_google.run(
        google_action="gmail search",
        args=["is:unread"],
        toolkit=toolkit,
        timeout_seconds=10,
        max_output_bytes=65536,
        idempotent=True,
        env={"HOME": "/nonexistent-home"},  # the stub does not read a token
    )


# -- The executor falls back, and says so -----------------------------------


async def test_a_legacy_script_path_runs_the_baked_copy(tmp_path, baked_script, caplog):
    """The reported failure mode, fixed: the toolkit names a path that is

    not there, the call succeeds anyway, and the baked-in script is what
    actually ran.
    """
    toolkit = _toolkit(tmp_path, script=LEGACY_SCRIPT)
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        result = await _run(toolkit)

    assert result.outcome == OUTCOME_OK
    payload = json.loads(result.stdout)
    assert payload["ran"] == os.path.abspath(baked_script)
    assert payload["action"] == "gmail search is:unread"


async def test_the_fallback_warns_once_naming_both_paths(tmp_path, baked_script, caplog):
    """One warning per call, carrying both halves of the divergence: what

    toolkits.yaml says and what ran. Either path alone leaves the operator
    guessing at the other.
    """
    toolkit = _toolkit(tmp_path, script=LEGACY_SCRIPT)
    caplog.clear()  # the load above warns too -- this counts the call's own
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        await _run(toolkit)

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert LEGACY_SCRIPT in message
    assert baked_script in message
    assert "gmail" in message


async def test_an_existing_script_is_used_unchanged_and_silently(
    tmp_path, baked_script, caplog
):
    """No fallback when there is nothing to fall back from -- and no

    warning, or every correctly configured deployment would log one.
    """
    own = tmp_path / "own_google_api.py"
    _write_stub(str(own))
    toolkit = _toolkit(tmp_path, script=str(own))
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        result = await _run(toolkit)

    assert result.outcome == OUTCOME_OK
    assert json.loads(result.stdout)["ran"] == os.path.abspath(str(own))
    assert caplog.records == []


async def test_without_a_baked_copy_the_configured_path_is_kept(tmp_path, monkeypatch):
    """Neither path exists: the call fails, naming the path the operator

    configured. Substituting a second path that is also absent would only
    add a second wrong name to the error.
    """
    monkeypatch.setattr(
        execute_google, "GOOGLE_FALLBACK_SCRIPT", "/etc/nonexistent/baked.py"
    )
    toolkit = _toolkit(tmp_path, script=LEGACY_SCRIPT)
    result = await _run(toolkit)

    assert result.outcome == OUTCOME_FAILED
    assert LEGACY_SCRIPT in result.stderr


async def test_a_google_container_toolkit_never_falls_back(tmp_path, baked_script):
    """`google_container` puts the script on another container's

    filesystem, so this one has no opinion about whether it exists --
    same reason `missing_local_binaries` skips `ssh` toolkits.
    """
    toolkit = _toolkit(tmp_path, script=LEGACY_SCRIPT, container="hermes-google")
    argv = execute_google._build_argv(toolkit, "gmail search", ["is:unread"])

    assert argv[:3] == ["docker", "exec", "hermes-google"]
    assert LEGACY_SCRIPT in argv
    assert baked_script not in argv


async def test_probe_reports_ready_through_the_fallback(tmp_path, baked_script, caplog):
    """Readiness asks the same question the call does, so it must get the

    same answer -- and must not log a line per poll.
    """
    toolkit = _toolkit(tmp_path, script=LEGACY_SCRIPT)
    caplog.clear()  # the load above warns too -- the probe must not
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        assert await execute_google.probe(toolkit) is True
    assert caplog.records == []


# -- The startup warning (tier1) --------------------------------------------


def _load_with(caplog, path):
    with caplog.at_level(logging.WARNING, logger="gatekeeper"):
        return load_tier1(path)


def test_a_legacy_google_script_warns_at_load(tmp_path, monkeypatch, caplog):
    """The pre-0.40.1 toolkit at startup: loads clean (existence is not a

    Tier 1 error), and the operator hears about it while they are still
    looking at the log rather than on an agent's call hours later.
    """
    baked = tmp_path / "baked_google_api.py"
    _write_stub(str(baked))
    monkeypatch.setattr("gatekeeper.tier1.GOOGLE_FALLBACK_SCRIPT", str(baked))

    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": {
                        "executor": "google",
                        "google_script": LEGACY_SCRIPT,
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
    tier1 = _load_with(caplog, str(path))

    assert tier1.toolkit("gmail").google_script == LEGACY_SCRIPT
    assert LEGACY_SCRIPT in caplog.text
    assert str(baked) in caplog.text
    assert "gmail" in caplog.text


def test_the_startup_warning_says_so_when_there_is_no_fallback_either(
    tmp_path, monkeypatch, caplog
):
    """Both paths absent is the worse case, and reads differently: every

    call on this toolkit will fail, and no fallback is going to save it.
    """
    monkeypatch.setattr(
        "gatekeeper.tier1.GOOGLE_FALLBACK_SCRIPT", "/etc/nonexistent/baked.py"
    )
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": {
                        "executor": "google",
                        "google_script": LEGACY_SCRIPT,
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
    _load_with(caplog, str(path))

    assert LEGACY_SCRIPT in caplog.text
    assert "/etc/nonexistent/baked.py" in caplog.text
    assert "will fail" in caplog.text


def test_an_existing_google_script_warns_about_nothing(tmp_path, caplog):
    own = tmp_path / "own_google_api.py"
    _write_stub(str(own))
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": {
                        "executor": "google",
                        "google_script": str(own),
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
    tier1 = _load_with(caplog, str(path))

    assert missing_google_script(tier1.toolkit("gmail")) is None
    assert caplog.records == []


def test_the_startup_check_skips_non_google_and_container_toolkits(tmp_path, caplog):
    """Scoped the way the executor's fallback is: a `local` toolkit has no

    google_script at all, and a `google_container` one keeps its script on
    another filesystem.
    """
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "diag": {
                        "executor": "local",
                        "binaries": ["/usr/bin/uptime"],
                        "max_timeout_seconds": 10,
                        "max_output_bytes": 65536,
                    },
                    "gmail-remote": {
                        "executor": "google",
                        "google_script": LEGACY_SCRIPT,
                        "google_container": "hermes-google",
                        "allowed_google_actions": ["gmail search"],
                        "max_timeout_seconds": 20,
                        "max_output_bytes": 65536,
                    },
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    tier1 = _load_with(caplog, str(path))

    assert missing_google_script(tier1.toolkit("diag")) is None
    assert missing_google_script(tier1.toolkit("gmail-remote")) is None
    assert "google_script" not in caplog.text
