"""benign_exit1: exit 1 of grep/diff/test & co. is an answer, not a failure."""

from __future__ import annotations

import asyncio
import os

import pytest
from conftest import PYTHON

from gatekeeper import execute, exitcodes
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK, OUTCOME_UNKNOWN
from gatekeeper.exitcodes import benign_exit1


def docker(command: str) -> list[str]:
    return ["docker", "exec", "c", "sh", "-c", command]


def test_grep_no_match_via_docker_sh_c():
    assert benign_exit1(docker("grep foo /x"), "", "", 1, OUTCOME_FAILED)


@pytest.mark.parametrize(
    "command",
    [
        "egrep foo /x",
        "fgrep foo /x",
        "rg foo /x",
        "diff /a /b",
        "cmp /a /b",
        "test -f /x",
        "[ -f /x ]",
    ],
)
def test_each_benign_command(command):
    assert benign_exit1(docker(command), "", "", 1, OUTCOME_FAILED)


def test_absolute_path_is_reduced_to_basename():
    assert benign_exit1(docker("/usr/bin/grep foo /x"), "", "", 1, OUTCOME_FAILED)


def test_direct_argv_for_local_and_ssh():
    assert benign_exit1(["/usr/bin/grep", "foo", "/x"], "", "", 1, OUTCOME_FAILED)
    assert benign_exit1(["diff", "/a", "/b"], "1c1\n", "", 1, OUTCOME_FAILED)


def test_exit_2_is_a_failure():
    assert not benign_exit1(docker("grep foo /x"), "", "", 2, OUTCOME_FAILED)


def test_exit_1_with_stderr_is_a_failure():
    assert not benign_exit1(
        docker("grep foo /x"), "", "grep: /x: No such file\n", 1, OUTCOME_FAILED
    )


def test_timeout_is_a_failure():
    assert not benign_exit1(docker("grep foo /x"), "", "", None, OUTCOME_FAILED)


def test_outcome_unknown_is_not_rewritten():
    assert not benign_exit1(docker("grep foo /x"), "", "", 1, OUTCOME_UNKNOWN)


def test_other_command_is_a_failure():
    assert not benign_exit1(docker("cat /x"), "", "", 1, OUTCOME_FAILED)


def test_pipeline_is_a_failure():
    assert not benign_exit1(docker("grep a /x | wc -l"), "", "", 1, OUTCOME_FAILED)


def test_docker_without_sh_c_is_a_failure():
    assert not benign_exit1(
        ["docker", "exec", "c", "grep", "foo", "/x"], "", "", 1, OUTCOME_FAILED
    )


def _fake_run(exit_code: int, stderr: str = ""):
    async def run(argv, **kwargs):
        return execute.Result(
            outcome=OUTCOME_FAILED,
            exit_code=exit_code,
            stdout="",
            stderr=stderr,
            truncated=False,
            duration_ms=1,
        )

    return run


def test_service_reports_benign_exit1_as_ok(service, identities, monkeypatch):
    # The demo toolkit's binary is the Python interpreter; treat it as a
    # benign command so the service path can be exercised without grep.
    monkeypatch.setattr(
        exitcodes, "BENIGN_EXIT1_COMMANDS", frozenset({os.path.basename(PYTHON)})
    )
    monkeypatch.setattr(execute, "run", _fake_run(1))
    store, _ = identities
    result = asyncio.run(
        service.call(store.identities["full"], "demo.echo", {"text": "x"})
    )
    assert result.outcome == OUTCOME_OK
    assert result.exit_code == 1
    assert service.metrics[("demo.echo", "full", OUTCOME_OK)] == 1


def test_service_keeps_other_exit1_failed(service, identities, monkeypatch):
    monkeypatch.setattr(execute, "run", _fake_run(1))
    store, _ = identities
    result = asyncio.run(
        service.call(store.identities["full"], "demo.echo", {"text": "x"})
    )
    assert result.outcome == OUTCOME_FAILED
    assert result.exit_code == 1


def test_exec_without_docker_prefix():
    assert benign_exit1(["exec", "c", "sh", "-c", "grep foo /x"], "", "", 1, OUTCOME_FAILED)


def test_bare_sh_c_for_local_and_ssh():
    assert benign_exit1(["/bin/sh", "-c", "grep foo /x"], "", "", 1, OUTCOME_FAILED)


@pytest.mark.parametrize(
    "argv",
    [
        # sh -c pair later in argv = parameter values, not the command
        ["docker", "exec", "c", "echo", "sh", "-c", "grep foo /x"],
        ["/usr/bin/python3", "tool.py", "sh", "-c", "grep foo /x"],
        ["exec", "c", "cat", "bash", "-c", "test -f /x"],
        # docker subcommand other than exec
        ["docker", "run", "img", "sh", "-c", "grep foo /x"],
    ],
)
def test_sh_c_outside_command_position_is_ignored(argv):
    assert not benign_exit1(argv, "", "", 1, OUTCOME_FAILED)


def test_sh_c_without_script_is_a_failure():
    assert not benign_exit1(["docker", "exec", "c", "sh", "-c"], "", "", 1, OUTCOME_FAILED)
