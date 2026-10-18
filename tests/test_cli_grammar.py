"""The argv gatekeeper builds, against the two real CLI grammars.

The crate pins what it *builds* for every shipped google/microsoft tool
(rust/tests/cli_arg_contract.rs compares it with
rust/tests/fixtures/shipped_cli_argv_golden.json); this pins what the
vendored CLIs make of exactly those argvs: whether every flag exists in
the grammar at all, and whether what an omitted optional flag leaves
behind is still enough.

Nothing is sent and nothing is read: HERMES_HOME points at an empty
directory, so every run dies for want of a token file (drive.upload for
want of the local file it would have uploaded, one step earlier) --
after argparse has had its say, before the first HTTP request. `PATH` is
deliberately dead too, so google_api.py cannot find a `gws` binary to
delegate to.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The two vendored CLIs, by the executor that runs them.
CLI_SCRIPTS = {
    "google": REPO_ROOT / "scripts" / "google" / "google_api.py",
    "microsoft": REPO_ROOT / "scripts" / "microsoft" / "microsoft_api.py",
}

SHIPPED_ARGV = REPO_ROOT / "rust" / "tests" / "fixtures" / "shipped_cli_argv_golden.json"

#: What argparse prints when it refuses an argv.
ARGPARSE_REJECTIONS = (
    "usage:",
    "unrecognized arguments",
    "invalid choice",
    "the following arguments are required",
    "expected one argument",
)


def test_the_minimal_argv_of_every_shipped_cli_tool_parses(tmp_path):
    """Exit 2 with `usage:` on stderr is the failure this catches: a flag
    the CLI does not have, an action word it does not know, or a
    CLI-required flag mapped to an optional parameter and therefore left
    off the argv. Exit 1 is the pass -- argparse accepted the argv and the
    action itself then failed for want of the token file (or, for
    drive.upload, the local file) that is deliberately not there."""
    home = tmp_path / "empty-hermes-home"
    home.mkdir()
    env = {
        **os.environ,
        "HOME": str(home),
        "HERMES_HOME": str(home),
        "PATH": "/nonexistent",
    }

    rows = json.loads(SHIPPED_ARGV.read_text(encoding="utf-8"))
    assert rows, "no shipped google/microsoft tool to check"
    for row in rows:
        argv = [sys.executable, str(CLI_SCRIPTS[row["executor"]]), *row["argv"]]
        proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=60)
        where = f"{row['source']}: {row['id']} -> {' '.join(row['argv'])}"
        rejected = proc.returncode == 2 or any(
            marker in proc.stderr for marker in ARGPARSE_REJECTIONS
        )
        assert not rejected, (
            f"{where}\nthe CLI's grammar rejected this argv:\n{proc.stderr.strip()}"
        )
        assert proc.returncode == 1, f"{where}\n{proc.stderr.strip()}"


# -- A switch, against the two real argparse grammars -----------------------
#
# The crate pins what it emits for a switch (`--raw-query` for true,
# nothing for false or omitted); these pin what the CLIs make of it, in
# their own parsers rather than a description of them. Each CLI's `main()`
# builds the real parser and dispatches through `args.func`, which
# `set_defaults` reads out of the module globals as that line runs -- so
# replacing the handler first captures the parsed namespace before a
# single request is made. Nothing is sent and no token is read.


def _load_cli(name):
    spec = importlib.util.spec_from_file_location(
        f"_cli_under_test_{name}", CLI_SCRIPTS[name]
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def google_cli(monkeypatch):
    # google_api.py puts its own directory on sys.path to reach
    # `_hermes_home`; the copy is restored at teardown.
    monkeypatch.setattr(sys, "path", list(sys.path))
    return _load_cli("google")


@pytest.fixture
def microsoft_cli():
    return _load_cli("microsoft")


def _real_parse(module, handler, argv, monkeypatch):
    """The argparse namespace the CLI itself builds for `argv`."""
    seen = {}

    def record(args):
        seen["args"] = args
        return {}

    monkeypatch.setattr(module, handler, record)
    monkeypatch.setattr(sys, "argv", ["cli", *argv])
    module.main()
    return seen["args"]


def test_the_shipped_drive_search_switch_parses_as_store_true(google_cli, monkeypatch):
    """`drive.search`'s `raw_query: true`, as the shipped catalog builds
    it, handed to google_api.py's own Drive grammar. `--raw-query` is
    `store_true` there, and this is the argv that sets it."""
    argv = ["drive", "search", "name contains 'budget'", "--raw-query"]

    args = _real_parse(google_cli, "drive_search", argv, monkeypatch)
    assert args.raw_query is True
    assert args.query == "name contains 'budget'"


def test_the_shipped_drive_search_without_the_switch_parses_as_false(
    google_cli, monkeypatch
):
    """`false` and "omitted" are the same argv, and the CLI reads it as
    its own `store_true` default -- a full-text search, not a raw one."""
    args = _real_parse(google_cli, "drive_search", ["drive", "search", "budget"], monkeypatch)
    assert args.raw_query is False


def test_a_microsoft_switch_parses_as_store_true(microsoft_cli, monkeypatch):
    """The same against microsoft_api.py's `mail list --unread`, so the
    contract is checked against both real grammars."""
    argv = ["mail", "list", "--folder", "inbox", "--unread"]
    args = _real_parse(microsoft_cli, "mail_list", argv, monkeypatch)
    assert args.unread is True
    assert args.folder == "inbox"

    args = _real_parse(microsoft_cli, "mail_list", ["mail", "list", "--folder", "inbox"], monkeypatch)
    assert args.unread is False


@pytest.mark.parametrize(
    "cli,handler,argv",
    [
        ("google", "drive_search", ["drive", "search", "q", "--raw-query", "true"]),
        ("microsoft", "mail_list", ["mail", "list", "--unread", "true"]),
    ],
    ids=["google", "microsoft"],
)
def test_both_grammars_reject_the_valued_spelling(cli, handler, argv, monkeypatch):
    """Why `switch:` exists at all. `--flag true` -- what a valued
    mapping emits for a boolean -- is not a value these parsers take: it
    is an extra positional the action does not have, and argparse exits
    2 over it rather than quietly doing something."""
    monkeypatch.setattr(sys, "path", list(sys.path))
    module = _load_cli(cli)
    with pytest.raises(SystemExit) as excinfo:
        _real_parse(module, handler, argv, monkeypatch)
    assert excinfo.value.code == 2
