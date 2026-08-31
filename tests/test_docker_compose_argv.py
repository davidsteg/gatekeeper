"""The effective docker command keeps `compose` in front of `-p`.

Reported as: `docker.compose_ps(stack=jellyfin)` exits 125 with
`unknown shorthand flag: 'p' in -p`, with the docker executor suspected of
dropping the `compose` subcommand while assembling the command.

It does not, and there is no separate docker executor to drop it in:
`toolkit.executor == "docker"` runs the same `validate.build_argv` ->
`execute.run` path as `local`, and `build_argv` is verbatim -- it prepends
`tool.binary` and appends exactly one resolved string per `argv` template
element (FR-5.3/5.4), inserting and removing nothing. `_unpriv`, the one
wrapper that ever stands between it and the binary, `execv`s the argv it
was handed without parsing it.

So a `docker -p ...` on the wire says the spec the *running* catalog
resolved to carried no `compose` -- for a versioned entry (FR-3.3) that is
the one version `current_version` names, which is not necessarily the
version a reader of `admin.tool_get`'s full `versions` list looks at.

These tests pin both halves: the shipped catalog really does build
`docker compose -p ...`, and the builder stays verbatim -- so the reported
symptom can never be papered over by injecting `compose` here, which would
hide a bad spec instead of surfacing it.
"""

from __future__ import annotations

import os

import pytest

from gatekeeper.catalog import load_catalog, parse_tool_spec
from gatekeeper.tier1 import load_tier1
from gatekeeper.validate import build_argv

#: Every placeholder the shipped docker tools use, resolved. `compose_path`
#: is derived (FR-5.5) and normally comes from `resolve_parameters`; supplied
#: directly here because these tests are about argv assembly, not about path
#: resolution, which has its own coverage and its own `/mnt/raid` sandbox.
VALUES = {
    "stack": "jellyfin",
    "compose_path": "/mnt/raid/jellyfin/compose.yaml",
    "tail": "100",
}


@pytest.fixture
def shipped(repo_config_dir):
    tier1 = load_tier1(os.path.join(repo_config_dir, "toolkits.yaml"))
    catalog = load_catalog(os.path.join(repo_config_dir, "tools.yaml"), tier1, strict=True)
    return tier1, catalog


def test_shipped_docker_tools_keep_compose_before_p(shipped):
    """`-p` is never docker's own first argument.

    `docker -p` is a flag error (exit 125); `docker compose -p` is the
    project flag of the compose plugin. The only difference is element 1.
    """
    tier1, catalog = shipped
    docker_tools = [t for t in catalog.tools.values() if t.toolkit == "docker"]
    assert docker_tools, "the shipped catalog must still carry docker tools"

    for tool in docker_tools:
        argv = build_argv(tool, VALUES, tier1.toolkit(tool.toolkit))
        assert argv[0] == tool.binary, tool.id
        assert argv[1] == "compose", f"{tool.id} would run 'docker {argv[1]}'"
        assert argv[2] == "-p", tool.id
        assert argv[3] == VALUES["stack"], tool.id


def test_compose_ps_builds_the_exact_command(shipped):
    """The full command for the tool the incident was reported against."""
    tier1, catalog = shipped
    tool = catalog.tools["docker.compose_ps@nas1"]

    assert build_argv(tool, VALUES, tier1.toolkit("docker")) == [
        "/usr/bin/docker",
        "compose",
        "-p",
        "jellyfin",
        "-f",
        "/mnt/raid/jellyfin/compose.yaml",
        "ps",
        "--format",
        "json",
    ]


def test_build_argv_inserts_nothing(shipped):
    """A spec without `compose` builds `docker -p ...` -- and must keep doing so.

    This is the reported failure reproduced at its actual origin. The
    builder carries the spec faithfully; making it inject a subcommand
    would repair one malformed catalog entry by making every other one
    unreadable from its argv, and would break FR-5.3's promise that the
    template is the command.
    """
    tier1, catalog = shipped
    spec = catalog.flat_spec_of("docker.compose_ps")
    assert spec is not None and spec["argv"][0] == "compose"

    spec["argv"] = spec["argv"][1:]
    tool = parse_tool_spec(spec, tier1)
    argv = build_argv(tool, VALUES, tier1.toolkit("docker"))

    assert argv[:3] == ["/usr/bin/docker", "-p", "jellyfin"]
    assert "compose" not in argv
