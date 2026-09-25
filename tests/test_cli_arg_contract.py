"""The argv-tail contract the `google` and `microsoft` executors share.

`google_args` and `microsoft_args` are the same mapping with two names
(`validate._build_cli_args` builds both), so the rules are tested once,
against both spellings:

* a *required* parameter's value becomes one argv element's worth of
  value -- the bare value for a positional, ``--flag value`` for a flag;
* an *optional* parameter the agent did not supply is left off the argv
  entirely, so the CLI's own default applies. The tool's MCP schema says
  the parameter is optional (catalog.py lists only `required: true`
  names in `input_schema`'s `required` array); denying a call that omits
  it would make the tool unusable exactly as documented;
* a *positional* with no value is a denial even when it is optional --
  dropping it would shift the next positional into its place;
* a mapping naming a parameter the tool does not declare is a denial;
* a `switch:` entry is the valueless shape: it names a boolean
  parameter, `true` emits the fixed flag exactly once, and `false` or
  "not supplied" emit nothing. Its value never reaches the argv, and a
  declaration that could not produce a safe one is a load-time error.

The last sections are a census of the shipped catalog and a run against
the two CLIs' own argparse grammars, rather than unit tests: they pin
what this contract's argv actually means to the programs that get it.
"""

from __future__ import annotations

import glob
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple

import pytest
import yaml
from conftest import PYTHON

from gatekeeper import execute_google, execute_microsoft, integrations, validate
from gatekeeper.catalog import parse_tool_spec
from gatekeeper.errors import ConfigError, Denied
from gatekeeper.tier1 import load_tier1

#: Absolute, not relative to the cwd: a census that quietly finds no
#: files is a census that quietly passes.
REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "config" / "examples"

#: The two vendored CLIs, by the executor that runs them.
CLI_SCRIPTS = {
    "google": REPO_ROOT / "src" / "gatekeeper" / "_google_api" / "google_api.py",
    "microsoft": REPO_ROOT
    / "src" / "gatekeeper" / "_microsoft_api" / "microsoft_api.py",
}

#: What argparse says when it will not take an argv. Checked alongside
#: the exit code, because a subparser's own `error()` also exits 2 and a
#: future CLI could exit differently while still refusing the argv.
ARGPARSE_REJECTIONS = (
    "usage:",
    "unrecognized arguments",
    "invalid choice",
    "the following arguments are required",
    "expected one argument",
)

#: (argv-mapping field, action field, executor) for the two providers.
CLI_FIELDS = (
    ("google_args", "google_action", "google"),
    ("microsoft_args", "microsoft_action", "microsoft"),
)


@pytest.fixture
def tier1(tmp_path):
    """One `google` and one `microsoft` toolkit, both permissive.

    The script paths are the test interpreter: nothing here runs a
    subprocess, but an absolute, existing path keeps the loader quiet.
    """
    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "toolkits": {
                    "gmail": {
                        "executor": "google",
                        "google_script": PYTHON,
                        "allowed_google_actions": ["gmail search"],
                        "credential": "google",
                        "max_timeout_seconds": 60,
                        "max_output_bytes": 131072,
                    },
                    "outlook": {
                        "executor": "microsoft",
                        "microsoft_script": PYTHON,
                        "allowed_microsoft_actions": ["mail list", "mail get"],
                        "credential": "microsoft",
                        "max_timeout_seconds": 60,
                        "max_output_bytes": 131072,
                    },
                },
                "audit": {"dir": str(tmp_path / "logs")},
            }
        ),
        encoding="utf-8",
    )
    return load_tier1(str(path))


def _outlook_list(tier1, **overrides):
    """config/examples/tools.yaml's `outlook.list_messages`, verbatim in
    the parts that matter: two flags, both optional."""
    spec = {
        "id": "outlook.list_messages",
        "toolkit": "outlook",
        "version": 1,
        "title": "List mail",
        "description": "Lists Outlook messages.",
        "category": "read",
        "idempotent": True,
        "enabled": True,
        "microsoft_action": "mail list",
        "microsoft_args": {
            "folder": {"flag": "--folder"},
            "max_results": {"flag": "--max"},
        },
        "parameters": {
            "folder": {"type": "string", "required": False,
                       "pattern": "^[A-Za-z0-9=_-]{1,200}$", "description": "f"},
            "max_results": {"type": "integer", "required": False, "minimum": 1,
                            "maximum": 100, "description": "m"},
        },
        "required_scopes": ["Mail.Read"],
        "timeout_seconds": 30,
        "max_output_bytes": 65536,
    }
    spec.update(overrides)
    return parse_tool_spec(spec, tier1)


def _gmail_search(tier1, **overrides):
    """config/examples/tools.yaml's `gmail.search`: one required
    positional, one optional flag."""
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
                      "description": "q"},
            "max_results": {"type": "integer", "required": False, "minimum": 1,
                            "maximum": 500, "description": "m"},
        },
        "required_scopes": ["gmail.readonly"],
        "timeout_seconds": 30,
        "max_output_bytes": 65536,
    }
    spec.update(overrides)
    return parse_tool_spec(spec, tier1)


# -- An optional parameter is optional at call time too ---------------------


def test_an_omitted_optional_flag_is_left_off_the_microsoft_argv(tier1):
    """`outlook.list_messages` with no arguments is the documented call
    ("Default inbox", "default 10") -- the CLI's defaults supply both."""
    tool = _outlook_list(tier1)
    tk = tier1.toolkit("outlook")

    values = validate.resolve_parameters(tool, {})
    assert validate.build_microsoft_call(tool, values, tk) == []


def test_one_supplied_optional_flag_does_not_drag_in_the_other(tier1):
    tool = _outlook_list(tier1)
    tk = tier1.toolkit("outlook")

    values = validate.resolve_parameters(tool, {"folder": "archive"})
    assert validate.build_microsoft_call(tool, values, tk) == ["--folder", "archive"]

    values = validate.resolve_parameters(tool, {"max_results": 25})
    assert validate.build_microsoft_call(tool, values, tk) == ["--max", "25"]


def test_an_omitted_optional_flag_is_left_off_the_google_argv(tier1):
    tool = _gmail_search(tier1)
    tk = tier1.toolkit("gmail")

    values = validate.resolve_parameters(tool, {"query": "is:unread"})
    assert validate.build_google_call(tool, values, tk) == ["is:unread"]


def test_the_schema_and_the_runtime_agree_about_what_is_required(tier1):
    """The property behind the two tests above: a name the input schema
    does not list as required must be omittable at call time."""
    for tool, build, toolkit_name in (
        (_outlook_list(tier1), validate.build_microsoft_call, "outlook"),
        (_gmail_search(tier1), validate.build_google_call, "gmail"),
    ):
        required = set(tool.input_schema()["required"])
        supplied = {
            name: ("x" if param.type == "string" else 1)
            for name, param in tool.agent_parameters.items()
            if name in required
        }
        values = validate.resolve_parameters(tool, supplied)
        build(tool, values, tier1.toolkit(toolkit_name))  # must not deny


# -- What is still a denial -------------------------------------------------


def test_a_required_value_that_never_arrived_is_still_a_denial(tier1):
    """Can only happen on a programming error -- `resolve_parameters`
    denies a missing required parameter first -- and then fails closed."""
    tool = _gmail_search(tier1)

    with pytest.raises(Denied) as excinfo:
        validate.build_google_call(tool, {"max_results": "5"}, tier1.toolkit("gmail"))
    assert "'query' needs a value" in excinfo.value.agent_message


def test_an_optional_positional_with_no_value_is_a_denial(tier1):
    """Skipping a positional would shift the next one into its place --
    an argv shape nobody wrote down. Denied rather than guessed."""
    tool = _gmail_search(
        tier1,
        parameters={
            "query": {"type": "string", "required": False, "pattern": "^.{1,500}$",
                      "description": "q"},
        },
        google_args={"query": {"positional": True}},
    )

    values = validate.resolve_parameters(tool, {})
    with pytest.raises(Denied):
        validate.build_google_call(tool, values, tier1.toolkit("gmail"))


def test_a_mapping_naming_an_undeclared_parameter_is_a_denial(tier1):
    """A configuration error: failed closed, not passed through as a
    stray flag with no value behind it."""
    tool = _outlook_list(
        tier1,
        microsoft_args={"folder": {"flag": "--folder"}, "typo": {"flag": "--max"}},
    )

    values = validate.resolve_parameters(tool, {"folder": "inbox"})
    with pytest.raises(Denied) as excinfo:
        validate.build_microsoft_call(tool, values, tier1.toolkit("outlook"))
    assert "'typo' needs a value" in excinfo.value.agent_message


# -- Booleans: the switch contract ------------------------------------------
#
# A boolean is not a value these CLIs take. `--raw-query` (drive search),
# `--unread` (mail list) and `--html` (both send actions) are argparse
# `store_true` options: they are present or absent, and a value after
# them is a parse error. `switch: --raw-query` is the declaration for
# that shape -- `true` emits the fixed flag exactly once, `false` and
# "not supplied" emit nothing at all. The parameter's value never
# reaches the argv, so there is no element for an agent to smuggle a
# second argument through.


def _google_switch(tier1):
    """`gmail.search` with a `--raw-query`-shaped switch declared between
    its positional and its valued flag, so ordering is under test too."""
    return _gmail_search(
        tier1,
        google_args={
            "query": {"positional": True},
            "raw_query": {"switch": "--raw-query"},
            "max_results": {"flag": "--max"},
        },
        parameters={
            "query": {"type": "string", "required": True, "pattern": "^.{1,500}$",
                      "description": "q"},
            "raw_query": {"type": "boolean", "required": False, "description": "r"},
            "max_results": {"type": "integer", "required": False, "minimum": 1,
                            "maximum": 500, "description": "m"},
        },
    )


def _microsoft_switch(tier1):
    """`outlook.list_messages` with a `--unread`-shaped switch, the same
    contract under the other spelling."""
    return _outlook_list(
        tier1,
        microsoft_args={
            "folder": {"flag": "--folder"},
            "unread": {"switch": "--unread"},
        },
        parameters={
            "folder": {"type": "string", "required": False,
                       "pattern": "^[A-Za-z0-9=_-]{1,200}$", "description": "f"},
            "unread": {"type": "boolean", "required": False, "description": "u"},
        },
    )


class SwitchCase(NamedTuple):
    """One provider's switch, and the argv it is expected to produce.

    The same contract is asserted against both providers, because
    `google_args` and `microsoft_args` are one implementation read under
    two names.
    """

    make_tool: Any      #: builds the tool from the `tier1` fixture
    build: Any          #: `validate.build_google_call` / `..._microsoft_call`
    toolkit: str
    param: str          #: the boolean parameter behind the switch
    flag: str           #: the fixed token it emits
    baseline: dict      #: the tool's other arguments, supplied every time
    on: list            #: the whole argv when the switch is `true`
    off: list           #: ... and when it is `false` or not supplied


SWITCH_CASES = (
    SwitchCase(
        _google_switch, validate.build_google_call, "gmail",
        "raw_query", "--raw-query",
        baseline={"query": "is:unread"},
        on=["is:unread", "--raw-query"],
        off=["is:unread"],
    ),
    SwitchCase(
        _microsoft_switch, validate.build_microsoft_call, "outlook",
        "unread", "--unread",
        baseline={},
        on=["--unread"],
        off=[],
    ),
)

SWITCH_IDS = ["google", "microsoft"]


@pytest.mark.parametrize("case", SWITCH_CASES, ids=SWITCH_IDS)
def test_a_true_switch_emits_its_fixed_flag_exactly_once(tier1, case):
    tool = case.make_tool(tier1)
    values = validate.resolve_parameters(tool, {**case.baseline, case.param: True})
    argv = case.build(tool, values, tier1.toolkit(case.toolkit))

    assert argv == case.on
    assert argv.count(case.flag) == 1
    # The boolean itself never becomes an argv element.
    assert "true" not in argv


@pytest.mark.parametrize("case", SWITCH_CASES, ids=SWITCH_IDS)
def test_a_false_switch_emits_nothing(tier1, case):
    tool = case.make_tool(tier1)
    values = validate.resolve_parameters(tool, {**case.baseline, case.param: False})
    argv = case.build(tool, values, tier1.toolkit(case.toolkit))

    assert argv == case.off
    assert case.flag not in argv
    assert "false" not in argv


@pytest.mark.parametrize("case", SWITCH_CASES, ids=SWITCH_IDS)
def test_an_omitted_switch_emits_nothing(tier1, case):
    """Omitted and `false` are the same argv -- which is exactly what
    `store_true`'s own default means."""
    tool = case.make_tool(tier1)
    values = validate.resolve_parameters(tool, dict(case.baseline))
    assert case.build(tool, values, tier1.toolkit(case.toolkit)) == case.off


def test_a_switch_does_not_disturb_the_value_taking_args_around_it(tier1):
    """Declaration order is argv order, and a switch occupies exactly one
    slot in it -- the positional before it and the flag after it are
    emitted unchanged."""
    tool = _google_switch(tier1)
    tk = tier1.toolkit("gmail")

    values = validate.resolve_parameters(
        tool, {"query": "is:unread", "raw_query": True, "max_results": 5}
    )
    assert validate.build_google_call(tool, values, tk) == [
        "is:unread", "--raw-query", "--max", "5",
    ]

    values = validate.resolve_parameters(
        tool, {"query": "is:unread", "raw_query": False, "max_results": 5}
    )
    assert validate.build_google_call(tool, values, tk) == ["is:unread", "--max", "5"]

    values = validate.resolve_parameters(tool, {"query": "is:unread"})
    assert validate.build_google_call(tool, values, tk) == ["is:unread"]


def test_a_switch_takes_a_boolean_and_nothing_else(tier1):
    """The smuggling question, asked at the parameter layer: a switch's
    parameter is `type: boolean`, so a string is refused before argv
    building is even reached -- an agent has no way to put its own text
    next to the flag."""
    tool = _google_switch(tier1)

    for smuggled in ("true", "--max 999", 1):
        with pytest.raises(Denied):
            validate.resolve_parameters(
                tool, {"query": "is:unread", "raw_query": smuggled}
            )


def test_a_switch_value_that_is_not_a_boolean_is_a_denial_at_build_time(tier1):
    """The same question asked one layer down, where only a programming
    error could put it: `build_*_call` fails closed rather than passing
    an unexpected value through as a second argv element."""
    tool = _google_switch(tier1)

    with pytest.raises(Denied) as excinfo:
        validate.build_google_call(
            tool, {"query": "is:unread", "raw_query": "--max 999"},
            tier1.toolkit("gmail"),
        )
    assert "raw_query" in excinfo.value.agent_message


def test_a_required_switch_that_never_arrived_is_a_denial(tier1):
    """`false` is a value; *no* value is not. A required switch whose
    parameter never resolved is the same programming error a required
    flag's is, and fails the same way."""
    tool = _gmail_search(
        tier1,
        google_args={"query": {"positional": True},
                     "raw_query": {"switch": "--raw-query"}},
        parameters={
            "query": {"type": "string", "required": True, "pattern": "^.{1,500}$",
                      "description": "q"},
            "raw_query": {"type": "boolean", "required": True, "description": "r"},
        },
    )

    with pytest.raises(Denied) as excinfo:
        validate.build_google_call(
            tool, {"query": "is:unread"}, tier1.toolkit("gmail")
        )
    assert "'raw_query' needs a value" in excinfo.value.agent_message


def test_a_boolean_mapped_to_a_flag_still_emits_its_value(tier1):
    """The pre-switch spelling, preserved: `flag:` means "takes a value"
    for every parameter type, booleans included, and still emits
    ``--flag true`` / ``--flag false``.

    That is the right argv for a CLI whose boolean option takes a value,
    and the wrong one for these two -- which is what `switch:` is for,
    and what the census below holds the shipped catalog to. Pinned so a
    change to this half is a deliberate one.
    """
    tool = _outlook_list(
        tier1,
        microsoft_args={"unread": {"flag": "--unread"}},
        parameters={
            "unread": {"type": "boolean", "required": False, "description": "u"},
        },
    )
    tk = tier1.toolkit("outlook")

    values = validate.resolve_parameters(tool, {"unread": True})
    assert validate.build_microsoft_call(tool, values, tk) == ["--unread", "true"]

    values = validate.resolve_parameters(tool, {"unread": False})
    assert validate.build_microsoft_call(tool, values, tk) == ["--unread", "false"]

    values = validate.resolve_parameters(tool, {})
    assert validate.build_microsoft_call(tool, values, tk) == []


# -- A switch declaration the loader will not take --------------------------
#
# All of these are `ConfigError` at parse time, not a denial at call
# time: a mapping that cannot produce a safe argv should never reach a
# running catalog in the first place.


def _bad_google(tier1, google_args, parameters):
    return _gmail_search(tier1, google_args=google_args, parameters=parameters)


def _bad_microsoft(tier1, microsoft_args, parameters):
    return _outlook_list(tier1, microsoft_args=microsoft_args, parameters=parameters)


BAD_BUILDERS = (
    pytest.param(_bad_google, id="google"),
    pytest.param(_bad_microsoft, id="microsoft"),
)

#: A boolean parameter, for the declarations below that need one.
_BOOL_PARAM = {"raw_query": {"type": "boolean", "required": False, "description": "r"}}


@pytest.mark.parametrize("make_bad", BAD_BUILDERS)
def test_a_switch_cannot_also_be_a_flag(tier1, make_bad):
    with pytest.raises(ConfigError, match="switch"):
        make_bad(
            tier1,
            {"raw_query": {"switch": "--raw-query", "flag": "--raw-query"}},
            dict(_BOOL_PARAM),
        )


@pytest.mark.parametrize("make_bad", BAD_BUILDERS)
def test_a_switch_cannot_be_positional(tier1, make_bad):
    """A bare `true`/`false` in a positional slot is not what any of this
    means -- and dropping it on `false` would shift the next positional."""
    with pytest.raises(ConfigError, match="switch"):
        make_bad(
            tier1,
            {"raw_query": {"switch": "--raw-query", "positional": True}},
            dict(_BOOL_PARAM),
        )


@pytest.mark.parametrize("make_bad", BAD_BUILDERS)
def test_a_switch_must_name_a_boolean_parameter(tier1, make_bad):
    """"Emit the flag when it is true" needs a parameter that has a
    `true`. A string parameter behind a switch would silently emit the
    flag for every value it accepts, including the empty one."""
    with pytest.raises(ConfigError, match="boolean"):
        make_bad(
            tier1,
            {"raw_query": {"switch": "--raw-query"}},
            {"raw_query": {"type": "string", "required": False,
                           "pattern": "^.{0,10}$", "description": "r"}},
        )


@pytest.mark.parametrize("make_bad", BAD_BUILDERS)
def test_a_switch_must_name_a_declared_parameter(tier1, make_bad):
    """A valued mapping naming an unknown parameter is caught at call
    time (it has no value to emit). A switch has nothing to miss -- it
    would emit its flag unconditionally -- so it is caught at load."""
    with pytest.raises(ConfigError, match="raw_query"):
        make_bad(tier1, {"raw_query": {"switch": "--raw-query"}}, {})


@pytest.mark.parametrize("make_bad", BAD_BUILDERS)
@pytest.mark.parametrize(
    "switch",
    [
        "",
        True,
        123,
        None,
        "raw-query",            # not an option at all
        "-",
        "--",
        "--raw-query --max 999",  # a second argument smuggled into one entry
        "--raw query",
        "--raw-query=true",     # argparse would read a value out of this
        "--{query}",            # flags are fixed, never parameterised
        "--raw\nquery",
    ],
)
def test_an_unusable_switch_name_is_rejected_at_load(tier1, make_bad, switch):
    """The flag is the whole payload of a switch entry, so its shape is
    checked where it is written down rather than trusted at runtime: one
    option-looking token, no whitespace, no `=`, no placeholder."""
    with pytest.raises(ConfigError, match="switch"):
        make_bad(tier1, {"raw_query": {"switch": switch}}, dict(_BOOL_PARAM))


@pytest.mark.parametrize("make_bad", BAD_BUILDERS)
def test_a_well_formed_switch_loads(tier1, make_bad):
    """The other side of the guard above: short and long option spellings
    both load."""
    for switch in ("--raw-query", "-r", "--raw_query", "--raw-query-2"):
        make_bad(tier1, {"raw_query": {"switch": switch}}, dict(_BOOL_PARAM))


# -- A census of the shipped catalog ---------------------------------------


def _shipped_specs():
    """Every tool spec this repo ships: the example YAML files and the
    starter tools `gatekeeper integration show` prints."""
    specs = []
    paths = sorted(glob.glob(str(EXAMPLES / "*tools*.yaml")))
    assert paths, f"no example tool files under {EXAMPLES}"
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            for spec in yaml.safe_load(handle).get("tools") or []:
                specs.append((str(Path(path).relative_to(REPO_ROOT)), spec))
    for integration in integrations.INTEGRATIONS.values():
        for spec in integration.tool_specs:
            specs.append(("integrations.py", spec))
    return specs


def _mapped_args(spec):
    for field in ("google_args", "microsoft_args"):
        for name, mapping in (spec.get(field) or {}).items():
            yield field, name, mapping


def test_every_mapped_arg_names_a_declared_parameter():
    for source, spec in _shipped_specs():
        parameters = spec.get("parameters") or {}
        for field, name, _mapping in _mapped_args(spec):
            assert name in parameters, (
                f"{source}: {spec.get('id')}.{field} maps {name!r}, which the "
                "tool does not declare as a parameter -- every call would be "
                "denied"
            )


def test_every_shipped_boolean_is_mapped_as_a_switch():
    """`flag:` on a boolean emits ``--flag true``, which neither bundled
    CLI accepts (their boolean options are `store_true`). The shipped
    catalog therefore maps a boolean as a `switch:` or not at all."""
    for source, spec in _shipped_specs():
        parameters = spec.get("parameters") or {}
        for field, name, mapping in _mapped_args(spec):
            if (parameters.get(name) or {}).get("type") != "boolean":
                continue
            assert mapping.get("switch"), (
                f"{source}: {spec.get('id')}.{field} maps the boolean {name!r} "
                "without a `switch:` -- google_api.py/microsoft_api.py take "
                "`store_true` options, which reject the `--flag true` a "
                "valued mapping would emit"
            )


def test_every_shipped_switch_names_a_boolean_parameter():
    """The converse: a switch emits its flag on `true`, so what is behind
    it has to have a `true`."""
    for source, spec in _shipped_specs():
        parameters = spec.get("parameters") or {}
        for field, name, mapping in _mapped_args(spec):
            if not mapping.get("switch"):
                continue
            assert (parameters.get(name) or {}).get("type") == "boolean", (
                f"{source}: {spec.get('id')}.{field} declares {name!r} as a "
                "switch, but the parameter is not `type: boolean`"
            )


def test_every_mapped_positional_is_required_or_derived():
    """An optional positional is a denial waiting to happen (see
    `test_an_optional_positional_with_no_value_is_a_denial`); a derived
    one is always present, because the server computes it."""
    for source, spec in _shipped_specs():
        parameters = spec.get("parameters") or {}
        for field, name, mapping in _mapped_args(spec):
            if not mapping.get("positional"):
                continue
            param = parameters.get(name) or {}
            assert param.get("required") or param.get("derived"), (
                f"{source}: {spec.get('id')}.{field} maps {name!r} as a "
                "positional, but the parameter is neither required nor derived"
            )


# -- The same argv, against the two real CLI grammars -----------------------
#
# Everything above pins what this repo *builds*; this pins what the CLIs
# make of it. Each shipped google/microsoft tool is run for real, as a
# subprocess, with only its required (and derived) parameters supplied --
# the argv shape an omitted optional flag leaves behind, which is the
# half of the contract a unit test cannot check: whether the flag exists
# in the grammar at all, and whether what stayed behind is still enough.
#
# Nothing is sent and nothing is read: HERMES_HOME points at an empty
# directory, so every run dies for want of a token file (drive.upload for
# want of the local file it would have uploaded, one step earlier) --
# after argparse has had its say, before the first HTTP request. `PATH` is
# deliberately dead too, so google_api.py cannot find a `gws` binary to
# delegate to.


@pytest.fixture
def shipped_tier1(tmp_path):
    """One toolkit per shipped google/microsoft tool, each whitelisting
    exactly the actions its own tools name -- so `parse_tool_spec` and
    `build_*_call` run the same Tier 1 checks they would in production,
    and `_action_argv` sees the real toolkit name it derives the service
    token from (`gmail`, `calendar`, `drive`, `outlook`)."""
    toolkits: dict[str, dict] = {}
    for _source, spec in _shipped_specs():
        for _field, action_field, executor in CLI_FIELDS:
            if action_field not in spec:
                continue
            allowed = f"allowed_{executor}_actions"
            entry = toolkits.setdefault(
                spec["toolkit"],
                {
                    "executor": executor,
                    f"{executor}_script": PYTHON,
                    allowed: [],
                    "credential": executor,
                    "max_timeout_seconds": 60,
                    "max_output_bytes": 131072,
                },
            )
            if spec[action_field] not in entry[allowed]:
                entry[allowed].append(spec[action_field])
            # A tool may only tighten its toolkit's path_roots, never
            # widen them (FR-4.10) -- so a toolkit carrying a tool with a
            # derived path (drive.upload) needs that root declared.
            for param in (spec.get("parameters") or {}).values():
                root = param.get("must_resolve_under")
                if root and root not in entry.setdefault("path_roots", []):
                    entry["path_roots"].append(root)

    path = tmp_path / "toolkits.yaml"
    path.write_text(
        yaml.safe_dump(
            {"toolkits": toolkits, "audit": {"dir": str(tmp_path / "logs")}}
        ),
        encoding="utf-8",
    )
    return load_tier1(str(path))


def _sample(param):
    """A value of the right *shape* for one parameter.

    Not pattern-valid on purpose: `resolve_parameters` is what checks a
    value against its allowlist and it has its own tests. What is under
    test here is the argv's shape, which no pattern influences.
    """
    if param.get("type") == "integer":
        return "1"
    if param.get("type") == "boolean":
        return "true"
    if param.get("type") == "enum":
        return str((param.get("values") or ["x"])[0])
    return "x"


def _minimal_argv(spec, tier1):
    """(executor, argv) for one shipped tool, optional arguments omitted.

    Built by the production path end to end: `parse_tool_spec` for the
    tool, `_action_argv` for the head, `build_google_call` /
    `build_microsoft_call` for the tail. `None` for a tool that is
    neither provider's.
    """
    for _field, action_field, executor in CLI_FIELDS:
        if action_field not in spec:
            continue
        toolkit = tier1.toolkit(spec["toolkit"])
        tool = parse_tool_spec(spec, tier1)
        values = {
            name: _sample(param)
            for name, param in (spec.get("parameters") or {}).items()
            if param.get("required") or param.get("derived")
        }
        if executor == "google":
            head = execute_google._action_argv(toolkit, spec[action_field])
            tail = validate.build_google_call(tool, values, toolkit)
        else:
            head = execute_microsoft._action_argv(toolkit, spec[action_field])
            tail = validate.build_microsoft_call(tool, values, toolkit)
        return executor, [sys.executable, str(CLI_SCRIPTS[executor]), *head, *tail]
    return None


def test_the_minimal_argv_of_every_shipped_cli_tool_parses(shipped_tier1, tmp_path):
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

    checked = 0
    for source, spec in _shipped_specs():
        built = _minimal_argv(spec, shipped_tier1)
        if built is None:
            continue
        _executor, argv = built
        proc = subprocess.run(
            argv, capture_output=True, text=True, env=env, timeout=60
        )
        where = f"{source}: {spec.get('id')} -> {' '.join(argv[2:])}"
        rejected = proc.returncode == 2 or any(
            marker in proc.stderr for marker in ARGPARSE_REJECTIONS
        )
        assert not rejected, (
            f"{where}\nthe CLI's grammar rejected this argv:\n"
            f"{proc.stderr.strip()}"
        )
        # Exit 1 is the action's own failure -- the missing token file,
        # or (drive.upload) the missing local file it would have
        # uploaded. Either way the argv got past argparse, which is what
        # this test is about.
        assert proc.returncode == 1, f"{where}\n{proc.stderr.strip()}"
        checked += 1

    assert checked, "no shipped google/microsoft tool was checked"


# -- A switch, against the two real argparse grammars -----------------------
#
# The unit tests above pin what this repo emits for a switch; these pin
# what the CLIs make of it, in their own parsers rather than a
# description of them. Each CLI's `main()` builds the real parser and
# dispatches through `args.func`, which `set_defaults` reads out of the
# module globals as that line runs -- so replacing the handler first
# captures the parsed namespace before a single request is made. Nothing
# is sent and no token is read.


def _load_cli(name):
    spec = importlib.util.spec_from_file_location(
        f"_cli_under_test_{name}", CLI_SCRIPTS[name]
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def google_cli():
    return _load_cli("google")


@pytest.fixture(scope="module")
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


def _shipped_spec(tool_id):
    for _source, spec in _shipped_specs():
        if spec.get("id") == tool_id:
            return spec
    raise AssertionError(f"{tool_id!r} is not in the shipped catalog")


def test_the_shipped_drive_search_switch_parses_as_store_true(
    google_cli, shipped_tier1, monkeypatch
):
    """The motivating case, end to end: `drive.search`'s `raw_query`, as
    the shipped catalog declares it, built by the production path and
    handed to google_api.py's own Drive grammar. `--raw-query` is
    `store_true` there, and this is the argv that sets it."""
    spec = _shipped_spec("drive.search")
    toolkit = shipped_tier1.toolkit(spec["toolkit"])
    tool = parse_tool_spec(spec, shipped_tier1)

    values = validate.resolve_parameters(
        tool, {"query": "name contains 'budget'", "raw_query": True}
    )
    argv = [
        *execute_google._action_argv(toolkit, spec["google_action"]),
        *validate.build_google_call(tool, values, toolkit),
    ]
    assert argv == ["drive", "search", "name contains 'budget'", "--raw-query"]

    args = _real_parse(google_cli, "drive_search", argv, monkeypatch)
    assert args.raw_query is True
    assert args.query == "name contains 'budget'"


def test_the_shipped_drive_search_without_the_switch_parses_as_false(
    google_cli, shipped_tier1, monkeypatch
):
    """`false` and "omitted" are the same argv, and the CLI reads both as
    its own `store_true` default -- a full-text search, not a raw one."""
    spec = _shipped_spec("drive.search")
    toolkit = shipped_tier1.toolkit(spec["toolkit"])
    tool = parse_tool_spec(spec, shipped_tier1)

    for supplied in ({"query": "budget"}, {"query": "budget", "raw_query": False}):
        values = validate.resolve_parameters(tool, supplied)
        argv = [
            *execute_google._action_argv(toolkit, spec["google_action"]),
            *validate.build_google_call(tool, values, toolkit),
        ]
        assert argv == ["drive", "search", "budget"]

        args = _real_parse(google_cli, "drive_search", argv, monkeypatch)
        assert args.raw_query is False


def test_a_microsoft_switch_parses_as_store_true(
    microsoft_cli, tier1, monkeypatch
):
    """The same against microsoft_api.py's `mail list --unread`, so the
    contract is checked against both real grammars and not just the one
    the shipped catalog happens to use."""
    tool = _microsoft_switch(tier1)
    toolkit = tier1.toolkit("outlook")

    values = validate.resolve_parameters(tool, {"folder": "inbox", "unread": True})
    argv = [
        *execute_microsoft._action_argv(toolkit, "mail list"),
        *validate.build_microsoft_call(tool, values, toolkit),
    ]
    assert argv == ["mail", "list", "--folder", "inbox", "--unread"]

    args = _real_parse(microsoft_cli, "mail_list", argv, monkeypatch)
    assert args.unread is True
    assert args.folder == "inbox"

    values = validate.resolve_parameters(tool, {"folder": "inbox", "unread": False})
    argv = [
        *execute_microsoft._action_argv(toolkit, "mail list"),
        *validate.build_microsoft_call(tool, values, toolkit),
    ]
    args = _real_parse(microsoft_cli, "mail_list", argv, monkeypatch)
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
    module = _load_cli(cli)
    with pytest.raises(SystemExit) as excinfo:
        _real_parse(module, handler, argv, monkeypatch)
    assert excinfo.value.code == 2
