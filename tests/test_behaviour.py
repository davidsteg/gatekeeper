"""Positivtests: was funktionieren muss.

Der Negativkorpus zeigt, dass die Grenzen halten. Hier geht es darum, dass
gatekeeper innerhalb der Grenzen auch tatsaechlich etwas ausrichtet -- eine
Absicherung, die alles ablehnt, waere trivial und nutzlos.
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


def test_derived_path_resolves(catalog, sandbox):
    tool = catalog.get("demo.show")
    values = resolve_parameters(tool, {"stack": "media-jellyfin"})
    assert values["compose_path"] == os.path.realpath(
        str(sandbox / "media-jellyfin" / "compose.yaml")
    )
    assert resolve_scopes(tool, values) == ["stack:media-jellyfin"]


def test_input_schema_hides_derived_parameters(catalog):
    """Der Agent sieht nur, was er setzen darf."""
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
    # Wahrheitswerte sind in Python Ganzzahlen - hier duerfen sie es nicht sein.
    with pytest.raises(Denied):
        resolve_parameters(tool, {"n": True})


# -- Ausfuehrung -----------------------------------------------------------


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
    """FR-6.9: der wichtigste Unterschied im Ausfuehrungspfad.

    Ein als Fehler gemeldetes Zeitlimit provoziert die Wiederholung, die bei
    einem bereits durchgelaufenen Schreibzugriff das Duplikat erzeugt.
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
    """Der Wert bleibt ein Wert -- es gibt keinen Interpreter."""
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
            [str(tmp_path / "gibt-es-nicht")],
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
    # Der Agent bekam eine nichtssagende Antwort - das Log kennt den Grund.
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


# -- Auslieferungszustand und Beispiele ------------------------------------


def test_nothing_active_is_shipped():
    """gatekeeper bringt keine Konfiguration mit -- nur Beispiele.

    Eine mitgelieferte `tools.yaml` waere eine Faehigkeit, die niemand
    entschieden hat: nach der Installation stuenden Tools bereit, die im
    Audit-Log keinen Urheber haben. Der Auslieferungszustand ist deshalb leer.
    """
    config = os.path.join(os.path.dirname(__file__), "..", "config")
    present = sorted(
        name for name in os.listdir(config) if name.endswith((".yaml", ".yml"))
    )
    assert present == [], f"aktive Konfiguration im Repo: {present}"
    assert os.path.isdir(os.path.join(config, "examples"))


def test_missing_catalog_is_an_empty_catalog(tier1, tmp_path):
    """Der Normalzustand nach `init`, kein Fehlerfall."""
    catalog = load_catalog(str(tmp_path / "gibt-es-nicht.yaml"), tier1)
    assert catalog.tools == {}
    assert catalog.raw == []


def test_empty_catalog_file_loads(tier1, tmp_path):
    path = tmp_path / "leer.yaml"
    path.write_text("tools: []\n", encoding="utf-8")
    assert load_catalog(str(path), tier1).tools == {}
    # Auch der Fall, in dem der Schluessel ohne Inhalt dasteht.
    path.write_text("tools:\n", encoding="utf-8")
    assert load_catalog(str(path), tier1).tools == {}


def test_missing_tier1_names_the_way_out(tmp_path):
    """Ebene 1 hat keinen Leerzustand -- die Meldung muss weiterhelfen."""
    from gatekeeper.errors import ConfigError

    with pytest.raises(ConfigError) as exc:
        load_tier1(str(tmp_path / "fehlt.yaml"))
    assert "gatekeeper init" in str(exc.value)


def test_shipped_config_is_valid(repo_config_dir):
    """Die Beispiele muessen streng laden -- inklusive Ebene-1-Pruefung.

    Sie sind das, wovon jemand abschreibt. Ein Tippfehler darin faellt sonst
    erst auf einem fremden Host auf.
    """
    tier1 = load_tier1(os.path.join(repo_config_dir, "toolkits.yaml"))
    catalog = load_catalog(
        os.path.join(repo_config_dir, "tools.yaml"), tier1, strict=True
    )
    assert "docker.compose_up" in catalog.tools
    assert "diag.uptime" in catalog.tools
    assert catalog.disabled_by_tier1 == []

    # Alle Docker-Tools muessen einen Stack-Scope beanspruchen, sonst greift
    # weder das Rechteprofil noch die Sperrliste aus FR-4.12.
    for tool in catalog.tools.values():
        if tool.toolkit == "docker":
            assert tool.required_scopes == ("stack:{stack}",), tool.id


def test_shipped_docker_toolkit_protects_itself(repo_config_dir):
    tier1 = load_tier1(os.path.join(repo_config_dir, "toolkits.yaml"))
    docker = tier1.toolkit("docker")
    for critical in ("gatekeeper", "dockhand", "ix-dockhand"):
        assert docker.is_protected(critical)


def test_shipped_docker_toolkit_blocks_volume_removal(repo_config_dir):
    """'compose down -v' loescht Volumes - kein Tool braucht das."""
    tier1 = load_tier1(os.path.join(repo_config_dir, "toolkits.yaml"))
    docker = tier1.toolkit("docker")
    for flag in ("-v", "--volumes", "--rmi", "rm", "prune"):
        assert docker.check_args(["compose", flag]) == flag


async def test_local_executor_probe_does_not_execute(service):
    """NFR-9: `local` wird ueber Dateirechte geprueft, nicht durch Ausfuehrung.

    Regression: die erste Fassung startete das erste Binary des Toolkits ohne
    Argumente. Bei einem Interpreter wartet das auf Eingabe, und /health/ready
    meldete dauerhaft 'degraded'.
    """
    ready = await service.probe_executors()
    assert ready == {"local": True}


# -- init ------------------------------------------------------------------


def _run_init(tmp_path, *extra):
    """Ruft das CLI wie ein Mensch auf -- inklusive Argument-Parsing."""
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


def test_init_creates_a_runnable_but_empty_state(tmp_path):
    """Nach `init` startet der Server -- und kann nichts.

    Genau das ist gewollt. gatekeeper trifft keine Annahme darueber, welche
    Binaries ein Agent erreichen koennen soll: das weiss nur, wer das System
    kennt. Ein mitgeliefertes Toolkit waere eine Faehigkeit, die niemand
    entschieden hat.
    """
    code, out, _ = _run_init(tmp_path)
    assert code == 0

    tier1 = load_tier1(str(tmp_path / "toolkits.yaml"))
    catalog = load_catalog(str(tmp_path / "tools.yaml"), tier1, strict=True)
    identities = load_identities(str(tmp_path / "identities.yaml"))

    assert tier1.toolkits == {}, "Ebene 1 darf nichts vorgeben"
    assert catalog.tools == {}, "der Auslieferungszustand darf kein Tool kennen"
    assert list(identities.identities) == ["admin"]
    assert identities.identities["admin"].role == "admin"
    assert identities.identities["admin"].tools == frozenset()

    # Betriebsparameter darf init setzen -- sie erlauben nichts, sie begrenzen.
    assert tier1.rate_limits["read"].count > 0
    assert tier1.audit_dir

    token = out.split("shown once):")[1].strip()
    assert identities.authenticate(token).id == "admin"


def test_empty_tier1_is_valid(tmp_path):
    """Ebene 1 ohne Toolkits ist eine gueltige Aussage: nichts ist moeglich."""
    path = tmp_path / "toolkits.yaml"
    for body in ("toolkits: {}\n", "toolkits:\n"):
        path.write_text(body + "audit:\n  dir: /tmp/x\n", encoding="utf-8")
        assert load_tier1(str(path)).toolkits == {}


def test_tool_for_a_removed_toolkit_is_disabled_not_fatal(tmp_path, tier1, tool_specs):
    """FR-4.7: verschwindet ein Toolkit, faellt sein Tool weg -- nicht der Start.

    Sonst waere das Entfernen eines Toolkits ein Weg, den Dienst lahmzulegen:
    der naechste Start braeche ab, und zwar bevor jemand die Oberflaeche
    erreichen koennte, um den Katalog zu reparieren.
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


def test_init_token_appears_once_and_only_as_hash_on_disk(tmp_path):
    _, out, _ = _run_init(tmp_path)
    token = out.split("shown once):")[1].strip()
    assert token.startswith("gk_")
    assert out.count(token) == 1
    assert token not in (tmp_path / "identities.yaml").read_text(encoding="utf-8")


def test_example_compose_ps_asks_for_json(repo_config_dir):
    """`docker compose ps` soll strukturiert antworten, nicht als Textabelle.

    Ein Agent, der Spalten abzaehlt, verliest sich beim ersten langen
    Containernamen. '--format json' steht fest im Template und ist damit kein
    Einfallstor -- ein Parameterwert kann es nicht erzeugen (FR-5.4).
    """
    tier1 = load_tier1(os.path.join(repo_config_dir, "toolkits.yaml"))
    catalog = load_catalog(os.path.join(repo_config_dir, "tools.yaml"), tier1, strict=True)
    argv = catalog.tools["docker.compose_ps"].argv
    assert argv[-2:] == ("--format", "json")

    # Das Format darf nicht aus einem Parameter kommen -- sonst koennte ein
    # Agent es umlenken.
    assert "{" not in "".join(argv[-2:])


def test_directory_instead_of_file_says_what_happened(tmp_path):
    """Die Docker-Falle: gemountete Datei fehlt auf dem Host -> Verzeichnis.

    Ohne eigene Behandlung schlaegt das als roher IsADirectoryError durch --
    eine Meldung ueber eine Datei, die scheinbar vorhanden ist. Die Ursache
    liegt aber im Mount, und genau das muss dastehen.
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
    """Ebene 1 und Ebene 2 duerfen in getrennten Mounts liegen."""
    from gatekeeper.__main__ import _config_path

    monkeypatch.setenv("GATEKEEPER_CONFIG_DIR", str(tmp_path / "conf"))
    monkeypatch.setenv("GATEKEEPER_STATE_DIR", str(tmp_path / "state"))
    assert _config_path("toolkits.yaml", None).startswith(str(tmp_path / "conf"))
    assert _config_path("tools.yaml", None).startswith(str(tmp_path / "state"))
    assert _config_path("identities.yaml", None).startswith(str(tmp_path / "state"))

    # Ohne STATE_DIR liegt alles beisammen -- ein Mount genuegt.
    monkeypatch.delenv("GATEKEEPER_STATE_DIR")
    assert _config_path("tools.yaml", None).startswith(str(tmp_path / "conf"))


# -- Erststart -------------------------------------------------------------


def test_first_start_creates_everything_from_an_empty_directory(tmp_path):
    """Ordner mounten, starten -- mehr soll es nicht brauchen."""
    from gatekeeper.__main__ import _bootstrap_on_first_start

    empty = tmp_path / "config"
    empty.mkdir()
    _bootstrap_on_first_start(str(empty), str(empty))

    tier1 = load_tier1(str(empty / "toolkits.yaml"))
    identities = load_identities(str(empty / "identities.yaml"))
    assert tier1.toolkits == {}
    assert load_catalog(str(empty / "tools.yaml"), tier1).tools == {}
    assert [i.role for i in identities.identities.values()] == ["admin"]


def test_first_start_does_not_touch_a_partial_configuration(tmp_path):
    """Der wichtige Fall: liegt schon etwas da, wird nichts angelegt.

    Ein verrutschter Mount sieht sonst aus wie eine Erstinstallation. Eine
    frische Konfiguration darueberzulegen wuerde den Fehler verdecken und den
    Eindruck erwecken, der Katalog sei verschwunden -- mitsamt neuem
    Administrator-Token, das niemand angefordert hat.
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
    token = bootstrap(str(directory), str(directory))
    before = (directory / "identities.yaml").read_text(encoding="utf-8")

    _bootstrap_on_first_start(str(directory), str(directory))

    assert (directory / "identities.yaml").read_text(encoding="utf-8") == before
    assert load_identities(str(directory / "identities.yaml")).authenticate(token)
