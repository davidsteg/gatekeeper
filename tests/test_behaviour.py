"""Positivtests: was funktionieren muss.

Der Negativkorpus zeigt, dass die Grenzen halten. Hier geht es darum, dass
gatekeeper innerhalb der Grenzen auch tatsaechlich etwas ausrichtet -- eine
Absicherung, die alles ablehnt, waere trivial und nutzlos.
"""

from __future__ import annotations

import os

import pytest

from conftest import PYTHON, make_catalog
from gatekeeper import execute
from gatekeeper.catalog import load_catalog
from gatekeeper.errors import Denied, DenialReason
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


# -- Die ausgelieferte Konfiguration ---------------------------------------


def test_shipped_config_is_valid(repo_config_dir):
    """Die Dateien im Repo muessen streng laden -- inklusive Ebene-1-Pruefung.

    Faengt Tippfehler in tools.yaml ab, bevor sie auf dem Host auffallen.
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
