"""Toolkit network targets by hostname (`allowed_hosts`, 1.10.0).

An http toolkit may name exact hostnames instead of (or next to) IP
ranges. What has to hold, and what each test below pins:

- an allowed name connects, to the address resolved *once* and checked,
  with the real hostname kept for `Host` and TLS (no second lookup, so no
  DNS-rebinding window between check and connect);
- a name not on the list is refused before any DNS query;
- a name resolving to a private/loopback/link-local/multicast address is
  refused, IPv4 and IPv6, even when `allowed_cidrs` would cover it;
- a redirect is reported, never followed;
- a toolkit with only `allowed_cidrs` behaves exactly as before;
- each refusal lands in the audit log with its own reason, no secret;
- a change to the list goes through a toolkit_update proposal and is live
  after approval (or a SIGHUP's reload) without a restart.

DNS answers are pinned with a fake resolver and the HTTP side with
httpx's MockTransport -- the addresses involved are public ones, and no
outside network is ever contacted.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json

import httpx
import pytest
import yaml
from conftest import make_catalog

from gatekeeper import execute_http, validate
from gatekeeper.audit import AuditLog
from gatekeeper.catalog import load_catalog, parse_tool_spec
from gatekeeper.errors import ConfigError, DenialReason, Denied, Tier1Violation
from gatekeeper.execute import OUTCOME_FAILED, OUTCOME_OK
from gatekeeper.identity import Identity, generate_token, hash_token
from gatekeeper.service import Service
from gatekeeper.tier1 import load_tier1
from gatekeeper.toolkit_proposals import ToolkitProposalStore, ToolkitProposalWriteRefused

GITHUB_IP = "20.250.119.72"  # what api.github.com answered with in the report


def _write_tier1(tmp_path, body: dict, name: str = "toolkits.yaml"):
    path = tmp_path / name
    path.write_text(
        yaml.safe_dump({"toolkits": body, "audit": {"dir": str(tmp_path / "logs")}}),
        encoding="utf-8",
    )
    return path


def _github_toolkit(**extra):
    spec = {
        "executor": "http",
        "base_url": "https://api.github.com",
        "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/repos/"],
        "allowed_hosts": ["api.github.com"],
    }
    spec.update(extra)
    return spec


def _tool_spec(**overrides):
    spec = {
        "id": "github.ref_get",
        "toolkit": "github",
        "version": 1,
        "title": "Get ref",
        "description": "test",
        "category": "read",
        "enabled": True,
        "idempotent": True,
        "method": "GET",
        "path": "/repos/{name}",
        "parameters": {"name": {"type": "string", "pattern": "^[a-z]+$", "required": True}},
        "timeout_seconds": 5,
        "max_output_bytes": 65536,
    }
    spec.update(overrides)
    return spec


class FakeDNS:
    """Answers `getaddrinfo` from a table, counting every lookup.

    `answers[host]` is a list of answer sets; lookup N gets set N (the
    last one repeats) -- which is how a rebinding resolver is modelled:
    a public address on the first query, a private one afterwards.
    """

    def __init__(self, answers: dict[str, list[list[str]]]):
        self.answers = answers
        self.calls: list[str] = []

    async def __call__(self, host, port, *args, **kwargs):
        self.calls.append(host)
        sets = self.answers.get(host)
        if not sets:
            raise OSError(f"no such host {host}")
        chosen = sets[min(len(self.calls) - 1, len(sets) - 1)]
        out = []
        for addr in chosen:
            family = 10 if ":" in addr else 2
            sockaddr = (addr, port, 0, 0) if family == 10 else (addr, port)
            out.append((family, 1, 6, "", sockaddr))
        return out


@pytest.fixture
def dns(monkeypatch):
    def install(answers):
        fake = FakeDNS(answers)
        monkeypatch.setattr(asyncio.get_event_loop(), "getaddrinfo", fake)
        return fake
    return install


@pytest.fixture
def transport(monkeypatch):
    """Routes every httpx.AsyncClient in the executor through a recorder."""
    seen: list[httpx.Request] = []
    responder = {"fn": lambda request: httpx.Response(200, json={"ok": True})}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return responder["fn"](request)

    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.pop("verify", None)
        return real_client(*args, transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(execute_http.httpx, "AsyncClient", factory)
    return seen, responder


async def _run(tk, tier1, **tool_overrides):
    tool = parse_tool_spec(_tool_spec(**tool_overrides), tier1)
    method, path, query, body = validate.build_http_request(tool, {"name": "gatekeeper"}, tk)
    return await execute_http.run(
        method=method, path=path, query=query, body=body, toolkit=tk,
        credentials=None, timeout_seconds=5, max_output_bytes=65536, idempotent=True,
    )


# -- Connect-time behaviour ------------------------------------------------------


async def test_allowed_hostname_connects_to_the_checked_address(tmp_path, dns, transport):
    tier1 = load_tier1(str(_write_tier1(tmp_path, {"github": _github_toolkit()})))
    fake = dns({"api.github.com": [[GITHUB_IP]]})
    seen, _ = transport

    result = await _run(tier1.toolkit("github"), tier1)

    assert result.outcome == OUTCOME_OK, result.stderr
    assert fake.calls == ["api.github.com"]
    [request] = seen
    # The socket goes to the IP that was checked; the name stays in Host
    # and SNI, so TLS still verifies api.github.com's certificate.
    assert request.url.host == GITHUB_IP
    assert request.headers["host"] == "api.github.com"
    assert request.extensions["sni_hostname"] == "api.github.com"


async def test_hostname_not_in_allowed_hosts_is_refused_before_dns(tmp_path, dns, transport):
    tier1 = load_tier1(str(_write_tier1(tmp_path, {"github": _github_toolkit()})))
    fake = dns({"evil.example.com": [["93.184.216.34"]]})
    seen, _ = transport
    toolkit = dataclasses.replace(tier1.toolkit("github"), base_url="https://evil.example.com")

    result = await _run(toolkit, tier1)

    assert result.outcome == OUTCOME_FAILED
    assert result.denial_reason == DenialReason.HOST_NOT_ALLOWED.value
    assert "evil.example.com" in result.stderr
    assert fake.calls == []
    assert seen == []


@pytest.mark.parametrize(
    "private",
    [
        "10.0.0.1", "192.168.1.10", "172.16.0.1", "127.0.0.1", "169.254.169.254",
        "100.64.0.1", "224.0.0.1", "0.0.0.0",
        "::1", "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
    ],
)
async def test_hostname_resolving_to_non_public_address_is_blocked(
    tmp_path, dns, transport, private
):
    tier1 = load_tier1(str(_write_tier1(tmp_path, {"github": _github_toolkit()})))
    dns({"api.github.com": [[private]]})
    seen, _ = transport

    result = await _run(tier1.toolkit("github"), tier1)

    assert result.outcome == OUTCOME_FAILED
    assert result.denial_reason == DenialReason.ADDRESS_NOT_PUBLIC.value
    assert seen == []


async def test_one_private_address_in_the_answer_blocks_the_call(tmp_path, dns, transport):
    """Fail-closed: a round-robin answer does not get to pick the permissive one."""
    tier1 = load_tier1(str(_write_tier1(tmp_path, {"github": _github_toolkit()})))
    dns({"api.github.com": [[GITHUB_IP, "127.0.0.1"]]})
    seen, _ = transport

    result = await _run(tier1.toolkit("github"), tier1)

    assert result.denial_reason == DenialReason.ADDRESS_NOT_PUBLIC.value
    assert seen == []


async def test_dns_rebinding_after_the_check_never_reaches_a_socket(tmp_path, dns, transport):
    """The resolver answers public first and loopback on every later query.

    One lookup is made, and the request goes to that checked address as an
    IP literal -- httpx never resolves the name itself, so the rebinding
    answer is never used.
    """
    tier1 = load_tier1(str(_write_tier1(tmp_path, {"github": _github_toolkit()})))
    fake = dns({"api.github.com": [[GITHUB_IP], ["127.0.0.1"]]})
    seen, _ = transport

    result = await _run(tier1.toolkit("github"), tier1)

    assert result.outcome == OUTCOME_OK
    assert fake.calls == ["api.github.com"]
    assert [r.url.host for r in seen] == [GITHUB_IP]

    # And the second call re-resolves, sees the rebinding answer, refuses.
    again = await _run(tier1.toolkit("github"), tier1)
    assert again.denial_reason == DenialReason.ADDRESS_NOT_PUBLIC.value
    assert len(seen) == 1


async def test_redirect_to_a_disallowed_target_is_not_followed(tmp_path, dns, transport):
    tier1 = load_tier1(str(_write_tier1(tmp_path, {"github": _github_toolkit()})))
    dns({"api.github.com": [[GITHUB_IP]]})
    seen, responder = transport
    responder["fn"] = lambda request: httpx.Response(
        302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
    )

    result = await _run(tier1.toolkit("github"), tier1)

    assert result.outcome == OUTCOME_FAILED
    assert "not followed" in result.stderr
    assert len(seen) == 1


async def test_cidrs_narrow_a_hostname_toolkit(tmp_path, dns, transport):
    tier1 = load_tier1(str(_write_tier1(
        tmp_path, {"github": _github_toolkit(allowed_cidrs=["140.82.112.0/20"])}
    )))
    seen, _ = transport

    dns({"api.github.com": [[GITHUB_IP]]})
    outside = await _run(tier1.toolkit("github"), tier1)
    assert outside.denial_reason == DenialReason.CIDR_NOT_ALLOWED.value

    dns({"api.github.com": [["140.82.121.6"]]})
    inside = await _run(tier1.toolkit("github"), tier1)
    assert inside.outcome == OUTCOME_OK
    assert [r.url.host for r in seen] == ["140.82.121.6"]


async def test_cidrs_cannot_reopen_a_private_address_for_a_hostname(tmp_path, dns, transport):
    tier1 = load_tier1(str(_write_tier1(
        tmp_path, {"github": _github_toolkit(allowed_cidrs=["10.0.0.0/8"])}
    )))
    dns({"api.github.com": [["10.1.2.3"]]})
    seen, _ = transport

    result = await _run(tier1.toolkit("github"), tier1)

    assert result.denial_reason == DenialReason.ADDRESS_NOT_PUBLIC.value
    assert seen == []


async def test_cidr_only_toolkit_is_unchanged(tmp_path, dns, transport):
    """No allowed_hosts: any name, and a private LAN address inside the
    CIDR list still connects -- exactly the pre-1.10.0 behaviour."""
    tier1 = load_tier1(str(_write_tier1(tmp_path, {"sonarr": {
        "executor": "http",
        "base_url": "http://sonarr.lan:8989",
        "allowed_methods": ["GET"],
        "allowed_path_prefixes": ["/repos/"],
        "allowed_cidrs": ["192.168.1.42/32"],
    }})))
    toolkit = tier1.toolkit("sonarr")
    assert toolkit.allowed_hosts == ()
    seen, _ = transport

    dns({"sonarr.lan": [["192.168.1.42"]]})
    ok = await _run(toolkit, tier1, toolkit="sonarr", id="sonarr.get")
    assert ok.outcome == OUTCOME_OK
    assert seen[0].url.host == "192.168.1.42"

    dns({"sonarr.lan": [["192.168.1.43"]]})
    refused = await _run(toolkit, tier1, toolkit="sonarr", id="sonarr.get")
    assert refused.denial_reason == DenialReason.CIDR_NOT_ALLOWED.value


async def test_resolve_and_check_raises_typed_denials(tmp_path, dns):
    tier1 = load_tier1(str(_write_tier1(tmp_path, {"github": _github_toolkit()})))
    dns({"api.github.com": [["127.0.0.1"]]})
    with pytest.raises(Denied) as exc:
        await execute_http._resolve_and_check("api.github.com", 443, tier1.toolkit("github"))
    assert exc.value.reason is DenialReason.ADDRESS_NOT_PUBLIC
    # Case and a trailing root dot do not make a different host.
    dns({"API.GitHub.com.": [[GITHUB_IP]]})
    assert await execute_http._resolve_and_check(
        "API.GitHub.com.", 443, tier1.toolkit("github")
    ) == GITHUB_IP


# -- Audit -----------------------------------------------------------------------


def _identity():
    return Identity(
        id="agent", role="agent", token_hash=hash_token("unused"),
        tools=frozenset({"github.ref_get"}), scopes=(),
    )


def _audit_records(tmp_path):
    lines = (tmp_path / "audit-logs" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


@pytest.mark.parametrize(
    ("answer", "base_url", "reason"),
    [
        ("10.0.0.1", None, "address_not_public"),
        (GITHUB_IP, "https://evil.example.com", "host_not_allowed"),
    ],
)
async def test_refusal_reason_is_in_the_audit_log(
    tmp_path, dns, transport, answer, base_url, reason
):
    tier1 = load_tier1(str(_write_tier1(tmp_path, {"github": _github_toolkit()})))
    spec = _tool_spec()
    catalog = make_catalog(tmp_path, tier1, [spec])
    if base_url:
        # A toolkit pointed elsewhere by a hand edit after load: the
        # connect-time check is the authoritative one.
        tier1.toolkits["github"] = dataclasses.replace(
            tier1.toolkits["github"], base_url=base_url
        )
    dns({"api.github.com": [[answer]], "evil.example.com": [[answer]]})
    service = Service(tier1=tier1, catalog=catalog, audit=AuditLog(str(tmp_path / "audit-logs")))

    result = await service.call(_identity(), "github.ref_get", {"name": "gatekeeper"})

    assert result.outcome == OUTCOME_FAILED
    [record] = [r for r in _audit_records(tmp_path) if r.get("kind") == "call"]
    assert record["denial_reason"] == reason
    assert record["detail"]


# -- Load-time validation -------------------------------------------------------


@pytest.mark.parametrize(
    ("hosts", "message"),
    [
        (["*.github.com"], "wildcard"),
        (["api.*.com"], "wildcard"),
        (["20.250.119.72"], "IP address"),
        (["::1"], "IP address"),
        (["localhost"], "fully qualified"),
        (["bad_host.example.com"], "fully qualified"),
        (["https://api.github.com"], "fully qualified"),
    ],
)
def test_allowed_hosts_accepts_exact_names_only(tmp_path, hosts, message):
    path = _write_tier1(tmp_path, {"github": _github_toolkit(allowed_hosts=hosts)})
    with pytest.raises(ConfigError, match=message):
        load_tier1(str(path))


def test_allowed_hosts_are_normalized(tmp_path):
    tier1 = load_tier1(str(_write_tier1(
        tmp_path, {"github": _github_toolkit(allowed_hosts=["API.GitHub.com.", "api.github.com"])}
    )))
    assert tier1.toolkit("github").allowed_hosts == ("api.github.com",)


def test_base_url_outside_allowed_hosts_is_refused_at_load(tmp_path):
    path = _write_tier1(tmp_path, {"github": _github_toolkit(allowed_hosts=["uploads.github.com"])})
    with pytest.raises(ConfigError, match="not in allowed_hosts"):
        load_tier1(str(path))


def test_toolkit_needs_cidrs_or_hosts(tmp_path):
    spec = _github_toolkit()
    del spec["allowed_hosts"]
    with pytest.raises(ConfigError, match="allowed_cidrs' must not be empty"):
        load_tier1(str(_write_tier1(tmp_path, {"github": spec})))


def test_allowed_hosts_refused_on_a_non_network_executor(tmp_path):
    path = _write_tier1(tmp_path, {"box": {
        "executor": "local", "binaries": ["/bin/true"], "allowed_hosts": ["api.github.com"],
    }})
    with pytest.raises(ConfigError, match="only supported on an 'http', 'opencode' or 'kuma'"):
        load_tier1(str(path))


def test_tool_base_url_override_outside_allowed_hosts_is_disabled(tmp_path):
    tier1 = load_tier1(str(_write_tier1(tmp_path, {"github": _github_toolkit()})))
    with pytest.raises(Tier1Violation, match="allowed_hosts"):
        parse_tool_spec(_tool_spec(base_url="https://evil.example.com"), tier1)


# -- Changes through a proposal, live without a restart ------------------------


def _proposal_env(tmp_path, toolkit_spec):
    toolkits_path = _write_tier1(tmp_path, {"github": toolkit_spec})
    tools_path = tmp_path / "tools.yaml"
    tools_path.write_text(yaml.safe_dump({"tools": [_tool_spec()]}), encoding="utf-8")
    identities_path = tmp_path / "identities.yaml"
    identities_path.write_text(yaml.safe_dump({"identities": [{
        "id": "root", "role": "admin", "token_hash": hash_token(generate_token()),
        "password_hash": hash_token("x" * 20), "tools": [], "scopes": [],
    }]}), encoding="utf-8")
    tier1 = load_tier1(str(toolkits_path))
    service = Service(
        tier1=tier1, catalog=load_catalog(str(tools_path), tier1),
        audit=AuditLog(str(tmp_path / "audit-logs")),
    )
    store = ToolkitProposalStore(
        path=str(tmp_path / "toolkit_proposals.yaml"), audit=service.audit, service=service,
        toolkits_path=str(toolkits_path), tools_path=str(tools_path),
        identities_path=str(identities_path),
    )
    return store, service, toolkits_path


def _cidr_github():
    spec = _github_toolkit(allowed_cidrs=["140.82.112.0/20"])
    del spec["allowed_hosts"]
    return spec


async def test_switch_to_hostname_via_proposal_is_live_after_approval(tmp_path, dns, transport):
    store, service, toolkits_path = _proposal_env(tmp_path, _cidr_github())
    dns({"api.github.com": [[GITHUB_IP]]})

    before = await service.call(_identity(), "github.ref_get", {"name": "gatekeeper"})
    assert before.outcome == OUTCOME_FAILED  # 20.250.119.72 is in no listed range

    item = store.propose(
        name="github", kind="update", actor="hermes",
        spec={"allowed_hosts": ["api.github.com"], "allowed_cidrs": None},
    )
    # Pending changes nothing.
    assert service.tier1.toolkit("github").allowed_hosts == ()
    still = await service.call(_identity(), "github.ref_get", {"name": "gatekeeper"})
    assert still.outcome == OUTCOME_FAILED

    store.deploy(item.id, decided_by="root")

    live = service.tier1.toolkit("github")
    assert live.allowed_hosts == ("api.github.com",)
    assert live.allowed_cidrs == ()
    on_disk = yaml.safe_load(toolkits_path.read_text(encoding="utf-8"))["toolkits"]["github"]
    assert on_disk["allowed_hosts"] == ["api.github.com"]
    assert "allowed_cidrs" not in on_disk

    after = await service.call(_identity(), "github.ref_get", {"name": "gatekeeper"})
    assert after.outcome == OUTCOME_OK, after.stderr


def test_wildcard_proposal_is_refused_at_submit(tmp_path):
    store, _service, _tp = _proposal_env(tmp_path, _cidr_github())
    with pytest.raises(ToolkitProposalWriteRefused, match="wildcard"):
        store.propose(
            name="github", kind="update", actor="hermes",
            spec={"allowed_hosts": ["*.github.com"]},
        )
    assert store.list() == []


def test_network_fields_refused_on_a_non_network_toolkit(tmp_path, sandbox):
    from conftest import PYTHON
    store, _service, toolkits_path = _proposal_env(tmp_path, _cidr_github())
    raw = yaml.safe_load(toolkits_path.read_text(encoding="utf-8"))
    raw["toolkits"]["box"] = {"executor": "local", "binaries": [PYTHON]}
    toolkits_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    item = store.propose(
        name="box", kind="update", actor="hermes", spec={"allowed_cidrs": ["10.0.0.0/16"]},
    )
    with pytest.raises(ToolkitProposalWriteRefused, match="does not connect to a URL"):
        store.deploy(item.id, decided_by="root")


def test_removing_both_network_fields_is_refused_at_deploy(tmp_path):
    store, service, toolkits_path = _proposal_env(tmp_path, _cidr_github())
    before = toolkits_path.read_text(encoding="utf-8")
    item = store.propose(
        name="github", kind="update", actor="hermes", spec={"allowed_cidrs": None},
    )
    with pytest.raises(ToolkitProposalWriteRefused, match="must not be empty"):
        store.deploy(item.id, decided_by="root")
    assert toolkits_path.read_text(encoding="utf-8") == before
    assert service.tier1.toolkit("github").allowed_cidrs == ("140.82.112.0/20",)


async def test_sighup_reload_applies_a_hand_edited_toolkit(tmp_path, dns, transport):
    """What the SIGHUP handler calls (`Service.reload_config`) swaps the
    toolkits the next call uses -- no restart."""
    store, service, toolkits_path = _proposal_env(tmp_path, _cidr_github())
    dns({"api.github.com": [[GITHUB_IP]]})
    raw = yaml.safe_load(toolkits_path.read_text(encoding="utf-8"))
    raw["toolkits"]["github"] = _github_toolkit()
    toolkits_path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    error = service.reload_config(
        toolkits_path=store.toolkits_path, tools_path=store.tools_path,
        identities_path=store.identities_path,
    )

    assert error is None
    result = await service.call(_identity(), "github.ref_get", {"name": "gatekeeper"})
    assert result.outcome == OUTCOME_OK, result.stderr


def test_sighup_handler_calls_reload_config():
    """`serve` wires SIGHUP to `Service.reload_config` -- the function the
    test above shows swaps toolkits."""
    import inspect

    from gatekeeper import __main__ as cli

    source = inspect.getsource(cli)
    handler = source[source.index("def _on_sighup"):source.index("_signal.signal(_signal.SIGHUP")]
    assert "service.reload_config(" in handler
    assert "toolkits_path=" in handler
