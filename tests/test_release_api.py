"""`GET /release` -- the release notes for readers with no browser.

The console popup has covered this since 0.16.x; an agent, a deploy script
or `curl` could not reach the same text at all, and `serverInfo` on
`/admin/mcp` reported a hardcoded `0.1.0`. These tests hold the route to
what makes it useful: a token is required, the selection parameters
actually select, and a build without RELEASE.md says so with a status code
instead of pretending the endpoint does not exist.
"""

from __future__ import annotations

import httpx2
import pytest

import gatekeeper
from gatekeeper import release_notes
from gatekeeper.audit import AuditLog
from gatekeeper.server import build_app
from gatekeeper.service import Service

BASE = "http://gatekeeper.test"


@pytest.fixture
def app(tier1, catalog, identities, tmp_path):
    store, _tokens = identities
    audit = AuditLog(str(tmp_path / "logs-release"))
    service = Service(tier1=tier1, catalog=catalog, audit=audit)
    return build_app(service=service, identities=store, audit=audit)


def _client(app, token: str | None) -> httpx2.AsyncClient:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url=BASE, headers=headers, timeout=30.0
    )


async def test_release_requires_a_token(app):
    """Not in PUBLIC_PATHS: the notes are a version inventory of the very

    build answering the request, including which release fixed what.
    """
    async with _client(app, None) as http:
        assert (await http.get("/release")).status_code == 401


async def test_release_returns_versions_newest_first(app, identities):
    _store, tokens = identities
    async with _client(app, tokens["full"]) as http:
        response = await http.get("/release")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == gatekeeper.__version__
    assert body["releases"], "RELEASE.md should yield at least one section"
    assert body["releases"][0]["version"] == gatekeeper.__version__
    assert body["total"] >= body["count"]


async def test_version_selects_one_section_and_unknown_is_404(app, identities):
    _store, tokens = identities
    async with _client(app, tokens["full"]) as http:
        response = await http.get("/release", params={"version": gatekeeper.__version__})
        missing = await http.get("/release", params={"version": "99.99.99"})
    assert [r["version"] for r in response.json()["releases"]] == [gatekeeper.__version__]
    assert missing.status_code == 404


async def test_search_filters_and_reports_the_pre_limit_total(app, identities):
    """The question this exists for: what did any release ever change about

    credentials. `total` must count the matches, not the returned slice --
    otherwise a limited answer reads like a complete one.
    """
    _store, tokens = identities
    async with _client(app, tokens["full"]) as http:
        response = await http.get("/release", params={"search": "credential", "limit": 2})
    body = response.json()
    assert body["count"] == 2
    assert body["total"] > 2
    assert all("credential" in r["notes"].lower() or "credential" in r["version"] for r in body["releases"])


async def test_search_is_case_insensitive(app, identities):
    _store, tokens = identities
    async with _client(app, tokens["full"]) as http:
        lower = await http.get("/release", params={"search": "credential"})
        upper = await http.get("/release", params={"search": "CREDENTIAL"})
    assert lower.json()["total"] == upper.json()["total"]


async def test_a_bad_limit_is_refused_not_silently_defaulted(app, identities):
    _store, tokens = identities
    async with _client(app, tokens["full"]) as http:
        assert (await http.get("/release", params={"limit": "abc"})).status_code == 400
        assert (await http.get("/release", params={"limit": "0"})).status_code == 400


async def test_markdown_format_returns_text_with_headings(app, identities):
    _store, tokens = identities
    async with _client(app, tokens["full"]) as http:
        response = await http.get(
            "/release", params={"format": "markdown", "limit": 1}
        )
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.text.startswith(f"## {gatekeeper.__version__}")


async def test_full_returns_the_whole_file_including_the_preamble(app, identities):
    """`full` is what an agent managing this deployment needs: the release

    rule and the procedure are preamble and belong to no version's notes.
    """
    _store, tokens = identities
    async with _client(app, tokens["full"]) as http:
        response = await http.get("/release", params={"full": "1"})
        as_text = await http.get("/release", params={"full": "1", "format": "markdown"})
    markdown = response.json()["markdown"]
    assert "## Procedure" in markdown
    assert "# Releases" in markdown
    assert as_text.text == markdown


async def test_missing_release_md_is_503_with_a_reason(app, identities, monkeypatch):
    """503, not 404 -- the route exists, the file does not. A 404 would send

    the caller looking for an API version that has the endpoint.
    """
    _store, tokens = identities
    monkeypatch.setattr(release_notes, "_cache", None)
    monkeypatch.setattr(release_notes, "notes_path", lambda: None)
    async with _client(app, tokens["full"]) as http:
        response = await http.get("/release")
        full = await http.get("/release", params={"full": "1"})
    monkeypatch.setattr(release_notes, "_cache", None)
    assert response.status_code == 503
    assert "RELEASE.md" in response.json()["error"]
    assert full.status_code == 503
