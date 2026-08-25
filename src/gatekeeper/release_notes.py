"""Where RELEASE.md is and how it splits into versions (one copy, two readers).

`ui.py` renders these sections into the console's release-notes popup;
`server.py` serves them over `/release` for anyone who cannot open a
browser -- an agent, a deploy script, an operator with `curl`. Both need
the same two answers ("which file?" and "where does one version end?"),
and the second one is a format contract with RELEASE.md's own procedure
section, not an implementation detail either surface owns.

Deliberately markdown in, markdown out: the API must not ship the
console's HTML, and the console must not re-parse what the API returns.
Rendering stays in `ui.py`, which is the only module allowed to produce
HTML at all.
"""

from __future__ import annotations

import os
import re

#: Only headings that look like a version (`## 0.4.0`, optionally with a
#: build/pre-release suffix) start a new entry -- RELEASE.md's own
#: explanatory prose has `## Procedure` and `## Versioning` headings above
#: the version list, and those must stay preamble, not become fake
#: "releases" with no notes.
HEADING_RE = r"(?m)^## (\d+\.\d+\.\d+\S*)[ \t]*\n"

#: Cached per worker process: the file is small, read-only at runtime, and
#: rereading it per request would be wasteful for something that never
#: changes without a redeploy anyway (RELEASE.md ships baked into the image).
_cache: list[tuple[str, str]] | None = None


def notes_path() -> str | None:
    """Where RELEASE.md lives, checked in order:

    1. `GATEKEEPER_RELEASE_NOTES` -- what the container image sets
       (`/usr/share/gatekeeper/RELEASE.md`, baked in at build time, since
       RELEASE.md is not part of the installed Python package).
    2. Walking up from this file -- a dev checkout or an editable install
       has the real `RELEASE.md` sitting next to `pyproject.toml`, the same
       trick `__init__.py`'s version lookup uses and for the same reason:
       always current, nothing to keep in sync by hand.

    Returns `None` if neither exists -- callers say so plainly (the popup
    renders a note, `/release` answers 503) instead of failing.
    """
    override = os.environ.get("GATEKEEPER_RELEASE_NOTES")
    if override and os.path.isfile(override):
        return override
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        candidate = os.path.join(here, "RELEASE.md")
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    return None


def parse_sections(text: str) -> list[tuple[str, str]]:
    """Splits on `## <version>` headings -- the exact format RELEASE.md's

    own procedure section mandates, and what the release workflow's CI
    check parses too. One format, read by both. Bodies come back as the
    raw markdown between two headings.
    """
    pieces = re.split(HEADING_RE, text)
    sections = []
    # pieces[0] is the preamble before the first version heading; after
    # that, version/body pairs alternate. A duplicate version heading
    # (has happened once in this file's history) is kept as its own
    # entry rather than silently merged -- the list is never deduplicated.
    for i in range(1, len(pieces), 2):
        version = pieces[i]
        body = pieces[i + 1] if i + 1 < len(pieces) else ""
        sections.append((version, body.strip()))
    return sections


def load() -> list[tuple[str, str]]:
    """All sections, newest first (RELEASE.md's own order), as markdown."""
    global _cache
    if _cache is not None:
        return _cache
    path = notes_path()
    text = ""
    if path is not None:
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        except OSError:
            text = ""
    _cache = parse_sections(text)
    return _cache


def read_full() -> str:
    """The whole file verbatim, preamble included -- empty if there is none.

    The version-by-version view drops the preamble (the release rule, the
    procedure, the versioning scheme), and that preamble is precisely what
    an agent asked to *manage* this deployment needs in order to propose a
    release correctly. So the full text stays reachable, unparsed.
    """
    path = notes_path()
    if path is None:
        return ""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""


def query(
    *,
    version: str | None = None,
    search: str | None = None,
    limit: int | None = None,
) -> tuple[list[dict[str, str]], int]:
    """Sections as `{"version", "notes"}` dicts plus the pre-limit total.

    `version` selects one exact heading, `search` keeps sections whose
    heading or body contains the term (case-insensitive -- "credential"
    across 100+ releases is the question this exists for), `limit` cuts the
    list to the newest N. Filters compose; the total reports how many
    matched before `limit`, so a caller can tell "that is all of them" from
    "there is more behind this".
    """
    sections = load()
    if version:
        sections = [(v, body) for v, body in sections if v == version]
    if search:
        needle = search.lower()
        sections = [
            (v, body)
            for v, body in sections
            if needle in v.lower() or needle in body.lower()
        ]
    total = len(sections)
    if limit is not None and limit >= 0:
        sections = sections[:limit]
    return [{"version": v, "notes": body} for v, body in sections], total
