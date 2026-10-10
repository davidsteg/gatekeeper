"""How RELEASE.md splits into versions (`gatekeeper.release_notes`).

The console's version badge and `/release` both read these sections, so
they must reflect the actual RELEASE.md shipped with this checkout, not a
static number that can drift the way `__init__.py`'s hardcoded string did.
Rendering is the console's business (`/app` renders the markdown as React
elements; the frontend tests cover that) -- here the bodies are markdown.
"""

from __future__ import annotations

from gatekeeper import release_notes
from gatekeeper.release_notes import load, notes_path, parse_sections


def test_release_notes_path_finds_the_real_file():
    path = notes_path()
    assert path is not None
    assert path.endswith("RELEASE.md")


def test_parses_versions_in_order():
    text = (
        "# Releases\n\nsome preamble\n\n"
        "## 0.2.0\n\n**Bold summary.**\n\n- item one\n- item two\n\n"
        "## 0.1.0\n\nOlder notes with `inline code`.\n"
    )
    sections = parse_sections(text)
    versions = [v for v, _ in sections]
    assert versions == ["0.2.0", "0.1.0"]


def test_bodies_stay_markdown():
    """Markdown in, markdown out: no HTML is produced on this side."""
    text = "## 1.0.0\n\n**Bold** and `code` here.\n\n- first\n- second\n"
    ((_, body),) = parse_sections(text)
    assert body == "**Bold** and `code` here.\n\n- first\n- second"
    assert "<" not in body


def test_non_version_headings_in_preamble_are_not_treated_as_releases():
    """RELEASE.md's own '## Procedure' / '## Versioning' explanatory

    headings must stay preamble, not become fake zero-note "releases".
    """
    text = (
        "# Releases\n\n"
        "## The rule: every change is a release\n\ntext\n\n"
        "## Procedure\n\ntext\n\n"
        "## Versioning\n\ntext\n\n"
        "## 0.2.0\n\nreal notes\n\n"
        "## 0.1.0\n\nolder notes\n"
    )
    sections = parse_sections(text)
    versions = [v for v, _ in sections]
    assert versions == ["0.2.0", "0.1.0"]


def test_duplicate_version_heading_is_not_silently_merged():
    text = "## 0.3.1\n\nfirst entry\n\n## 0.3.1\n\nsecond entry\n"
    sections = parse_sections(text)
    assert len(sections) == 2
    assert "first entry" in sections[0][1]
    assert "second entry" in sections[1][1]


def test_empty_text_yields_no_sections():
    assert parse_sections("") == []
    assert parse_sections("# Releases\n\njust a preamble, no headings\n") == []


def test_real_release_md_parses_and_includes_current_release():
    import gatekeeper

    sections = load()
    assert sections, "RELEASE.md should parse to at least one section"
    versions = [v for v, _ in sections]
    assert gatekeeper.__version__ in versions


def test_missing_file_yields_no_sections(monkeypatch):
    """No RELEASE.md is "nothing to show", not an exception."""
    monkeypatch.setattr(release_notes, "_cache", None)
    monkeypatch.setattr(release_notes, "notes_path", lambda: None)
    assert release_notes.load() == []
    assert release_notes.read_full() == ""
    monkeypatch.setattr(release_notes, "_cache", None)
