"""The release-notes popup (`ui.py`'s `_release_notes_modal`).

Console UI shows a version badge; it must be a real link into a real popup
that reflects the actual RELEASE.md shipped with this checkout, not a
static number that can drift the way `__init__.py`'s hardcoded string did.
"""

from __future__ import annotations

from gatekeeper.ui import (
    _load_release_notes,
    _parse_release_notes,
    _release_notes_modal,
    _release_notes_path,
)


def test_release_notes_path_finds_the_real_file():
    path = _release_notes_path()
    assert path is not None
    assert path.endswith("RELEASE.md")


def test_parses_versions_in_order():
    text = (
        "# Releases\n\nsome preamble\n\n"
        "## 0.2.0\n\n**Bold summary.**\n\n- item one\n- item two\n\n"
        "## 0.1.0\n\nOlder notes with `inline code`.\n"
    )
    sections = _parse_release_notes(text)
    versions = [v for v, _ in sections]
    assert versions == ["0.2.0", "0.1.0"]


def test_bold_and_code_render_as_tags_not_raw_markdown():
    text = "## 1.0.0\n\n**Bold** and `code` here.\n"
    _, body = _parse_release_notes(text)[0]
    assert "<strong>Bold</strong>" in body
    assert "<code>code</code>" in body
    assert "**" not in body


def test_bullet_list_becomes_ul():
    text = "## 1.0.0\n\n- first\n- second\n"
    _, body = _parse_release_notes(text)[0]
    assert "<ul>" in body
    assert "<li>first</li>" in body
    assert "<li>second</li>" in body


def test_wrapped_multiline_bullet_stays_one_item():
    """A bullet whose text wraps onto indented continuation lines, with no

    blank line before the next bullet, must not flatten into a run-on
    paragraph or split into extra list items -- this is the exact shape
    every bullet in the real 0.4.0 RELEASE.md entry has.
    """
    text = (
        "## 1.0.0\n\n"
        "- first item that wraps\n"
        "  onto a second line\n"
        "- second item\n"
        "  also wraps here\n"
    )
    _, body = _parse_release_notes(text)[0]
    assert body.count("<li>") == 2
    assert "<li>first item that wraps onto a second line</li>" in body
    assert "<li>second item also wraps here</li>" in body


def test_html_in_notes_is_escaped_not_executed():
    text = "## 1.0.0\n\nSee <script>alert(1)</script> and a & b.\n"
    _, body = _parse_release_notes(text)[0]
    assert "<script>" not in body
    assert "&lt;script&gt;" in body


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
    sections = _parse_release_notes(text)
    versions = [v for v, _ in sections]
    assert versions == ["0.2.0", "0.1.0"]


def test_duplicate_version_heading_is_not_silently_merged():
    text = "## 0.3.1\n\nfirst entry\n\n## 0.3.1\n\nsecond entry\n"
    sections = _parse_release_notes(text)
    assert len(sections) == 2
    assert "first entry" in sections[0][1]
    assert "second entry" in sections[1][1]


def test_empty_text_yields_no_sections():
    assert _parse_release_notes("") == []
    assert _parse_release_notes("# Releases\n\njust a preamble, no headings\n") == []


def test_real_release_md_parses_and_includes_current_release():
    import gatekeeper

    sections = _load_release_notes()
    assert sections, "RELEASE.md should parse to at least one section"
    versions = [v for v, _ in sections]
    assert gatekeeper.__version__ in versions


def test_modal_renders_without_error_and_contains_anchor():
    html = _release_notes_modal()
    assert 'id="release-notes"' in html
    assert 'class="modal-box"' in html
    assert "Release notes" in html


def test_modal_falls_back_gracefully_when_file_missing(monkeypatch):
    import gatekeeper.ui as ui_module

    monkeypatch.setattr(ui_module, "_release_notes_cache", None)
    monkeypatch.setattr(ui_module, "_release_notes_path", lambda: None)
    html = ui_module._release_notes_modal()
    assert "not available" in html
    monkeypatch.setattr(ui_module, "_release_notes_cache", None)
