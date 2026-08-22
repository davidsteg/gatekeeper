"""The vendored Cytoscape.js bundle is exactly what was vendored.

`_vendor_cytoscape.py` is the one file in `src/` nobody has read line by
line, so the guarantees available for it are mechanical ones: it is pinned
to a version, and its bytes hash to a recorded value. This re-checks the
hash on every run, which catches the two ways that could quietly stop
being true -- an accidental edit to a 435 KB line nobody would notice in a
diff, and an upgrade that forgot to update the recorded hash.

It also catches something subtler: the bundle is embedded as a Python raw
string, and minified JS is full of backslashes. If that embedding ever
loses or mangles a character, the hash moves and this fails, rather than
the console shipping a subtly corrupt library.
"""

from __future__ import annotations

import hashlib

from gatekeeper._vendor_cytoscape import (
    CYTOSCAPE_JS,
    CYTOSCAPE_SHA256,
    CYTOSCAPE_VERSION,
)


def test_bundle_matches_its_pinned_hash():
    actual = hashlib.sha256(CYTOSCAPE_JS.encode("utf-8")).hexdigest()
    assert actual == CYTOSCAPE_SHA256, (
        "Vendored Cytoscape.js does not match its recorded SHA-256. If this "
        "was a deliberate upgrade, update CYTOSCAPE_VERSION and "
        "CYTOSCAPE_SHA256 in _vendor_cytoscape.py in the same commit."
    )


def test_bundle_is_the_pinned_version():
    """The version in the path is the version in the file.

    `CYTOSCAPE_JS_PATH` puts the version in the URL so an upgrade replaces
    the immutable cache entry instead of being shadowed by it. That only
    works if the constant and the bundle actually agree.
    """
    assert CYTOSCAPE_VERSION == "3.34.1"
    assert f'version="{CYTOSCAPE_VERSION}"' in CYTOSCAPE_JS


def test_bundle_is_self_contained():
    """No network fetches from inside the library.

    The console's CSP names no external host, so a library that tried to
    pull a worker or a stylesheet from a CDN at runtime would half-work in
    a way that is easy to miss. Cytoscape does not, and this pins that.
    """
    assert "//unpkg.com" not in CYTOSCAPE_JS
    assert "//cdn." not in CYTOSCAPE_JS
    assert "cdnjs.cloudflare.com" not in CYTOSCAPE_JS
