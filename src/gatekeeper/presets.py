"""A small library of starter definitions for common homelab/SaaS services.

This is the "simplify adding tools" half of the http/truenas executor work:
once an admin has pasted a preset's `toolkit_yaml` into `toolkits.yaml` and
redeployed (Tier 1 stays a manual, deploy-time step -- FR-4.11, presets do
not and must not change that), picking one of its `tool_specs` in
`/ui/tools/presets` pre-fills the *existing* tool editor instead of a blank
textarea. The preset never bypasses `parse_tool_spec`/Tier 1 validation --
it only saves typing what would otherwise be hand-written YAML.

Logos are inline SVG, never a hotlinked image (the console's CSP is
`img-src 'self' data:`, no external requests). Most are the services' own
marks, sourced from homarr-labs/dashboard-icons under Apache License 2.0
(see `_BRAND_LOGOS` below); Tdarr has no such source available and falls
back to a plain colored-circle monogram via `_monogram()`.
"""

from __future__ import annotations

import dataclasses
from typing import Any


@dataclasses.dataclass(frozen=True, slots=True)
class Preset:
    key: str
    display_name: str
    logo_svg: str
    #: Copy-pasteable Tier 1 block for toolkits.yaml. Always contains
    #: CHANGEME placeholders for the host and allowed_cidrs -- no preset
    #: can know the admin's LAN in advance (FR-8.15: scoped narrowly per
    #: toolkit, never a blanket private range).
    toolkit_yaml: str
    #: Starter tool definitions, each a raw dict as `parse_tool_spec` /
    #: the tool editor's YAML textarea expect. Deliberately small (2-4
    #: per service): a seed to edit, not an exhaustive API binding.
    tool_specs: tuple[dict[str, Any], ...]
    credential_kind: str
    notes: str = ""


def _monogram(letters: str, color: str) -> str:
    """A flat-color circular badge with 1-3 letters -- the shared visual

    language for every preset logo, so twelve services read as one system
    instead of twelve mismatched icon styles.
    """
    size = 14 if len(letters) > 2 else 16
    return (
        '<svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" '
        'width="28" height="28" role="img" aria-hidden="true">'
        f'<circle cx="16" cy="16" r="15" fill="{color}"/>'
        f'<text x="16" y="21" text-anchor="middle" '
        f'font-family="system-ui,sans-serif" font-size="{size}" '
        'font-weight="700" fill="#fff">'
        f"{letters}</text></svg>"
    )

#: Real service marks (not schematic monograms), sourced from
#: homarr-labs/dashboard-icons (https://github.com/homarr-labs/dashboard-icons),
#: licensed Apache License 2.0 -- retained here per that license's notice
#: requirement. Each SVG's ids and CSS classes are namespaced with the
#: preset key (e.g. 'st0' -> 'radarr-st0') because the preset gallery
#: renders every logo on one page at once, and SVG ids/CSS classes are
#: global to the document, not scoped per <svg> -- unprefixed, two
#: services reusing the same gradient/clip-path id or the same generic
#: class name (several of these source files use '.st0', '.st1', ...)
#: would silently corrupt each other's colors.
_BRAND_LOGOS: dict[str, str] = {
    'sonarr': '<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><path d="M511.8 256c0 70.4-24.9 130.8-74.6 181.1-1.7 2-3.5 3.8-5.5 5.4-8.2 8-16.8 15.3-26 21.8Q341.05 512 256.3 512c-56.6 0-106.3-15.9-149.2-47.7-11.3-8-22-17.1-31.9-27.3C36.5 398.7 12.8 354 4 303.2c-1.7-9.9-2.9-20-3.4-30.2-.2-5.7-.4-11.3-.4-17 0-6 .1-11.7.4-17.1 0-.6.2-1.1.5-1.7 3.7-62.8 28.4-117 74.1-162.8C125.5 24.8 185.8 0 256.2 0c70.7 0 131 24.8 180.9 74.5q74.7 75.9 74.7 181.5" fill-rule="evenodd" clip-rule="evenodd" fill="#eee"/><path d="m459.7 100.3-52.9 52.9c-30.9 30.9-33.6 57.8-33.6 105.3 0 42.3 6.7 81.1 38.2 112.6 23 23 44.9 44.7 44.9 44.7-5.9 7.2-12.3 14.3-19.1 21.2-1.7 2-3.5 3.8-5.5 5.4-6 5.9-12.2 11.4-18.6 16.4l-41.4-41.4C334.9 380.6 305.6 377 257 377c-46.7 0-78.4 4.3-112.6 38.5-20.4 20.4-43.8 43.9-43.8 43.9-8.9-6.8-17.3-14.2-25.3-22.4-6.6-6.6-12.8-13.4-18.5-20.3 0 0 23.1-23.2 45.2-45.3 32.7-32.7 38-70.6 38-113 0-41.3-6.8-79.8-36.8-109.9C82.2 127.7 53.3 99 53.3 99c6.7-8.5 14-16.7 21.8-24.5 6.9-6.8 14-13.1 21.2-19l48 48c30.7 30.7 70 38.6 112.4 38.6 43.6 0 82.8-8.4 114.7-40.4C391 82.1 417 56.3 417 56.3c6.8 5.6 13.5 11.6 20.1 18.2 8.3 8.3 15.8 16.9 22.6 25.8" fill-rule="evenodd" clip-rule="evenodd" fill="#3a3f51"/><path d="M186 269.1c-.5-2.8-.8-5.5-.9-8.4-.1-1.6-.1-3.1-.1-4.7 0-1.7 0-3.2.1-4.7 0-.2 0-.3.1-.5 1-17.4 7.9-32.4 20.5-45.1 13.9-13.8 30.6-20.7 50.2-20.7s36.3 6.9 50.2 20.7c13.8 14 20.7 30.8 20.7 50.3s-6.9 36.2-20.7 50.2c-.5.5-1 1.1-1.5 1.5q-3.45 3.3-7.2 6-18 13.2-41.4 13.2c-23.4 0-29.4-4.4-41.3-13.2-3.1-2.2-6.1-4.7-8.9-7.6-10.8-10.6-17.3-22.9-19.8-37" fill-rule="evenodd" clip-rule="evenodd" fill="#0cf"/><path d="m372.7 141-35.4 34.6M72.9 76.8l96.5 96.1m199.7 198.9 65.6 67.9m4.4-363.3L372.7 141M76.6 438.5l64.6-64.7" fill="none" stroke="#0cf" stroke-width="2" stroke-miterlimit="1"/><path d="m372.7 141-40 40.6m-193.3-38.5 40.6 40.5M141 374l39.5-41.1m146.2-3.3 42.6 42.4" fill="none" stroke="#0cf" stroke-width="7" stroke-miterlimit="1"/></svg>',
    'radarr': '<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><g id="radarr-Group-Copy" transform="translate(70 21)"><path id="radarr-Shape" d="m10.3 59.8 3.9 372.4c-31.4 3.9-54.9-11.8-54.9-43.1l-3.9-309.7c0-98 90.2-121.5 145.1-82.3l278.3 160.7c39.2 27.4 47 78.4 27.4 113.7-3.9-27.4-15.7-43.1-39.2-58.8L53.4 36.2C29.9 20.6 10.3 24.5 10.3 59.8" fill="#24292e"/><path id="radarr-Shape_00000114049535938561773820000018271523940913105341_" d="M-13.2 451.8c23.5 7.8 47 3.9 66.6-7.8l321.5-188.2c19.6 27.4 15.7 54.9-7.8 70.6L96.5 483.2c-39.2 19.6-90.1 0-109.7-31.4" fill="#24292e"/><path id="radarr-Shape_00000165935924413286433040000003668002807793862576_" d="M80.9 342 273 232.3 84.8 126.4z" fill="#ffc230"/></g></svg>',
    'jellyfin': '<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><linearGradient id="jellyfin-a" x1="97.508" x2="522.069" y1="308.135" y2="63.019" gradientTransform="matrix(1 0 0 -1 0 514)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#aa5cc3"/><stop offset="1" stop-color="#00a4dc"/></linearGradient><path d="M256 196.2c-22.4 0-94.8 131.3-83.8 153.4s156.8 21.9 167.7 0-61.3-153.4-83.9-153.4" fill="url(#jellyfin-a)"/><linearGradient id="jellyfin-b" x1="94.193" x2="518.754" y1="302.394" y2="57.278" gradientTransform="matrix(1 0 0 -1 0 514)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#aa5cc3"/><stop offset="1" stop-color="#00a4dc"/></linearGradient><path d="M256 0C188.3 0-29.8 395.4 3.4 462.2s472.3 66 505.2 0S323.8 0 256 0m165.6 404.3c-21.6 43.2-309.3 43.8-331.1 0S211.7 101.4 256 101.4 443.2 361 421.6 404.3" fill="url(#jellyfin-b)"/></svg>',
    'bazarr': '<svg viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><defs><clipPath id="bazarr-a"><path d="M0 512h512V0H0z"/></clipPath></defs><g clip-path="url(#bazarr-a)" transform="matrix(.09375 0 0 -.09375 0 48.02)"><path fill="#fff" d="M506 256C506 117.93 394.07 6 256 6S6 117.93 6 256s111.93 250 250 250 250-111.93 250-250"/><path fill="none" stroke="#000" stroke-miterlimit="10" stroke-width="12" d="M506 256C506 117.93 394.07 6 256 6S6 117.93 6 256s111.93 250 250 250 250-111.93 250-250z"/><path d="M406.2 119.47a2368 2368 0 0 0-300.82 0c-25.418 1.747-50.24 24.551-53.31 50.048-6.847 60.087-6.847 120.17 0 180.26 3.07 25.496 27.892 48.3 53.31 50.048a2368 2368 0 0 0 300.82 0c25.419-1.748 50.24-24.552 53.311-50.048 6.846-60.087 6.846-120.17 0-180.26-3.071-25.497-27.893-48.3-53.311-50.048"/><path fill="#fff" d="M348.36 145.31H163.22c-5.452 0-9.914 4.461-9.914 9.913v.001c0 5.452 4.462 9.913 9.914 9.913h185.14c5.452 0 9.913-4.461 9.913-9.913v-.001c0-5.452-4.461-9.913-9.913-9.913m48.18 39.81H115.049c-5.5 0-9.999 4.5-9.999 9.999s4.499 9.999 9.999 9.999H396.54c5.5 0 9.999-4.499 9.999-9.999 0-5.499-4.499-9.999-9.999-9.999"/></g></svg>',
    'prowlarr': '<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><g id="prowlarr-g18" transform="matrix(1.33333 0 0 -1.33333 198.628 515.837)"><g id="prowlarr-g2248" transform="translate(425.097 -1123.349)scale(4.096)"><circle id="prowlarr-path2188" cx="-93.3" cy="321.8" r="45" fill-rule="evenodd" clip-rule="evenodd" fill="#ffe6d5"/><path id="prowlarr-path568" d="m-124.1 313.6 8.1 9.5 60.7.2-7.9-9.7z" fill="#83331b"/><path id="prowlarr-path570" d="M-124.1 313.6v-25.5c4.6-.2 8.1-2 8.1-4.1h47.2c-.4.5-.6 1.1-.6 1.7 0 2.2 2.7 4 6.2 4.2v23.7z" fill="#f8a37b"/><path id="prowlarr-path572" d="M-89.2 309.3c1 .5 2.5 2.1 1.6 3.7-.2.3-.3.5-.5.6h4.1c-.5-1.2-2.4-2.6-2.4-2.6s-.2-.3-1-1c-.6-.3-1.3-.6-1.8-.7m-12.1.1c-.5.2-1.2.6-1.7 1.2-.9.9-1 2.1-1 2.1l-.6 1h2.4c-.2-.1-.3-.3-.5-.6-.9-1.6.5-3.1 1.4-3.7m11.2.4c-.5.1-1.5.2-2.5.5-1.5.5-2.3 1.6-2.3 1.6s-1.6-1-3.8-1.4c-.7-.1-1.2-.2-1.5-.2 0 .7-.2 1.5-.2 1.5s-.4 1.3-1 1.7h12.6c-.6-.4-1-1.7-1-1.7s-.3-1.1-.3-2" fill="#da845d"/><path id="prowlarr-path574" d="M-100.5 311.9s.5-2.4 0-2.7-3.5 1.8-2.2 3.9c1.2 2 2.2-1.2 2.2-1.2" fill="#dee6e3"/><path id="prowlarr-path576" d="M-89.9 311.9s-.5-2.4 0-2.7 3.5 1.8 2.2 3.9c-1.2 2-2.2-1.2-2.2-1.2" fill="#dee6e3"/><path id="prowlarr-path578" d="M-107.7 332.1c.6-2.7-1.2-5.3-3.8-5.8-2.7-.6-5.3 1.2-5.8 3.8-.6 2.7 1.2 5.3 3.8 5.8 2.6.6 5.2-1.1 5.8-3.8" fill="#d4541e"/><path id="prowlarr-path580" d="M-109.6 335.1c-1.1.8-2.5 1.1-3.9.8-2.7-.6-4.4-3.2-3.8-5.8.1-.6.3-1.1.6-1.6 2.1.7 5.4 2.5 7.1 6.6" fill="#852e1b"/><path id="prowlarr-path582" d="M-109.9 331.6c.3-1.5-.6-2.9-2.1-3.3-1.5-.3-2.9.6-3.3 2.1-.3 1.5.6 2.9 2.1 3.3 1.6.4 3-.6 3.3-2.1" fill="#fff"/><path id="prowlarr-path584" d="M-76.1 333c-1.1 0-2.2.7-2.6 1.9-.5 1.4.3 3 1.7 3.4.8.3 4.6 1.8 3.5 5.4-.8 2.6-2.4 3-7 3.5-.9.1-1.7.2-2.6.3-3.3.5-5.7 1.8-7.2 4-2.2 3.2-1.3 6.9-1.2 7.3.4 1.5 1.9 2.3 3.3 2 1.5-.4 2.3-1.9 2-3.3 0 0-.4-1.7.5-2.9.6-.9 1.7-1.4 3.4-1.6l2.4-.3c4.3-.5 9.7-1 11.7-7.2 2.1-6.6-3-10.9-7-12.2-.3-.3-.6-.3-.9-.3" fill="#e2591e"/><path id="prowlarr-path588" d="m-85.8 354.5-.1.1c-1.8-1.1-4.1-1.4-5.3-1.4.2-.6.5-1.1.9-1.7.5-.7 1.1-1.3 1.8-1.9 2.4.4 4.3 2.2 5.4 3.4q-1.95.45-2.7 1.5" fill="#852e1b"/><path id="prowlarr-path590" d="M-80 347.1c2-.2 3.3-.4 4.3-.8.7 1.1 1.6 3 2 5.1-1.4.6-3 .9-4.5 1.1.1-1.5 0-3.8-1.8-5.4" fill="#852e1b"/><path id="prowlarr-path592" d="M-68 340.3c.3 1.2.3 2.6 0 4.1-.5-.4-1.2-.8-2.1-1.1-1.5-.4-2.5-.4-3.2-.3.3-1.5-.3-2.6-1.1-3.3 2.4-.9 4.8-.2 6.4.6" fill="#852e1b"/><path id="prowlarr-path594" d="M-73.3 341.8v1.2c0 .2-.1.5-.2.7.1-.2.1-.3.1-.5.2-.5.2-1 .1-1.4m-.1 1.9c-.4 1.3-1.1 2.1-2.2 2.6 1.1-.5 1.7-1.3 2.2-2.6m-6.6 3.4c-.2 0-.4 0-.5.1-.9.1-1.7.2-2.6.3h-.1.1c.9-.1 1.8-.2 2.6-.3.2-.1.4-.1.5-.1m-3.3.4" fill="#83bad2"/><path id="prowlarr-path596" d="M-68.4 339.1c-.3.2-.6.4-.9.7.5.2.9.4 1.3.6-.1-.5-.2-.9-.4-1.3m-4 4c-.4 0-.7 0-.9.1 0 .2-.1.3-.1.5-.4 1.3-1.1 2.1-2.2 2.6.2.4.5.9.8 1.5 1.4-.6 2.3-1.4 3-2.8q.45-.9.3-1.8c-.3-.1-.6-.1-.9-.1m-7.6 4c-.2 0-.4 0-.5.1-.9.1-1.7.2-2.6.3h-.1c-2.4.4-4.4 1.2-5.8 2.6l.5-.5c.3 0 .6.1.8.2 1.4-.4 3.1-.8 5.2-.9 1.4-.1 2.6-.2 3.7-.3-.3-.5-.6-1-1.2-1.5" fill="#ba4a1f"/><path id="prowlarr-path598" d="M-88.6 349.6c-.2.1-.4.3-.5.5-.2.1-.3.3-.4.4.5-.2 1.1-.5 1.8-.7-.3-.1-.6-.1-.9-.2" fill="#6f2717"/><path id="prowlarr-path600" d="M-75.6 346.3c-1 .4-2.4.6-4.3.8q.75.75 1.2 1.5c1.6-.2 2.9-.4 4-.8q-.6-.9-.9-1.5" fill="#6f2717"/><path id="prowlarr-path602" d="M-69.3 339.8c-1.2.8-2.5 1.5-4 2 .1.4.1.9 0 1.4.2 0 .5-.1.9-.1.3 0 .6 0 .9.1 0-.3-.1-.6-.1-.8 1.3-.6 2.5-1.2 3.6-2-.4-.3-.9-.5-1.3-.6" fill="#6f2717"/><path id="prowlarr-path604" d="M-69.1 344.9s-2.2 3.1-5 4.6c.1.4.2.7.3 1.1.5-.2.9-.5 1.2-.8 2.5-1.9 3.5-4.9 3.5-4.9m-9.1 6.3c-1.6.6-2.8.9-2.8.9s1.2 0 2.8-.3z" fill="#e66733"/><path id="prowlarr-path606" d="M-74.1 349.6c-.2.1-.5.2-.7.4-1.2.5-2.3.9-3.3 1.3v.6c1.4-.2 3-.6 4.3-1.2-.1-.4-.2-.8-.3-1.1" fill="#94401d"/><path id="prowlarr-path608" d="M-98.9 336.2s7.2 8.5 21.9 6.5c14.7-2.1 20.1-21.2 20.1-21.2l-6.3-7.9h-35.7z" fill="#ef5d22"/><path id="prowlarr-path610" d="M-96.6 338.3c1.6.4 4 .8 7.9.5 9.3-.6 21.3-15.5 21.3-15.5s-5.3 16.9-22.3 18.5c-3.1-1-5.4-2.4-6.9-3.5" fill="#852e1b"/><path id="prowlarr-path612" d="M-67.6 316h-2.1c-.6 1.6-3.5 9.2-8.1 13.2-3.8 3.3-9.3 7.1-16.2 7.4h1c5 0 9.3-1.8 12.7-4.1v.2c.1.7.4 1.3.8 1.9 2.8-2 5.4-4.4 7.4-6.5-.5-.5-1.1-.8-1.7-1.1 3.6-4 5.8-9.6 6.2-11m-3.1 13.9c-1.4 2.2-3.4 4.6-5.9 6.6.1 0 .1 0 .2.1h.1c.1 0 .3 0 .4.1h1.1c.2 0 .3 0 .5-.1 2.7-.6 4.4-3.2 3.8-5.8 0-.4-.1-.6-.2-.9" fill="#c74d1f"/><path id="prowlarr-path614" d="M-71.9 328.2c-2 2.1-4.6 4.5-7.4 6.5.3.4.7.8 1.1 1.1.1.1.3.2.4.3s.3.2.4.2c.1.1.3.1.4.2h.1c.1 0 .1 0 .2.1 2.6-2.1 4.5-4.5 5.9-6.6-.1-.3-.2-.5-.4-.7-.1-.5-.4-.8-.7-1.1" fill="#6f2717"/><path id="prowlarr-path616" d="M-82.2 332.8c-.6-2.7 1.2-5.3 3.8-5.8 2.7-.6 5.3 1.2 5.8 3.8.6 2.7-1.2 5.3-3.8 5.8s-5.3-1.2-5.8-3.8" fill="#d4541e"/><path id="prowlarr-path618" d="M-80.3 335.7c1.1.8 2.5 1.1 3.9.8 2.7-.6 4.4-3.2 3.8-5.8-.1-.6-.3-1.1-.6-1.6-2.2.8-5.5 2.5-7.1 6.6" fill="#852e1b"/><path id="prowlarr-path620" d="M-80.1 332.3c-.3-1.5.6-2.9 2.1-3.3 1.5-.3 2.9.6 3.3 2.1.3 1.5-.6 2.9-2.1 3.3-1.5.3-3-.6-3.3-2.1" fill="#fff"/><path id="prowlarr-path622" d="m-117.9 313.6-2.4 2.5s7.7 15.7 18.4 19.4c10.6 3.6 19-1.8 24.2-6.3s8.2-13.5 8.2-13.5l-1.9-2.1z" fill="#f46a2f"/><path id="prowlarr-path624" d="M-105.6 329.1s8.7 6.9 10.4 6.9 10-6 10-6l-1.4-1.7s-7.3 5.9-8.7 5.9-8.2-5.9-8.2-5.9z" fill="#852e1b"/><path id="prowlarr-path626" d="M-101.3 326.5s5 4.2 6.4 4.2 6.2-3.7 6.2-3.7l-1.3-2.5s-3.8 4.1-4.9 4.1-5.4-3.8-5.4-3.8z" fill="#852e1b"/><path id="prowlarr-path628" d="m-120.3 316.1 6.7 2.3s-2.2 7 4.1 10.4 9.1-.1 9.9-2.1c.9-2 .9-7.3.9-7.3h7.5s-.1 7.9 3.1 10.1 8 2.5 9.9-1.6c1.9-4.2 0-7.8 0-7.8l8.6-4.3-1.9-2.1h-46.4z" fill="#fff"/><path id="prowlarr-path630" d="M-100.5 323.3c0-1.6-1.3-3-3-3-1.6 0-3 1.3-3 3 0 1.6 1.3 3 3 3s3-1.3 3-3" fill="#fddd04"/><path id="prowlarr-path632" d="M-101.3 323.3c0-1.2-1-2.1-2.1-2.1-1.2 0-2.1 1-2.1 2.1s1 2.1 2.1 2.1 2.1-.9 2.1-2.1" fill="#391913"/><path id="prowlarr-path634" d="M-103.9 324.6c0-.5-.4-.9-.9-.9s-.9.4-.9.9.4.9.9.9.9-.4.9-.9" fill="#fff"/><path id="prowlarr-path636" d="M-83.6 323.3c0-1.6-1.3-3-3-3-1.6 0-3 1.3-3 3 0 1.6 1.3 3 3 3s3-1.3 3-3" fill="#fddd04"/><path id="prowlarr-path638" d="M-84.4 323.3c0-1.2-1-2.1-2.1-2.1-1.2 0-2.1 1-2.1 2.1s.9 2.1 2.1 2.1c1.1 0 2.1-.9 2.1-2.1" fill="#391913"/><path id="prowlarr-path640" d="M-87 324.6c0-.5-.4-.9-.9-.9s-.9.4-.9.9.4.9.9.9.9-.4.9-.9" fill="#fff"/><path id="prowlarr-path642" d="M-63.2 313.6h-6.2l1.9 2.1s0 .1-.1.3h4.4l5.8 7.1c.4-1 .5-1.6.5-1.6z" fill="#c74d1f"/><path id="prowlarr-path644" d="M-69.4 313.6h-2.1l1.9 2.1s0 .1-.1.3h2.1c.1-.2.1-.3.1-.3z" fill="#a33f1e"/><path id="prowlarr-path646" d="m-69.5 315.7-.6.3h.5c0-.2.1-.3.1-.3" fill="#de581d"/><path id="prowlarr-path648" d="M-71.5 313.6h-46.4l-2.4 2.4h50.1l.6-.3z" fill="#d5d0cd"/><path id="prowlarr-path650" d="M-99.6 320.1s-2.8-.7-3.9-3.4c-1-2.7.4-4.7 2.7-5.2 2.4-.5 5.8 1.2 5.8 1.2s2.8-2.7 6.2-2 4.5 4.5 2.8 6.9c-1.6 2.3-5.6 2.6-5.6 2.6s-6.1-1.8-8-.1" fill="#fff"/><path id="prowlarr-path652" d="M-94.9 312.7s.1-.1.4-.3v4.3c0 .2-.2.3-.3.3-.2 0-.3-.2-.3-.3v-4.1c.1 0 .2.1.2.1" fill="#a6b9b5"/><path id="prowlarr-path654" d="M-91.2 317.1s2.2 2.6.8 3.7-2.8-.8-4.6-.6-3.7 1.5-4.4.3c-.8-1.3 1.2-2.8 1.2-2.8s.5 1.3 1.6.7.2-2 .2-2 .8-.6 1.5-.7 1.8.8 1.8.8-.6 1.5.6 2.1c1.1.6 1.3-1.5 1.3-1.5" fill="#852e1b"/><path id="prowlarr-path656" d="M-113 325.1s-1.7-2.2-1.5-5.4c.1-3.2 4.8-6.1 4.8-6.1l-1.8 2.8c-.5.7-.3 1.6.4 2.2l2.8 2.3s-3.8-1.2-4.5-.3-.2 4.5-.2 4.5" fill="#852e1b"/><path id="prowlarr-path658" d="M-77.8 327s-.3-2.8-1-4.2-3.1-.8-3.1-.8 2.7-1.4 2.7-2.2c0-.9-1.8-3.6-1.8-3.6s5.9 3.7 3.2 10.8" fill="#852e1b"/><path id="prowlarr-path660" d="M-113.1 313.6s-1.2.9-1.9 2.1c-.8 1.2-1 2-1 2s-.1-1.6.4-2.7.8-1.4.8-1.4z" fill="#852e1b"/><path id="prowlarr-path662" d="M-76.9 313.6s1.1.9 2.1 2.6 1.3 3.9 1.3 3.9.5-3.2.2-4.5c-.3-1.4-.8-1.9-.8-1.9h-2.8" fill="#852e1b"/><path id="prowlarr-path664" d="M-72.5 341.4c-1.4.6-2.9 1-4.5 1.3-1.4.2-2.6.3-3.9.3 2.4-.6 7.4-2.1 11.4-5.8 5.5-5 7.6-9.6 7.6-9.6s-3.3 9.1-10.6 13.8" fill="#852e1b"/><path id="prowlarr-path666" d="M-69.1 335.3s3.6-2.8 5.7-8.3 2.1-6.9 2.1-6.9l-9 11.3 6-5.5c-.1 0-.3 3.2-4.8 9.4" fill="#852e1b"/><path id="prowlarr-path668" d="m-55.3 323.3-7.9-9.7v-22.5c.6.8 1.3 1.2 2 1.2s1.4-.4 1.9-1.1l3.9 7.1v25z" fill="#f6854f"/><path id="prowlarr-path670" d="M-71.7 304.6h3.5v3h1.6l-3.4 3.8-3.4-3.8h1.6v-3" fill="#852e1b"/><path id="prowlarr-path672" d="M-70 303.7h-3.4v-1.2h6.7v1.2z" fill="#852e1b"/><path id="prowlarr-path674" d="M-72.2 339.4c-1.7.6-4 1.2-6.5 1.3h-1c-1.4 0-2.8-.1-4.1-.1l-2.1.6c1.6.4 3.6.7 5.8.7.6 0 1.2 0 1.8-.1.8-.1 1.6-.2 2.3-.3 1.1-.6 2.5-1.3 3.8-2.1" fill="#f06c34"/><path id="prowlarr-path676" d="M-90 339.9s1.6.7 4 1.3l2.1-.6c-3.3-.3-6.1-.7-6.1-.7" fill="#94401d"/><path id="prowlarr-path678" d="M-69.5 338.2s-1 .6-2.7 1.2c-1.3.9-2.6 1.5-3.9 2.1 4.6-1 6.6-3.3 6.6-3.3" fill="#94401d"/><path id="prowlarr-path1131" d="M-93.3 368.7c-25.9 0-46.9-21-46.9-46.9s21-46.9 46.9-46.9 46.9 21 46.9 46.9-21 46.9-46.9 46.9m0-9.4c20.7 0 37.5-16.8 37.5-37.5s-16.8-37.5-37.5-37.5-37.5 16.8-37.5 37.5 16.8 37.5 37.5 37.5" fill-rule="evenodd" clip-rule="evenodd" fill="#e66001"/><path id="prowlarr-path586" d="M-85.8 354.5c-.8 1.2-.5 2.9-.5 2.9.4 1.5-.5 2.9-2 3.3s-2.9-.5-3.3-2c-.1-.4-.9-3.8 1-6.9 1.5.3 3.6.9 5.1 2.3 0 .2-.2.3-.3.4" fill="#fff"/></g></g></svg>',
    'hass': '<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><path d="M512 473.3c0 17.6-14.4 32-32 32H32c-17.6 0-32-14.4-32-32v-192c0-17.6 10.2-42.2 22.6-54.6L233.4 16c12.4-12.4 32.8-12.4 45.2 0l210.8 210.8c12.4 12.4 22.6 37 22.6 54.6z" fill="#f2f4f9"/><path d="M489.4 226.7 278.6 16c-12.4-12.4-32.8-12.4-45.2 0L22.6 226.7C10.2 239.1 0 263.7 0 281.3v192c0 17.6 14.4 32 32 32h196.8l-86.7-86.7c-4.5 1.5-9.2 2.4-14.2 2.4-24.1 0-43.7-19.6-43.7-43.7s19.6-43.7 43.7-43.7 43.7 19.6 43.7 43.7c0 5-.9 9.7-2.4 14.2l67.5 67.5V211.8c-14.5-7.1-24.5-22-24.5-39.2 0-24.1 19.6-43.7 43.7-43.7s43.7 19.6 43.7 43.7c0 17.2-10 32.1-24.5 39.2v173.4l67.1-67.1c-1.3-4.2-2-8.6-2-13.2 0-24.1 19.6-43.7 43.7-43.7s43.7 19.6 43.7 43.7-19.6 43.7-43.7 43.7c-5.3 0-10.4-1-15.1-2.8l-93.7 93.7v65.9H480c17.6 0 32-14.4 32-32v-192c0-17.6-10.2-42.2-22.6-54.7" fill="#18bcf2"/></svg>',
    'n8n': '<svg viewBox="0 121.3 512.1 269.6" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><path d="M458.1 229.1c-25.1 0-46.2-17.2-52.2-40.4h-61.8c-13.2 0-24.4 9.5-26.6 22.5l-2.2 13.3c-2 12.2-8.2 23.4-17.5 31.6 9.3 8.2 15.5 19.3 17.5 31.6l2.2 13.3c2.2 13 13.4 22.5 26.6 22.5h7.9c6-23.2 27.1-40.4 52.2-40.4 29.8 0 53.9 24.1 53.9 53.9s-24.1 53.9-53.9 53.9c-25.1 0-46.2-17.2-52.2-40.4h-7.9c-26.3 0-48.8-19-53.2-45l-2.2-13.3c-2.2-13-13.4-22.5-26.6-22.5h-21.4c-6 23.2-27.1 40.4-52.2 40.4s-46.2-17.2-52.2-40.4H106c-6 23.2-27.1 40.4-52.2 40.4C24.1 309.9 0 285.8 0 256s24.1-53.9 53.9-53.9c25.1 0 46.2 17.2 52.2 40.4h30.3c6-23.2 27.1-40.4 52.2-40.4s46.2 17.2 52.2 40.4h21.4c13.2 0 24.4-9.5 26.6-22.5l2.2-13.3c4.3-26 26.8-45 53.2-45H406c6-23.2 27.1-40.4 52.2-40.4 29.8 0 53.9 24.1 53.9 53.9s-24.2 53.9-54 53.9m0-27c14.9 0 26.9-12.1 26.9-26.9s-12.1-26.9-26.9-26.9-26.9 12.1-26.9 26.9 12 26.9 26.9 26.9M53.9 282.9c14.9 0 26.9-12.1 26.9-26.9s-12.1-26.9-26.9-26.9-27 12-27 26.9 12.1 26.9 27 26.9M215.6 256c0 14.9-12.1 26.9-26.9 26.9s-26.9-12.1-26.9-26.9 12.1-26.9 26.9-26.9 26.9 12 26.9 26.9m215.6 80.8c0 14.9-12.1 26.9-26.9 26.9-14.9 0-26.9-12.1-26.9-26.9s12.1-26.9 26.9-26.9 26.9 12.1 26.9 26.9" fill-rule="evenodd" clip-rule="evenodd" fill="#ea4b71"/></svg>',
    'uptimekuma': '<svg viewBox="0 0 622 622" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><g transform="translate(320 320)"><linearGradient id="uptimekuma-a" x1="-82.404" x2="121.666" y1="38.077" y2="-157.263" gradientTransform="matrix(1 0 0 -1 .001 -16)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#5cdd8b"/><stop offset="1" stop-color="#86e6a9"/></linearGradient><path d="M161.4-93.4c53.7 122.7 53.7 199.7 0 230.9-80.5 46.7-290.4 61-350.9-10.9-40.3-47.9-40.3-121.2 0-220 41-67.5 99.2-101.2 174.6-101.2 75.5 0 134.3 33.8 176.3 101.2z" fill="url(#uptimekuma-a)" stroke="#f2f2f2" stroke-width="200" stroke-opacity=".51"/></g></svg>',
    'immich': '<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><path d="M238.8 155.5c33.5 29.7 60.5 61.5 77.9 91.5 29.9-53.4 49.8-116.9 50.1-157.3v-.8c0-59.8-59.7-83.1-111.1-83.1S144.6 29 144.6 88.8V92c28.7 12.8 62.6 35.6 94.2 63.5" fill="#fa2921"/><path d="M55.9 318.6c21-23.3 53.1-48.6 89.4-69.9 38.6-22.7 77.2-38.6 111.1-45.8-41.6-44.9-95.8-83.5-134.1-96.2-.3-.1-.5-.2-.7-.2-57-18.7-97.6 30.9-113.5 79.8S-4.1 299.1 52.8 317.6c.8.2 1.8.6 3.1 1" fill="#ed79b5"/><path d="M503.9 185.4C488 136.6 447.4 87 390.5 105.5c-.8.3-1.8.6-3.1 1-3.3 31.2-14.4 70.5-31.2 109.1-17.9 41.1-39.8 76.6-62.9 102.4 60 11.9 126.5 11.3 165.1-1 .3-.1.5-.2.7-.2 57-18.6 60.6-82.5 44.8-131.4" fill="#ffb400"/><path d="M205 366.3c-9.7-43.7-12.8-85.3-9.3-119.8-55.5 25.7-109 65.3-133 97.8-.2.2-.3.4-.5.6-35.2 48.4-.6 102.3 41 132.5s103.5 46.4 138.7-1.9c.5-.7 1.1-1.5 1.9-2.6-15.6-27.1-29.7-65.5-38.8-106.6" fill="#1e83f7"/><path d="M448.8 341.9c-30.7 6.5-71.5 8.1-113.4 4-44.6-4.3-85.1-14.2-116.8-28.2 7.2 60.8 28.4 123.8 51.9 156.7.2.2.3.4.5.6 35.2 48.4 97.1 32.2 138.7 1.9 41.6-30.2 76.2-84.1 41-132.5-.5-.6-1.1-1.4-1.9-2.5" fill="#18c249"/></svg>',
    'telegram': '<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><linearGradient id="telegram-a" x1="256" x2="256" y1="2" y2="514" gradientTransform="matrix(1 0 0 -1 0 514)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#1d93d2"/><stop offset="1" stop-color="#38b0e3"/></linearGradient><circle cx="256" cy="256" r="256" fill="url(#telegram-a)"/><path d="m173.3 274.7 30.4 84.1s3.8 7.9 7.9 7.9 64.5-62.9 64.5-62.9l67.3-129.9-169 79.1z" fill="#c8daea"/><path d="m213.6 296.3-5.8 62s-2.4 19 16.5 0c19-19 37.2-33.6 37.2-33.6" fill="#a9c6d8"/><path d="m173.8 277.7-62.5-20.4s-7.5-3-5.1-9.9c.5-1.4 1.5-2.6 4.5-4.7C124.6 233.1 367 146 367 146s6.8-2.3 10.9-.8c2 .6 3.6 2.3 4 4.4.4 1.8.6 3.7.5 5.5 0 1.6-.2 3.1-.4 5.4-1.5 23.8-45.7 201.6-45.7 201.6s-2.6 10.4-12.1 10.8c-4.7.2-9.3-1.6-12.6-4.9-18.6-16-82.8-59.2-97-68.6-.6-.4-1.1-1.1-1.2-1.9-.2-1 .9-2.2.9-2.2s111.8-99.4 114.8-109.8c.2-.8-.6-1.2-1.8-.9-7.4 2.7-136.2 84.1-150.4 93-.9.2-2 .3-3.1.1" fill="#fff"/></svg>',
    'google_api': '<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><path d="M501.8 261.8c0-18.2-1.6-35.6-4.7-52.4H256v99.1h137.8c-6.1 31.9-24.2 58.9-51.4 77V450h83.1c48.3-44.6 76.3-110.2 76.3-188.2" fill="#4285f4"/><path d="M256 512c69.1 0 127.1-22.8 169.4-61.9l-83.1-64.5c-22.8 15.4-51.9 24.7-86.3 24.7-66.6 0-123.1-44.9-143.4-105.4H27.5V371C69.6 454.5 155.9 512 256 512" fill="#34a853"/><path d="M112.6 304.6c-5.1-15.4-8.1-31.7-8.1-48.6s3-33.3 8.1-48.6v-66.1H27.5C10 175.7 0 214.6 0 256s10 80.3 27.5 114.7L93.8 319c0 .1 18.8-14.4 18.8-14.4" fill="#fbbc05"/><path d="M256 101.9c37.7 0 71.2 13 98 38.2l73.3-73.3C382.8 25.4 325.1 0 256 0 155.9 0 69.6 57.5 27.5 141.3l85.2 66.1c20.2-60.5 76.7-105.5 143.3-105.5" fill="#ea4335"/><path d="M0 0h512v512H0z" fill="none"/></svg>',
    'truenas': '<svg viewBox="0 10 90 71" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><g fill="none"><path fill="#31BEEC" d="M90 38.197v19.137L48.942 80.999V61.864z"/><path fill="#0095D5" d="M41.086 61.863V81L0 57.333V38.197l18.566 10.687q.03.025.067.04z"/><path fill="#AEADAE" d="m61.621 45.506-16.607 9.576-16.622-9.576 16.622-9.575z"/><path fill="#0095D5" d="M86.086 31.416 69.464 40.99 48.942 29.15V10z"/><path fill="#31BEEC" d="M41.086 10v19.15l-20.55 11.827-16.621-9.561z"/></g></svg>',
}

def _brand_logo(key: str) -> str:
    return _BRAND_LOGOS[key]



def _http_toolkit_yaml(
    key: str, *, port: int, path_prefixes: list[str], header: str | None,
    methods: list[str] = ("GET", "POST"),
) -> str:
    prefixes = "\n".join(f'      - "{p}"' for p in path_prefixes)
    methods_line = ", ".join(f'"{m}"' for m in methods)
    header_comment = (
        f"    # Sends the credential as '{header}'. Never as a ?apikey= query "
        "param (FR-8.14) -- that would end up in the target's access logs."
        if header
        else "    # This service accepts no per-request credential; adjust if yours does."
    )
    return (
        f"  {key}:\n"
        "    executor: http\n"
        f'    base_url: "http://CHANGEME:{port}"\n'
        f"    allowed_methods: [{methods_line}]\n"
        "    allowed_path_prefixes:\n"
        f"{prefixes}\n"
        "    allowed_cidrs:\n"
        # 203.0.113.0/24 is RFC 5737 TEST-NET-3, reserved for documentation --
        # a syntactically valid placeholder that can never resolve to a real
        # host, so a copy-pasted-but-unedited block fails closed rather than
        # silently allowing an unintended address.
        '      - "203.0.113.1/32"  # CHANGEME -- e.g. 192.168.1.42/32, this one host\n'
        f"    credential: {key}\n"
        f"{header_comment}\n"
        "    follow_redirects: false\n"
        "    max_timeout_seconds: 20\n"
        "    max_output_bytes: 131072\n"
    )


def _tool(
    tool_id: str, *, toolkit: str, title: str, description: str, method: str, path: str,
    category: str = "read", idempotent: bool = True, query: dict[str, str] | None = None,
    body: dict[str, str] | None = None, parameters: dict[str, Any] | None = None,
    required_scopes: list[str] | None = None, timeout_seconds: int = 15,
    max_output_bytes: int = 65536,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "id": tool_id, "toolkit": toolkit, "version": 1, "title": title,
        "description": description, "category": category, "idempotent": idempotent,
        "enabled": False, "method": method, "path": path,
        "parameters": parameters or {}, "required_scopes": required_scopes or [],
        "timeout_seconds": timeout_seconds, "max_output_bytes": max_output_bytes,
    }
    if query:
        spec["query"] = query
    if body:
        spec["body"] = body
    return spec


#: The *-arr apps and Jellyfin share one auth shape: an API key in a
#: fixed header name, key query param also accepted by the target but
#: never used by gatekeeper (FR-8.14).
_ARR_QUERY_PARAM = {"api_key_header": "X-Api-Key"}

_PRESETS: list[Preset] = [
    Preset(
        key="sonarr",
        display_name="Sonarr",
        logo_svg=_brand_logo("sonarr"),
        toolkit_yaml=_http_toolkit_yaml(
            "sonarr", port=8989, path_prefixes=["/api/v3/series"], header="X-Api-Key",
        ),
        credential_kind="api_key_header",
        tool_specs=(
            _tool(
                "sonarr.list_series", toolkit="sonarr", title="List series",
                description="Lists all series known to Sonarr.",
                method="GET", path="/api/v3/series",
            ),
            _tool(
                "sonarr.search_series", toolkit="sonarr", title="Search series",
                description="Looks up series by name (does not add anything).",
                method="GET", path="/api/v3/series/lookup",
                query={"term": "{term}"},
                parameters={
                    "term": {"type": "string", "required": True, "pattern": "^.{1,200}$",
                              "description": "Series name to search for."},
                },
            ),
            _tool(
                "sonarr.add_series", toolkit="sonarr", title="Add series",
                description="Adds a series by TVDB ID. Externally visible once added.",
                method="POST", path="/api/v3/series", category="write_external",
                idempotent=False,
                body={"tvdbId": "{tvdb_id}", "qualityProfileId": "{quality_profile_id}"},
                parameters={
                    "tvdb_id": {"type": "string", "required": True, "pattern": "^[0-9]{1,10}$",
                                 "description": "TVDB ID of the series."},
                    "quality_profile_id": {"type": "string", "required": True,
                                             "pattern": "^[0-9]{1,5}$",
                                             "description": "Sonarr quality profile ID."},
                },
            ),
        ),
    ),
    Preset(
        key="radarr",
        display_name="Radarr",
        logo_svg=_brand_logo("radarr"),
        toolkit_yaml=_http_toolkit_yaml(
            "radarr", port=7878, path_prefixes=["/api/v3/movie"], header="X-Api-Key",
        ),
        credential_kind="api_key_header",
        tool_specs=(
            _tool(
                "radarr.list_movies", toolkit="radarr", title="List movies",
                description="Lists all movies known to Radarr.",
                method="GET", path="/api/v3/movie",
            ),
            _tool(
                "radarr.search_movie", toolkit="radarr", title="Search movie",
                description="Looks up movies by name (does not add anything).",
                method="GET", path="/api/v3/movie/lookup",
                query={"term": "{term}"},
                parameters={
                    "term": {"type": "string", "required": True, "pattern": "^.{1,200}$",
                              "description": "Movie name to search for."},
                },
            ),
            _tool(
                "radarr.add_movie", toolkit="radarr", title="Add movie",
                description="Adds a movie by TMDB ID. Externally visible once added.",
                method="POST", path="/api/v3/movie", category="write_external",
                idempotent=False,
                body={"tmdbId": "{tmdb_id}", "qualityProfileId": "{quality_profile_id}"},
                parameters={
                    "tmdb_id": {"type": "string", "required": True, "pattern": "^[0-9]{1,10}$",
                                 "description": "TMDB ID of the movie."},
                    "quality_profile_id": {"type": "string", "required": True,
                                             "pattern": "^[0-9]{1,5}$",
                                             "description": "Radarr quality profile ID."},
                },
            ),
        ),
    ),
    Preset(
        key="jellyfin",
        display_name="Jellyfin",
        logo_svg=_brand_logo("jellyfin"),
        toolkit_yaml=_http_toolkit_yaml(
            "jellyfin", port=8096, path_prefixes=["/Library", "/Sessions"],
            header="X-Emby-Token", methods=["GET"],
        ),
        credential_kind="api_key_header",
        notes="Read-only in this preset, matching the v1 toolkit catalog.",
        tool_specs=(
            _tool(
                "jellyfin.list_libraries", toolkit="jellyfin", title="List libraries",
                description="Lists configured media libraries.",
                method="GET", path="/Library/MediaFolders",
            ),
            _tool(
                "jellyfin.list_sessions", toolkit="jellyfin", title="List sessions",
                description="Lists currently active playback sessions.",
                method="GET", path="/Sessions",
            ),
        ),
    ),
    Preset(
        key="bazarr",
        display_name="Bazarr",
        logo_svg=_brand_logo("bazarr"),
        toolkit_yaml=_http_toolkit_yaml(
            "bazarr", port=6767, path_prefixes=["/api/"], header="X-Api-Key",
        ),
        credential_kind="api_key_header",
        tool_specs=(
            _tool(
                "bazarr.list_wanted", toolkit="bazarr", title="List wanted subtitles",
                description="Lists episodes/movies still missing a subtitle.",
                method="GET", path="/api/episodes/wanted",
            ),
            _tool(
                "bazarr.list_series", toolkit="bazarr", title="List series",
                description="Lists series known to Bazarr.",
                method="GET", path="/api/series",
            ),
        ),
    ),
    Preset(
        key="tdarr",
        display_name="Tdarr",
        logo_svg=_monogram("Td", "#26c6da"),
        toolkit_yaml=_http_toolkit_yaml(
            "tdarr", port=8265, path_prefixes=["/api/v2/"], header=None,
        ),
        credential_kind="api_key_header",
        notes=(
            "Tdarr's own auth is optional/basic rather than a fixed API-key "
            "header; adjust the toolkit's credential kind if you enable it."
        ),
        tool_specs=(
            _tool(
                "tdarr.list_nodes", toolkit="tdarr", title="List nodes",
                description="Lists Tdarr transcode nodes and their status.",
                method="GET", path="/api/v2/get-nodes",
            ),
            _tool(
                "tdarr.list_queue", toolkit="tdarr", title="List queue",
                description="Lists queued/processing transcode jobs.",
                method="GET", path="/api/v2/get-queue",
            ),
        ),
    ),
    Preset(
        key="prowlarr",
        display_name="Prowlarr",
        logo_svg=_brand_logo("prowlarr"),
        toolkit_yaml=_http_toolkit_yaml(
            "prowlarr", port=9696, path_prefixes=["/api/v1/indexer"], header="X-Api-Key",
        ),
        credential_kind="api_key_header",
        tool_specs=(
            _tool(
                "prowlarr.list_indexers", toolkit="prowlarr", title="List indexers",
                description="Lists configured indexers and their status.",
                method="GET", path="/api/v1/indexer",
            ),
            _tool(
                "prowlarr.test_indexer", toolkit="prowlarr", title="Test indexer",
                description="Tests connectivity of one configured indexer.",
                method="POST", path="/api/v1/indexer/{indexer_id}/test",
                category="write", idempotent=True,
                parameters={
                    "indexer_id": {"type": "string", "required": True,
                                    "pattern": "^[0-9]{1,10}$",
                                    "description": "Prowlarr indexer ID."},
                },
            ),
        ),
    ),
    Preset(
        key="hass",
        display_name="Home Assistant",
        logo_svg=_brand_logo("hass"),
        toolkit_yaml=_http_toolkit_yaml(
            "hass", port=8123, path_prefixes=["/api/states", "/api/services"],
            header=None,
        ).replace(
            "    # This service accepts no per-request credential; adjust if yours does.\n",
            "    # Sends a long-lived access token as 'Authorization: Bearer ...'.\n",
        ),
        credential_kind="bearer",
        tool_specs=(
            _tool(
                "hass.get_state", toolkit="hass", title="Get entity state",
                description="Reads the current state of one entity.",
                method="GET", path="/api/states/{entity_id}",
                parameters={
                    "entity_id": {"type": "string", "required": True,
                                   "pattern": "^[a-z_]+\\.[a-z0-9_]+$",
                                   "description": "e.g. light.living_room."},
                },
            ),
            _tool(
                "hass.call_service", toolkit="hass", title="Call a service",
                description=(
                    "Calls a Home Assistant service (e.g. turning something on). "
                    "Externally visible and not undoable by gatekeeper."
                ),
                method="POST", path="/api/services/{domain}/{service}",
                category="write_external", idempotent=False,
                body={"entity_id": "{entity_id}"},
                parameters={
                    "domain": {"type": "string", "required": True, "pattern": "^[a-z_]+$",
                                "description": "e.g. light."},
                    "service": {"type": "string", "required": True, "pattern": "^[a-z_]+$",
                                 "description": "e.g. turn_on."},
                    "entity_id": {"type": "string", "required": True,
                                   "pattern": "^[a-z_]+\\.[a-z0-9_]+$",
                                   "description": "Target entity."},
                },
            ),
        ),
    ),
    Preset(
        key="n8n",
        display_name="n8n",
        logo_svg=_brand_logo("n8n"),
        toolkit_yaml=_http_toolkit_yaml(
            "n8n", port=5678, path_prefixes=["/api/v1/workflows"],
            header="X-N8N-API-KEY",
        ),
        credential_kind="api_key_header",
        tool_specs=(
            _tool(
                "n8n.list_workflows", toolkit="n8n", title="List workflows",
                description="Lists configured workflows.",
                method="GET", path="/api/v1/workflows",
            ),
            _tool(
                "n8n.activate_workflow", toolkit="n8n", title="Activate workflow",
                description="Activates a workflow so its triggers start firing.",
                method="POST", path="/api/v1/workflows/{workflow_id}/activate",
                category="write", idempotent=True,
                parameters={
                    "workflow_id": {"type": "string", "required": True,
                                     "pattern": "^[A-Za-z0-9_-]{1,64}$",
                                     "description": "n8n workflow ID."},
                },
            ),
        ),
    ),
    Preset(
        key="uptimekuma",
        display_name="Uptime Kuma",
        logo_svg=_brand_logo("uptimekuma"),
        toolkit_yaml=_http_toolkit_yaml(
            "uptimekuma", port=3001, path_prefixes=["/api/status-page/"],
            header=None, methods=["GET"],
        ),
        credential_kind="api_key_header",
        notes=(
            "Uptime Kuma's primary API is Socket.IO, not conventional REST. "
            "This preset targets its read-only status-page JSON endpoint "
            "('/api/status-page/<slug>') -- the fit for the http executor is "
            "partial; monitor management still needs the web UI."
        ),
        tool_specs=(
            _tool(
                "uptimekuma.status_page", toolkit="uptimekuma", title="Read status page",
                description="Reads a public status page's monitor summary as JSON.",
                method="GET", path="/api/status-page/{slug}",
                parameters={
                    "slug": {"type": "string", "required": True,
                              "pattern": "^[a-z0-9-]{1,64}$",
                              "description": "Status page slug."},
                },
            ),
        ),
    ),
    Preset(
        key="immich",
        display_name="Immich",
        logo_svg=_brand_logo("immich"),
        toolkit_yaml=_http_toolkit_yaml(
            "immich", port=2283, path_prefixes=["/api/asset", "/api/search"],
            header="x-api-key",
        ),
        credential_kind="api_key_header",
        tool_specs=(
            _tool(
                "immich.list_assets", toolkit="immich", title="List recent assets",
                description="Lists recently added photos/videos.",
                method="GET", path="/api/asset",
            ),
            _tool(
                "immich.search_metadata", toolkit="immich", title="Search assets",
                description="Searches assets by free-text query against metadata.",
                method="POST", path="/api/search/metadata",
                body={"query": "{query}"},
                parameters={
                    "query": {"type": "string", "required": True, "pattern": "^.{1,200}$",
                               "description": "Search text."},
                },
            ),
        ),
    ),
    Preset(
        key="telegram",
        display_name="Telegram",
        logo_svg=_brand_logo("telegram"),
        toolkit_yaml=(
            "  telegram:\n"
            "    executor: http\n"
            '    base_url: "https://api.telegram.org/bot{credential}"\n'
            '    allowed_methods: ["GET", "POST"]\n'
            "    allowed_path_prefixes:\n"
            '      - "/sendMessage"\n'
            '      - "/getUpdates"\n'
            "    allowed_cidrs:\n"
            '      - "149.154.160.0/20"  # Telegram Bot API published range\n'
            '      - "91.108.4.0/22"\n'
            "    credential: telegram\n"
            "    # The bot token lives IN base_url via {credential}, substituted\n"
            "    # server-side only (execute_http.py) -- never in a header, never\n"
            "    # visible to a tool definition or the agent.\n"
            "    follow_redirects: false\n"
            "    max_timeout_seconds: 15\n"
            "    max_output_bytes: 65536\n"
        ),
        credential_kind="url_path",
        notes=(
            "The bot token is embedded in base_url via {credential}, not a "
            "header -- the one deliberate exception to 'credentials are "
            "always a header' (see execute_http.py's _substitute_base_url)."
        ),
        tool_specs=(
            _tool(
                "telegram.send_message", toolkit="telegram", title="Send message",
                description=(
                    "Sends a message via the bot. Externally visible and delivered "
                    "immediately -- there is no 'undo' tool."
                ),
                method="POST", path="/sendMessage", category="write_external",
                idempotent=False,
                body={"chat_id": "{chat_id}", "text": "{text}"},
                parameters={
                    "chat_id": {"type": "string", "required": True,
                                 "pattern": "^-?[0-9]{1,20}$",
                                 "description": "Target chat ID."},
                    "text": {"type": "string", "required": True, "pattern": "^.{1,4096}$",
                              "description": "Message text."},
                },
            ),
            _tool(
                "telegram.get_updates", toolkit="telegram", title="Get updates",
                description="Reads recent messages/events sent to the bot.",
                method="GET", path="/getUpdates",
            ),
        ),
    ),
    Preset(
        key="google_api",
        display_name="Google API",
        logo_svg=_brand_logo("google_api"),
        toolkit_yaml=(
            "  google_api:\n"
            "    executor: http\n"
            '    base_url: "https://www.googleapis.com"\n'
            '    allowed_methods: ["GET"]\n'
            "    allowed_path_prefixes:\n"
            '      - "/customsearch/v1"   # example: Custom Search JSON API\n'
            "    allowed_cidrs:\n"
            '      - "142.250.0.0/15"  # Google published range; narrow further if you can\n'
            "    credential: google_api\n"
            "    # Sends 'X-goog-api-key' (FR-8.14 prefers a header over ?key=).\n"
            "    follow_redirects: false\n"
            "    max_timeout_seconds: 15\n"
            "    max_output_bytes: 65536\n"
        ),
        credential_kind="api_key_header",
        notes=(
            "Most Google Workspace APIs (Calendar, Gmail, Drive) require OAuth2 "
            "and are NOT covered by this preset -- gatekeeper's v1 http executor "
            "supports static credentials only (FR-8.11), no authorization-code "
            "flow. This preset is scoped to API-key-eligible APIs such as "
            "Custom Search; adjust allowed_path_prefixes/base_url per API."
        ),
        tool_specs=(
            _tool(
                "google_api.custom_search", toolkit="google_api", title="Custom Search",
                description="Runs a Google Programmable Search Engine query.",
                method="GET", path="/customsearch/v1",
                query={"q": "{query}", "cx": "{engine_id}"},
                parameters={
                    "query": {"type": "string", "required": True, "pattern": "^.{1,200}$",
                               "description": "Search text."},
                    "engine_id": {"type": "string", "required": True,
                                   "pattern": "^[A-Za-z0-9:_-]{1,64}$",
                                   "description": "Programmable Search Engine ID."},
                },
            ),
        ),
    ),
    Preset(
        key="truenas",
        display_name="TrueNAS",
        logo_svg=_brand_logo("truenas"),
        toolkit_yaml=(
            "  truenas:\n"
            "    executor: truenas\n"
            '    ws_url: "wss://CHANGEME/api/current"\n'
            "    allowed_rpc_methods:\n"
            "      - pool.query\n"
            "      - pool.dataset.query\n"
            "    credential: truenas\n"
            "    max_timeout_seconds: 30\n"
            "    max_output_bytes: 65536\n"
        ),
        credential_kind="ws_api_key",
        notes=(
            "JSON-RPC 2.0 over WebSocket, not REST (TrueNAS's REST v2.0 is "
            "deprecated as of 25.04). See config/examples/toolkits.yaml and "
            "tools.yaml for a full worked example including a write tool."
        ),
        # truenas tool specs are `method`/`params`, not the http `method`/
        # `path` shape -- built directly rather than through the http-shaped
        # `_tool()` helper, which has no truenas branch.
        tool_specs=(
            {
                "id": "truenas.list_pools", "toolkit": "truenas", "version": 1,
                "title": "List storage pools",
                "description": "Lists ZFS pools and their status.",
                "category": "read", "idempotent": True, "enabled": False,
                "method": "pool.query", "params": {},
                "parameters": {}, "required_scopes": [],
                "timeout_seconds": 15, "max_output_bytes": 32768,
            },
        ),
    ),
]

PRESETS: dict[str, Preset] = {preset.key: preset for preset in _PRESETS}
