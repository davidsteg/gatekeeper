"""A small library of starter definitions for common homelab/SaaS services.

This is the "simplify adding tools" half of the http/truenas executor work:
once an admin has pasted an integration's `toolkit_yaml` into `toolkits.yaml` and
redeployed (Tier 1 stays a manual, deploy-time step -- FR-4.11, integrations do
not and must not change that), picking one of its `tool_specs` in
`/ui/tools/integrations` pre-fills the *existing* tool editor instead of a blank
textarea. The integration never bypasses `parse_tool_spec`/Tier 1 validation --
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
class Integration:
    key: str
    display_name: str
    logo_svg: str
    #: Copy-pasteable Tier 1 block for toolkits.yaml. Always contains
    #: CHANGEME placeholders for the host and allowed_cidrs -- no integration
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

    language for every integration logo, so twelve services read as one system
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
#: integration key (e.g. 'st0' -> 'radarr-st0') because the integration gallery
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
    'pfsense': '<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><path d="M465 512H47c-26 0-47-21-47-47V47C0 21 21 0 47 0h418c26 0 47 21 47 47v418c0 26-21 47-47 47" fill="#fff"/><path d="M148 361.4c19.2 0 35.7-5.9 49.5-17.2 13.9-11.2 23.8-26.4 29.1-44.9s4-33.7-3.3-44.9-21.1-17.2-40.3-17.2-35.7 5.9-49.5 17.2c-13.9 11.2-23.1 26.4-28.4 44.9s-4.6 33.7 3.3 44.9c6.6 11.9 19.8 17.2 39.6 17.2" fill="#1a1a1a"/><path d="m311.8 237.2 17.2-60.8h30.4l11.9-43.6c4-13.2 8.6-26.4 14.5-38.3 5.3-11.9 13.2-22.5 22.5-31.7 9.2-9.2 21.1-16.5 35-21.8s31.7-8 52.2-8c5.3 0 9.9 0 15.2.7-4.6-19.2-21.8-33-41.6-33.7H42.9C19.2 0 0 19.8 0 43.6v379.2l69.4-246.4h70l-9.2 32.4h1.3c4-4.6 9.2-8.6 15.9-13.2 6.6-4.6 13.2-8.6 20.5-12.6s15.2-6.6 23.8-9.2 17.2-3.3 25.8-3.3c18.5 0 33.7 3.3 46.9 9.2s23.1 15.2 31.1 26.4c6.6 9.9 10.6 21.8 12.6 35.7l5.3-4h-1.3v-.6z" fill="#1a1a1a"/><path d="M506.7 98.4c-3.3-.7-7.3-1.3-11.9-1.3-11.9 0-21.8 2.6-29.7 7.9-7.3 5.3-13.9 15.9-18.5 32.4l-11.2 39h42.9l10.6 33.7-27.7 27.1h-42.9l-52.2 185h-75.3l52.2-185h-29.1l-5.9 4c0 1.3.7 3.3.7 4.6 1.3 15.2-.7 32.4-5.9 50.9-4.6 17.2-11.9 33.7-21.8 49.5s-21.1 29.7-33.7 41.6c-13.2 11.9-27.7 21.8-43.6 29.1s-32.4 10.6-50.2 10.6c-15.9 0-29.7-2.6-42.3-7.3-12.6-4.6-21.1-13.2-26.4-25.1h-1.3L50.2 512h418.2c23.8 0 43.6-19.2 43.6-43.6v-368c-2-.6-4-1.3-5.3-2" fill="#1a1a1a"/></svg>',
    'netdata': '<svg viewBox="0 46.3 512 419.4" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><path d="M315 465.7H211.7L0 46.3h300.5c116.8.2 211.5 97.4 211.5 217.2-.2 111.8-88.3 202.1-197 202.2" fill-rule="evenodd" clip-rule="evenodd" fill="#00ab44"/></svg>',
    'sabnzbd': '<svg viewBox="0 0 1000 1000" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><path stroke="#000" stroke-linejoin="round" stroke-width="74" d="M200.4 39.3h598.1v437.8h161l-460.1 483L39.4 477h161z"/><path fill="#ffb300" fill-rule="evenodd" d="M200.4 39.3h598.1v437.8h161l-460.1 483-460-483h161z"/><path fill="#ffca28" fill-rule="evenodd" d="M499.4 960.2 201.1 39.4h596.7z"/><path stroke="#000" stroke-linecap="round" stroke-linejoin="round" stroke-width="74" d="M329.2 843.5H83v-51.8h146.1v-45.9H83V596.9h246.2v51.5H183.1v45.9h146.1zm292.2 0H375.2V694.3h146.1v-45.9H375.2v-51.5h246.2zm-146.1-97.8h46v46h-46zm192.1 97.8v-344h100.1v97.4h146.1v246.6zm100.1-195.2h46v143.4h-46z"/><path fill="#fff" fill-rule="evenodd" d="M329.2 843.5H83v-51.8h146.1v-45.9H83V596.9h246.2v51.5H183.1v45.9h146.1zm292.2 0H375.2V694.3h146.1v-45.9H375.2v-51.5h246.2zm-146.1-51.8h46v-46h-46zm192.1 51.9v-344h100.1V597h146.1v246.6zm100.1-51.9h46V648.4h-46z"/></svg>',
    'paperless': '<svg viewBox="43.38 0.14 425.32 512.02" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><path d="M136.8 459.6c-2.3-10.8-6.9-32.5-7.4-32.5-96.5-57.7-85.1-157.6-53.1-214.7 6.9 71.9 134.2 121.6 60 209.6-.6 1.1 3.4 14.8 6.9 27.4 14.8-25.1 37.1-55.4 36-58.2-91.4-222.7 194.1-239.8 253.5-378 26.8 133.6-13.7 340.3-243.3 392.9-1.1.6-41.7 71.9-43.4 72.5 0-1.1-17.1-.6-14.8-6.3 1.1-3.6 3.3-8.1 5.6-12.7m56.6-98.8c-36-85.1 69.7-178.7 122.2-202.1C208.2 254.6 189.9 326 193.4 360.8M134 405.9c29.1-33.7-5.1-91.4-25.7-110.2 34.8 60 32.5 94.8 25.7 110.2" fill="#17541f" transform="translate(-15.306 -14.379)scale(1.10017)"/></svg>',
    'docker': '<svg viewBox="-0.07 71.3 511.97 369.5" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><path d="M501.4 212.3c-11.5-8-38-11-58.6-7-2.4-20-13.5-37.5-32.7-53l-11-8-7.7 11.5c-9.6 15-14.4 36-13 56 .5 7 2.9 19.5 10.1 30.5-6.7 4-20.7 9-38.9 9H2.3l-1 4c-3.4 20-3.4 82.5 36 130.5 29.8 36.5 74 55 132.1 55 125.9 0 219.1-60.5 262.8-170 17.3.5 54.3 0 73-37.5.5-1 1.4-3 4.8-10.5l1.9-4zM280 71.3h-52.8v50H280zm0 60h-52.8v50H280zm-62.5 0h-52.8v50h52.8zm-62.4 0h-52.8v50h52.8zm-62.5 60H39.8v50h52.8zm62.5 0h-52.8v50h52.8zm62.4 0h-52.8v50h52.8zm62.5 0h-52.8v50H280zm62.4 0h-52.8v50h52.8z" fill="#2396ed"/></svg>',
    'linux': '<svg viewBox="0 0 216 256" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><defs><linearGradient id="linux-s"><stop offset="0"/><stop offset="1" stop-opacity=".25"/></linearGradient><linearGradient id="linux-u"><stop offset="0" stop-color="#110800"/><stop offset=".59" stop-color="#a65a00" stop-opacity=".8"/><stop offset="1" stop-color="#ff921e" stop-opacity="0"/></linearGradient><linearGradient id="linux-v"><stop offset="0" stop-color="#7c7c7c"/><stop offset="1" stop-color="#7c7c7c" stop-opacity=".33"/></linearGradient><linearGradient id="linux-g"><stop offset="0" stop-color="#7c7c7c"/><stop offset="1" stop-color="#7c7c7c" stop-opacity=".33"/></linearGradient><linearGradient id="linux-a"><stop offset="0" stop-color="#b98309"/><stop offset="1" stop-color="#382605"/></linearGradient><linearGradient id="linux-c"><stop offset="0" stop-color="#ebc40c"/><stop offset="1" stop-color="#ebc40c" stop-opacity="0"/></linearGradient><linearGradient id="linux-d"><stop offset="0"/><stop offset="1" stop-opacity="0"/></linearGradient><linearGradient id="linux-e"><stop offset="0" stop-color="#3e2a06"/><stop offset="1" stop-color="#ad780a"/></linearGradient><linearGradient id="linux-f"><stop offset="0" stop-color="#f3cd0c"/><stop offset="1" stop-color="#f3cd0c" stop-opacity="0"/></linearGradient><linearGradient id="linux-w"><stop offset="0" stop-color="#fefefc"/><stop offset=".75" stop-color="#fefefc"/><stop offset="1" stop-color="#d4d4d4"/></linearGradient><linearGradient id="linux-h"><stop offset="0" stop-color="#757574" stop-opacity="0"/><stop offset=".25" stop-color="#757574"/><stop offset=".5" stop-color="#757574"/><stop offset="1" stop-color="#757574" stop-opacity="0"/></linearGradient><linearGradient id="linux-l"><stop offset="0" stop-color="#949494" stop-opacity=".39"/><stop offset=".5" stop-color="#949494"/><stop offset="1" stop-color="#949494" stop-opacity=".39"/></linearGradient><linearGradient id="linux-x"><stop offset="0" stop-color="#c8c8c8"/><stop offset="1" stop-color="#797978"/></linearGradient><linearGradient id="linux-o"><stop offset="0" stop-color="#747474"/><stop offset=".13" stop-color="#8c8c8c"/><stop offset=".25" stop-color="#a4a4a4"/><stop offset=".5" stop-color="#d4d4d4"/><stop offset=".62" stop-color="#d4d4d4"/><stop offset="1" stop-color="#7c7c7c"/></linearGradient><linearGradient id="linux-j"><stop offset="0" stop-color="#646464" stop-opacity="0"/><stop offset=".31" stop-color="#646464" stop-opacity=".58"/><stop offset=".47" stop-color="#646464"/><stop offset=".73" stop-color="#646464" stop-opacity=".26"/><stop offset="1" stop-color="#646464" stop-opacity="0"/></linearGradient><linearGradient id="linux-y"><stop offset="0" stop-color="#020204"/><stop offset=".73" stop-color="#020204"/><stop offset="1" stop-color="#5c5c5c"/></linearGradient><linearGradient id="linux-z"><stop offset="0" stop-color="#d2940a"/><stop offset=".75" stop-color="#d89c08"/><stop offset=".87" stop-color="#b67e07"/><stop offset="1" stop-color="#946106"/></linearGradient><linearGradient id="linux-p"><stop offset="0" stop-color="#ad780a"/><stop offset=".12" stop-color="#d89e08"/><stop offset=".25" stop-color="#edb80b"/><stop offset=".39" stop-color="#ebc80d"/><stop offset=".53" stop-color="#f5d838"/><stop offset=".77" stop-color="#f6d811"/><stop offset="1" stop-color="#f5cd31"/></linearGradient><linearGradient id="linux-A"><stop offset="0" stop-color="#3a2903"/><stop offset=".55" stop-color="#735208"/><stop offset="1" stop-color="#ac8c04"/></linearGradient><linearGradient id="linux-q"><stop offset="0" stop-color="#f5ce2d"/><stop offset="1" stop-color="#d79b08"/></linearGradient><linearGradient xlink:href="#linux-a" id="linux-ac" x1="23.18" x2="64.31" y1="193.01" y2="262.02" gradientUnits="userSpaceOnUse" href="#linux-a"/><linearGradient xlink:href="#linux-c" id="linux-ag" x1="64.47" x2="77.41" y1="210.83" y2="235.21" gradientUnits="userSpaceOnUse" href="#linux-c"/><linearGradient xlink:href="#linux-d" id="linux-ai" x1="146.93" x2="150.2" y1="211.96" y2="235.73" gradientUnits="userSpaceOnUse" href="#linux-d"/><linearGradient xlink:href="#linux-e" id="linux-ak" x1="151.5" x2="192.94" y1="253.02" y2="185.84" gradientUnits="userSpaceOnUse" href="#linux-e"/><linearGradient xlink:href="#linux-f" id="linux-ao" x1="162.81" x2="161.59" y1="180.67" y2="191.64" gradientUnits="userSpaceOnUse" href="#linux-f"/><linearGradient xlink:href="#linux-g" id="linux-ay" x1="165.69" x2="168.27" y1="173.58" y2="173.47" gradientUnits="userSpaceOnUse" href="#linux-g"/><linearGradient xlink:href="#linux-h" id="linux-aA" x1="84.29" x2="89.32" y1="46.64" y2="55.63" gradientUnits="userSpaceOnUse" href="#linux-h"/><linearGradient xlink:href="#linux-j" id="linux-aF" x1="83.59" x2="94.48" y1="32.51" y2="43.63" gradientUnits="userSpaceOnUse" href="#linux-j"/><linearGradient xlink:href="#linux-l" id="linux-aI" x1="117.87" x2="123.66" y1="47.25" y2="54.11" gradientUnits="userSpaceOnUse" href="#linux-l"/><linearGradient xlink:href="#linux-o" id="linux-aL" x1="112.9" x2="131.32" y1="36.23" y2="47.01" gradientUnits="userSpaceOnUse" href="#linux-o"/><linearGradient xlink:href="#linux-j" id="linux-aN" x1="119.16" x2="131.42" y1="31.56" y2="43.14" gradientUnits="userSpaceOnUse" href="#linux-j"/><linearGradient xlink:href="#linux-p" id="linux-aW" x1="78.09" x2="126.77" y1="69.26" y2="68.88" gradientUnits="userSpaceOnUse" href="#linux-p"/><linearGradient xlink:href="#linux-q" id="linux-bd" x1="126.74" x2="126.74" y1="67.49" y2="71.09" gradientUnits="userSpaceOnUse" href="#linux-q"/><filter id="linux-P"><feGaussianBlur stdDeviation="0.64 0.55"/></filter><filter id="linux-R"><feGaussianBlur stdDeviation=".98"/></filter><filter id="linux-T"><feGaussianBlur stdDeviation=".68"/></filter><filter id="linux-U" width="2.6" height="1.4" x="-.8" y="-.2"><feGaussianBlur stdDeviation="1.25"/></filter><filter id="linux-V" width="2.6" height="2" x="-.8" y="-.5"><feGaussianBlur stdDeviation="1.78 2.19"/></filter><filter id="linux-W" width="1.6" height="1.6" x="-.3" y="-.3"><feGaussianBlur stdDeviation="1.73"/></filter><filter id="linux-X" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation=".78"/></filter><filter id="linux-Z" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation=".98"/></filter><filter id="linux-ab" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation="1.19 1.17"/></filter><filter id="linux-ae" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation="3.38"/></filter><filter id="linux-af"><feGaussianBlur stdDeviation="2.1 2.06"/></filter><filter id="linux-ah"><feGaussianBlur stdDeviation=".32"/></filter><filter id="linux-aj"><feGaussianBlur stdDeviation="1.95 1.9"/></filter><filter id="linux-am" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation="4.12"/></filter><filter id="linux-an" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation="3.12 3.37"/></filter><filter id="linux-ap" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation=".41"/></filter><filter id="linux-ar" width="1.6" height="1.6" x="-.3" y="-.3"><feGaussianBlur stdDeviation="2.45"/></filter><filter id="linux-at" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation="1.12 0.81"/></filter><filter id="linux-ax" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation=".88"/></filter><filter id="linux-aC" width="1.6" height="1.6" x="-.3" y="-.3"><feGaussianBlur stdDeviation=".44"/></filter><filter id="linux-aG"><feGaussianBlur stdDeviation=".12"/></filter><filter id="linux-aK" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation=".45"/></filter><filter id="linux-aO"><feGaussianBlur stdDeviation=".13"/></filter><filter id="linux-aP" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation="1.75"/></filter><filter id="linux-aQ"><feGaussianBlur stdDeviation="0.8 0.74"/></filter><filter id="linux-aU" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation=".77"/></filter><filter id="linux-aV"><feGaussianBlur stdDeviation=".65"/></filter><filter id="linux-aY" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation=".73"/></filter><filter id="linux-ba" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation=".1"/></filter><filter id="linux-bc"><feGaussianBlur stdDeviation=".1"/></filter><filter id="linux-bf" width="1.4" height="1.4" x="-.2" y="-.2"><feGaussianBlur stdDeviation=".23"/></filter><radialGradient xlink:href="#linux-s" id="linux-N" cx="0" cy="0" r="1" gradientTransform="matrix(19 0 0 18 61.18 121.19)" gradientUnits="userSpaceOnUse" href="#linux-s"/><radialGradient xlink:href="#linux-s" id="linux-Q" cx="0" cy="0" r="1" gradientTransform="matrix(23.6 0 0 18 125.74 131.6)" gradientUnits="userSpaceOnUse" href="#linux-s"/><radialGradient xlink:href="#linux-s" id="linux-S" cx="0" cy="0" r="1" gradientTransform="matrix(9.35 0 0 10 94.21 127.47)" gradientUnits="userSpaceOnUse" href="#linux-s"/><radialGradient xlink:href="#linux-u" id="linux-aq" cx="0" cy="0" r="1" gradientTransform="matrix(18.9901 5.08838 -5.34203 19.9367 169.71 194.53)" gradientUnits="userSpaceOnUse" href="#linux-u"/><radialGradient xlink:href="#linux-u" id="linux-as" cx="0" cy="0" r="1" gradientTransform="matrix(19.7224 -.83351 .62745 14.84675 169.71 189.89)" gradientUnits="userSpaceOnUse" href="#linux-u"/><radialGradient xlink:href="#linux-v" id="linux-av" cx="0" cy="0" r="1" gradientTransform="rotate(23.5 -332.242 532.18)scale(6.95 3.21)" gradientUnits="userSpaceOnUse" href="#linux-v"/><radialGradient xlink:href="#linux-w" id="linux-az" cx="0" cy="0" r="1" gradientTransform="matrix(10.23944 -.10723 .1642 15.67914 86.49 51.41)" gradientUnits="userSpaceOnUse" href="#linux-w"/><radialGradient xlink:href="#linux-x" id="linux-aD" cx="0" cy="0" r="1" gradientTransform="rotate(-9.35 309.884 -497.172)scale(6.25 5.77)" gradientUnits="userSpaceOnUse" href="#linux-x"/><radialGradient xlink:href="#linux-w" id="linux-aH" cx="0" cy="0" r="1" gradientTransform="rotate(-1.8 1695.327 -3731.952)scale(13.64 15.68)" gradientUnits="userSpaceOnUse" href="#linux-w"/><radialGradient xlink:href="#linux-y" id="linux-aR" cx="0" cy="0" r="1" gradientTransform="rotate(-36 141.335 -120.193)scale(11.44 10.38)" gradientUnits="userSpaceOnUse" href="#linux-y"/><radialGradient xlink:href="#linux-z" id="linux-aS" cx="0" cy="0" r="1" gradientTransform="matrix(25.10142 -10.34606 7.26701 17.6311 109.77 70.61)" gradientUnits="userSpaceOnUse" href="#linux-z"/><radialGradient xlink:href="#linux-A" id="linux-aZ" cx="0" cy="0" r="1" gradientTransform="matrix(1.32 0 0 1.42 92.11 59.88)" gradientUnits="userSpaceOnUse" href="#linux-A"/><radialGradient xlink:href="#linux-A" id="linux-bb" cx="0" cy="0" r="1" gradientTransform="matrix(2.78 0 0 1.62 104.65 59.7)" gradientUnits="userSpaceOnUse" href="#linux-A"/><clipPath id="linux-O"><use xlink:href="#linux-B" href="#linux-B"/></clipPath><clipPath id="linux-Y"><use xlink:href="#linux-C" href="#linux-C"/></clipPath><clipPath id="linux-aa"><use xlink:href="#linux-D" href="#linux-D"/></clipPath><clipPath id="linux-ad"><use xlink:href="#linux-E" href="#linux-E"/></clipPath><clipPath id="linux-al"><use xlink:href="#linux-F" href="#linux-F"/></clipPath><clipPath id="linux-aw"><use xlink:href="#linux-G" href="#linux-G"/></clipPath><clipPath id="linux-aE"><use xlink:href="#linux-H" href="#linux-H"/></clipPath><clipPath id="linux-aB"><use xlink:href="#linux-I" href="#linux-I"/></clipPath><clipPath id="linux-aM"><use xlink:href="#linux-J" href="#linux-J"/></clipPath><clipPath id="linux-aJ"><use xlink:href="#linux-K" href="#linux-K"/></clipPath><clipPath id="linux-aT"><use xlink:href="#linux-L" href="#linux-L"/></clipPath><clipPath id="linux-aX"><use xlink:href="#linux-M" href="#linux-M"/></clipPath><clipPath id="linux-be"><use xlink:href="#linux-L" href="#linux-L"/><use xlink:href="#linux-M" href="#linux-M"/></clipPath></defs><path id="linux-B" fill="#020204" d="M106.95 0c-6 0-12.02 1.18-17.46 4.12-5.78 3.11-10.52 8.09-13.43 13.97-2.92 5.88-4.06 12.16-4.24 19.08-.33 13.14.3 26.92 1.29 39.41.26 3.8.74 6.02.25 9.93-1.62 8.3-8.88 13.88-12.76 21.17-4.27 8.04-6.07 17.13-9.29 25.65-2.95 7.79-7.09 15.1-9.88 22.95-3.91 10.97-5.08 23.03-2.5 34.39 1.97 8.66 6.08 16.78 11.62 23.73-.8 1.44-1.58 2.91-2.4 4.34-2.57 4.43-5.71 8.64-7.17 13.55-.73 2.45-1.02 5.07-.55 7.59s1.75 4.93 3.75 6.53c1.31 1.04 2.9 1.72 4.53 2.1 1.63.37 3.32.46 5 .43 6.37-.14 12.55-2.07 18.71-3.69 3.66-.96 7.34-1.81 11.03-2.58 13.14-2.69 27.8-1.61 39.99.15 4.13.63 8.23 1.44 12.29 2.43 6.36 1.54 12.69 3.5 19.23 3.69 1.72.05 3.46-.03 5.14-.4 1.68-.38 3.31-1.06 4.65-2.13 2.01-1.6 3.29-4.02 3.76-6.54s.18-5.15-.56-7.61c-1.48-4.92-4.65-9.11-7.27-13.52-1.04-1.75-2-3.53-3.03-5.28 7.9-8.87 14.26-19.13 17.94-30.4 4.01-12.3 4.75-25.55 3.06-38.38s-5.76-25.27-11.11-37.05c-6.72-14.76-12.37-20.1-16.47-33.07-4.42-14.02-.77-30.61-4.06-43.32-1.17-4.32-3.04-8.45-5.45-12.23-2.82-4.43-6.4-8.39-10.65-11.47C124.13 2.62 115.61 0 106.95 0"/><path fill="#fdfdfb" d="M83.13 74c-.9 1.13-1.48 2.49-1.84 3.89-.35 1.4-.48 2.85-.54 4.3-.11 2.89.07 5.83-.7 8.62-.82 2.98-2.65 5.57-4.44 8.08-3.11 4.36-6.25 8.84-7.78 13.97a24.8 24.8 0 0 0-.91 9.62c-3.47 5.1-6.48 10.53-8.98 16.18-3.78 8.57-6.37 17.69-7.28 27.01-1.12 11.41.34 23.15 4.85 33.69 3.25 7.63 8.11 14.6 14.38 20.04a49.2 49.2 0 0 0 10.5 6.97c13.11 6.45 29.31 6.46 42.2-.41 6.74-3.59 12.43-8.84 17.91-14.15 3.3-3.2 6.59-6.48 9.11-10.32 4.85-7.41 6.54-16.41 7.59-25.2 1.83-15.36 1.89-31.6-4.85-45.53-2.32-4.8-5.41-9.22-9.12-13.05-.98-6.7-2.93-13.27-5.76-19.42-2.05-4.45-4.54-8.68-6.44-13.18-.78-1.85-1.46-3.75-2.32-5.56-.87-1.81-1.93-3.55-3.39-4.94-1.48-1.42-3.33-2.43-5.28-3.07-1.95-.65-4.01-.94-6.06-1.04-4.11-.21-8.22.33-12.33.16-3.27-.13-6.53-.7-9.8-.51-1.63.1-3.26.39-4.78 1.01-1.52.61-2.92 1.56-3.94 2.84"/><path fill="url(#linux-N)" d="M68.67 115.18c.87 1.31-.55 5.84 19.86 2.94 0 0-3.59.39-7.12 1.21-5.49 1.84-10.27 3.89-13.97 6.61-3.65 2.7-6.33 6.21-9.68 9.22 0 0 5.43-9.92 6.78-12.91 1.36-2.99-.22-2.85.85-7.25s3.69-8.63 3.69-8.63-2.14 6.22-.41 8.81" clip-path="url(#linux-O)" filter="url(#linux-P)" opacity=".25"/><path fill="url(#linux-Q)" d="M134.28 113.99c-4.16 2.9-6.6 2.56-11.64 3.12-5.05.57-18.7.36-18.7.36s1.97-.03 6.36.78c4.38.82 13.31 1.6 18.34 3.51 5.04 1.92 6.87 2.47 9.93 4.4 4.35 2.75 7.55 7.06 11.71 10.08 0 0 .2-4-1.48-6.99s-6.2-7.7-7.53-12.1c-1.32-4.4-1.96-13.04-1.96-13.04s-.88 6.99-5.03 9.88" clip-path="url(#linux-O)" filter="url(#linux-R)" opacity=".42"/><path fill="url(#linux-S)" d="M95.17 107.81c-.16 1.25-.36 2.5-.6 3.74-.12.61-.26 1.22-.48 1.8-.23.58-.56 1.14-1.02 1.55-.41.37-.9.62-1.4.85-1.94.88-4.01 1.47-6.12 1.74.84.06 1.68.14 2.53.23.53.06 1.06.12 1.57.25.52.14 1.03.34 1.46.65.47.35.84.82 1.12 1.34.55 1.02.73 2.2.83 3.37.13 1.48.14 2.98.03 4.46.1-.99.31-1.98.62-2.92.57-1.72 1.47-3.32 2.69-4.65.49-.52 1.02-1.01 1.6-1.42a8.86 8.86 0 0 1 6.24-1.51c-2.21.09-4.44-.6-6.2-1.93-.9-.68-1.68-1.52-2.22-2.5a7 7 0 0 1-.65-5.05" clip-path="url(#linux-O)" filter="url(#linux-T)" opacity=".2"/><path d="M89.85 137.14a75.4 75.4 0 0 0-2.17 12.31c-.55 5.87-.42 11.78-.74 17.67-.26 4.99-.85 10.04.02 14.97a25.3 25.3 0 0 0 2.2 6.78c.16-.82.29-1.64.36-2.47.37-4-.3-8.01-.53-12.01-.4-7.02.57-14.04.97-21.06.3-5.39.27-10.8-.11-16.19" clip-path="url(#linux-O)" filter="url(#linux-U)" opacity=".11"/><path fill="#7c7c7c" d="M160.08 131.23c1.03-.16 7.34 5.21 6.48 7.21-.86 1.99-2.49.79-3.65.8-1.16.02-4.33 1.46-4.86.55-.54-.91 1.4-3.03 2.41-4.81.82-1.43-1.4-3.59-.38-3.75" clip-path="url(#linux-O)" filter="url(#linux-V)" opacity=".75"/><path fill="#7c7c7c" d="M121.52 11.12c-2.21 1.56-1.25 3.51-.3 5.46.95 1.96-2.09 7.59-2.12 7.83s5.98-2.85 7.62-4.87c1.94-2.37 6.83 3.22 6.56 2.37.01-1.52-9.55-12.34-11.76-10.79" clip-path="url(#linux-O)" filter="url(#linux-W)"/><path fill="#838384" d="M138.27 76.63c-1.86 1.7.88 4.25 2.17 7.24.81 1.86 3.04 4.49 5.2 4.07 1.63-.32 2.63-2.66 2.48-4.3-.3-3.18-2.98-3.93-4.93-5.02-1.54-.86-3.61-3.18-4.92-1.99" clip-path="url(#linux-O)" filter="url(#linux-X)"/><path id="linux-C" fill="#020204" d="M63.98 100.91c-6.1 6.92-12.37 13.63-15.81 21.12-1.71 3.8-2.51 7.93-3.68 11.93-1.32 4.54-3.12 8.94-5.14 13.22-1.87 3.95-3.93 7.81-5.98 11.66-1.5 2.81-3.02 5.67-3.54 8.81-.41 2.48-.18 5.04.46 7.47.63 2.43 1.64 4.75 2.79 6.98 4.88 9.55 12.21 17.77 20.89 24.07 3.94 2.85 8.15 5.32 12.58 7.35 2.4 1.09 4.92 2.07 7.56 2.11 1.32.03 2.65-.19 3.86-.72 1.2-.53 2.28-1.38 3-2.49.88-1.36 1.18-3.05 1-4.66s-.81-3.15-1.65-4.53c-2.06-3.38-5.31-5.83-8.44-8.25a283 283 0 0 1-19.55-16.58c-1.76-1.65-3.53-3.34-4.76-5.42-1.2-2.02-1.85-4.32-2.29-6.63-1.21-6.33-.9-12.99 1.25-19.07.85-2.38 1.96-4.65 3.04-6.93 1.86-3.95 3.62-7.98 6.07-11.6 3.05-4.51 7.13-8.33 9.61-13.17 2.1-4.09 2.95-8.68 3.76-13.2.64-3.54 1.85-7 2.47-10.54-1.21 2.3-5.11 6.07-7.5 9.07"/><path fill="#7c7c7c" d="M56.96 126.1c-2 1.84-3.73 3.97-5.13 6.31-2.3 3.84-3.65 8.16-5.33 12.31-1.24 3.09-2.69 6.2-2.86 9.53-.09 1.71.16 3.42.22 5.13s-.1 3.49-.94 4.98a6.05 6.05 0 0 1-3.22 2.71c1.83.61 3.45 1.79 4.6 3.33.96 1.3 1.58 2.81 2.41 4.18.68 1.12 1.51 2.16 2.54 2.97 1.02.82 2.25 1.4 3.54 1.56 1.79.23 3.65-.36 4.97-1.58-1.66-15.55-.14-31.42 4.44-46.37.29-.94.59-1.89.67-2.87.07-.99-.12-2.03-.72-2.81a2.99 2.99 0 0 0-2.77-1.17c-.52.06-1.03.26-1.45.57-.42.32-.76.74-.97 1.22" clip-path="url(#linux-Y)" filter="url(#linux-Z)" opacity=".95"/><path id="linux-D" fill="#020204" d="M162.76 127.12c5.24 4.22 8.57 10.59 9.6 17.24.8 5.18.28 10.51-.89 15.62-1.17 5.12-2.97 10.06-4.77 15-.71 1.96-1.43 3.95-1.71 6.02-.29 2.08-.11 4.27.89 6.11 1.15 2.11 3.29 3.56 5.59 4.24 2.27.68 4.72.66 7.02.09s6.17-1.31 8.04-2.77c4.75-3.69 5.88-10.1 7.01-15.72 1.17-5.87.6-12.02-.43-17.95-1.41-8.09-3.78-15.99-6.79-23.62a82.3 82.3 0 0 0-8.44-15.96c-3.32-4.89-8.02-8.7-11.5-13.48-1.21-1.66-2.66-3.38-3.84-5.06-2.56-3.62-1.98-2.94-3.57-5.29-1.15-1.7-2.97-2.28-4.88-3.02-1.92-.74-4.06-.96-6.04-.41-2.6.73-4.73 2.79-5.86 5.24-1.13 2.46-1.33 5.28-.89 7.95.57 3.44 2.14 6.64 3.92 9.64 2 3.39 4.32 6.66 7.35 9.18 3.16 2.63 6.98 4.37 10.19 6.95"/><path fill="#838384" d="M150.42 118.99c.42.4.86.81 1.31 1.19 3.22 2.63 4.93 5.58 8.2 8.16 5.34 4.22 10.75 11.5 11.8 18.15.82 5.19-.26 8.01-1.58 14.12-1.32 6.12-5.06 14.78-7.09 20.68-.8 2.35 1.64 1.38 1.32 3.86-.16 1.22-.18 2.45-.03 3.67.02-.23.03-.48.06-.71.39-3.38 1.42-6.63 2.55-9.82 2.17-6.13 4.66-12.15 6.38-18.45 1.72-6.29 1.53-10.82.63-16.23-1.13-6.81-5.09-13.09-10.69-17.24-3.97-2.93-8.64-4.81-12.86-7.38" clip-path="url(#linux-aa)" filter="url(#linux-ab)"/><path id="linux-E" fill="url(#linux-ac)" d="M34.98 175.33c1.38-.57 2.93-.68 4.39-.41 1.47.27 2.86.91 4.09 1.74 2.47 1.68 4.3 4.12 6.05 6.54 4.03 5.54 7.9 11.2 11.42 17.08 2.85 4.78 5.46 9.71 8.76 14.18 2.15 2.93 4.57 5.64 6.73 8.55 2.16 2.92 4.07 6.08 5.03 9.58 1.25 4.55.76 9.56-1.4 13.75-1.52 2.95-3.86 5.48-6.7 7.19S67.52 256 64.2 256c-5.27 0-10.42-2.83-15.32-4.78-9.98-3.98-20.82-5.22-31.11-8.32-3.16-.95-6.27-2.08-9.45-2.95-1.42-.39-2.85-.73-4.19-1.34-1.34-.6-2.59-1.51-3.33-2.77-.57-.98-.8-2.13-.8-3.26 0-1.14.28-2.26.67-3.32.77-2.13 2.02-4.06 2.86-6.17 1.37-3.44 1.62-7.23 1.43-10.93-.18-3.69-.78-7.36-1.03-11.05-.12-1.65-.16-3.32.16-4.95.31-1.62 1.01-3.21 2.2-4.35 1.1-1.06 2.55-1.69 4.05-2 1.49-.31 3.03-.32 4.55-.29s3.05.12 4.57-.01c1.52-.12 3.05-.46 4.37-1.22 1.26-.72 2.29-1.79 3.14-2.96s1.54-2.45 2.25-3.72c.7-1.26 1.43-2.52 2.36-3.64.92-1.12 2.06-2.09 3.4-2.64"/><path fill="#d99a03" d="M37.16 177.7c1.25-.5 2.67-.56 3.98-.26 1.32.3 2.55.94 3.61 1.77 2.14 1.65 3.62 3.97 5.05 6.26 3.42 5.54 6.76 11.15 9.92 16.86 2.4 4.31 4.68 8.7 7.62 12.65 1.95 2.62 4.18 5.03 6.17 7.62s3.76 5.41 4.64 8.56c1.14 4.05.68 8.54-1.28 12.26-1.42 2.68-3.58 4.96-6.2 6.48a15.94 15.94 0 0 1-8.69 2.14c-4.82-.22-9.23-2.63-13.77-4.26-8.71-3.16-18.14-3.59-27.08-6.05-3.2-.87-6.32-2.03-9.53-2.84-1.43-.36-2.88-.66-4.23-1.23s-2.62-1.45-3.36-2.72c-.54-.95-.76-2.06-.73-3.15.04-1.09.31-2.17.7-3.19.78-2.04 2-3.88 2.78-5.92 1.19-3.08 1.34-6.47 1.12-9.76s-.8-6.56-1-9.85c-.08-1.48-.1-2.97.2-4.41.3-1.45.93-2.85 1.98-3.89 1.14-1.13 2.7-1.74 4.29-1.99 1.58-.24 3.19-.13 4.78.01 1.6.14 3.2.32 4.8.23 1.6-.1 3.22-.49 4.54-1.39 1.2-.81 2.1-2 2.79-3.27s1.18-2.64 1.71-3.98c.52-1.35 1.09-2.69 1.91-3.89.82-1.19 1.93-2.24 3.28-2.79" clip-path="url(#linux-ad)" filter="url(#linux-ae)"/><path fill="#f5bd0c" d="M35.99 174.57c1.22-.6 2.65-.72 3.98-.45s2.57.92 3.62 1.77c2.09 1.7 3.43 4.13 4.67 6.51 2.84 5.46 5.5 11.04 8.9 16.19 2.48 3.73 5.33 7.2 7.83 10.92 3.39 5.03 6.15 10.57 7.29 16.5.76 4 .74 8.31-1.18 11.9-1.27 2.37-3.32 4.31-5.75 5.52-2.42 1.22-5.21 1.71-7.92 1.47-4.27-.37-8.14-2.47-12.16-3.94-7.13-2.59-14.84-3.22-22.18-5.18-3.09-.82-6.13-1.89-9.26-2.54-1.39-.29-2.8-.5-4.12-1s-2.57-1.33-3.25-2.55c-.47-.86-.63-1.86-.56-2.84.07-.97.36-1.92.74-2.83.77-1.8 1.9-3.46 2.49-5.32.88-2.75.52-5.72-.14-8.53-.65-2.8-1.6-5.55-1.89-8.41-.13-1.27-.13-2.57.17-3.82.29-1.25.88-2.45 1.81-3.34 1.2-1.15 2.88-1.73 4.56-1.89 1.67-.16 3.35.06 5.01.3s3.34.5 5.01.42c1.68-.07 3.39-.51 4.7-1.54 1.3-1.02 2.12-2.53 2.59-4.09.47-1.57.62-3.2.81-4.82s.43-3.26 1.06-4.77 1.69-2.9 3.17-3.64" clip-path="url(#linux-ad)" filter="url(#linux-af)"/><path fill="url(#linux-ag)" d="M51.2 188.21c2.25 4.06 3.62 8.72 5.85 12.82 2.05 3.77 4.38 7.65 6.46 11.12.93 1.55 3.09 3.93 5.27 7.62 1.98 3.34 3.98 8.01 5.1 9.58-.64-1.84-1.96-6.77-3.54-10.28-1.47-3.28-3.19-5.15-4.24-6.92-2.08-3.47-4.33-6.6-6.47-9.91-2.95-4.57-5.2-9.68-8.43-14.03" clip-path="url(#linux-ad)" filter="url(#linux-ah)"/><path fill="url(#linux-ai)" d="M198.7 215.61c-.4 1.33-1.02 2.62-1.81 3.8-1.75 2.59-4.3 4.55-6.84 6.35-4.33 3.07-8.85 5.89-12.89 9.38-2.7 2.34-5.17 4.97-7.45 7.73-1.95 2.36-3.79 4.84-6.02 6.94-2.25 2.12-4.89 3.84-7.74 4.77-3.47 1.13-7.13 1.08-10.47.22-2.34-.6-4.63-1.64-6.08-3.53s-1.92-4.44-2.09-6.94c-.3-4.42.23-8.93.71-13.42.4-3.73.77-7.46.92-11.18.27-6.77-.18-13.47-1.09-20.05-.16-1.11-.32-2.22-.23-3.35.09-1.14.47-2.32 1.27-3.2.74-.81 1.77-1.29 2.79-1.52 1.02-.24 2.06-.25 3.09-.28 2.43-.06 4.86-.21 7.25.01 1.51.13 2.99.41 4.49.55 2.51.24 5.12.12 7.64-.62 2.71-.8 5.29-2.29 8.05-2.7 1.13-.17 2.26-.15 3.36.01 1.12.15 2.24.46 3.1 1.15.66.52 1.14 1.23 1.51 1.99.56 1.14.9 2.39 1.1 3.68.17 1.14.24 2.31.53 3.41.48 1.81 1.58 3.35 2.89 4.6 1.32 1.25 2.85 2.24 4.39 3.22 1.53.97 3.07 1.93 4.7 2.73.77.38 1.56.72 2.29 1.15.74.44 1.42.97 1.91 1.67.66.95.92 2.2.72 3.43" clip-path="url(#linux-O)" filter="url(#linux-aj)" opacity=".2"/><path id="linux-F" fill="url(#linux-ak)" d="M213.47 222.92c-2.26 2.68-5.4 4.45-8.53 6.05-5.33 2.71-10.86 5.1-15.87 8.37-3.36 2.19-6.46 4.76-9.36 7.53-2.48 2.37-4.83 4.9-7.61 6.91-2.81 2.03-6.05 3.5-9.48 4.01-.95.14-1.9.21-2.86.21-3.24 0-6.48-.78-9.46-2.08-2.7-1.17-5.3-2.86-6.86-5.36-1.56-2.52-1.92-5.59-1.92-8.56-.01-5.23.96-10.41 1.87-15.57.76-4.29 1.48-8.58 1.95-12.91.85-7.86.84-15.81.28-23.71-.1-1.32-.21-2.65-.01-3.96s.74-2.62 1.74-3.48c.93-.8 2.17-1.16 3.4-1.22 1.22-.07 2.44.12 3.65.3 2.85.42 5.73.74 8.52 1.48 1.76.46 3.48 1.08 5.23 1.56 2.94.79 6.01 1.17 9.02.82 3.25-.38 6.41-1.6 9.68-1.52 1.34.03 2.67.28 3.95.69 1.3.41 2.59 1 3.55 1.98.73.74 1.24 1.67 1.62 2.64.57 1.44.88 2.98 1.01 4.52.11 1.37.09 2.76.35 4.11.43 2.21 1.6 4.24 3.04 5.97 1.45 1.74 3.18 3.21 4.91 4.66s3.46 2.89 5.32 4.16c.87.6 1.77 1.16 2.6 1.81.83.66 1.59 1.42 2.11 2.34.45.81.69 1.72.69 2.65 0 .52-.07 1.04-.23 1.56-.45 1.43-1.28 2.82-2.3 4.04"/><path fill="#cd8907" d="M213.21 216.12c-.53 1.33-1.28 2.58-2.22 3.67-2.07 2.42-4.93 4.01-7.78 5.44-4.88 2.44-9.92 4.58-14.5 7.52-3.06 1.97-5.9 4.28-8.55 6.78-2.26 2.13-4.41 4.41-6.95 6.21-2.57 1.83-5.53 3.14-8.65 3.6-3.8.56-7.72-.16-11.25-1.67-2.46-1.06-4.84-2.56-6.27-4.83-1.42-2.26-1.75-5.02-1.75-7.69-.02-4.71.87-9.37 1.71-14 .7-3.85 1.36-7.71 1.78-11.6.76-7.08.73-14.22.25-21.32-.08-1.19-.17-2.39.01-3.57s.67-2.35 1.57-3.13c.85-.73 1.99-1.05 3.11-1.1 1.11-.06 2.22.12 3.33.28 2.61.38 5.23.67 7.78 1.33 1.61.42 3.18.98 4.78 1.4 2.68.72 5.49 1.06 8.24.74 2.97-.34 5.85-1.44 8.83-1.37 1.23.03 2.44.26 3.61.62 1.19.37 2.37.9 3.25 1.78.66.67 1.11 1.51 1.48 2.38.53 1.29.89 2.67.91 4.07.03 1.46-.28 2.92-.09 4.37.16 1.17.66 2.28 1.3 3.28.63 1 1.4 1.91 2.17 2.81 1.48 1.75 2.96 3.53 4.82 4.87 2.11 1.53 4.62 2.43 6.8 3.85.65.43 1.28.91 1.74 1.54.78 1.06.98 2.5.54 3.74" clip-path="url(#linux-al)" filter="url(#linux-am)"/><path fill="#f5c021" d="M212.91 214.61c-.6 1.35-1.37 2.6-2.28 3.71-2.12 2.58-4.99 4.35-8 5.49-4.97 1.88-10.39 2.13-15.26 4.27-2.97 1.3-5.65 3.26-8.36 5.12-2.18 1.49-4.42 2.94-6.82 3.98-2.72 1.19-5.6 1.85-8.5 2.32-1.84.29-3.71.51-5.57.41s-3.72-.54-5.37-1.49c-1.24-.72-2.36-1.75-3.03-3.1-.73-1.49-.86-3.24-.85-4.94.05-4.5 1.02-8.96.99-13.47-.03-3.93-.81-7.8-1.03-11.72-.43-7.54 1.19-15.2-.24-22.59-.22-1.19-.53-2.37-.52-3.58.01-.6.1-1.21.31-1.77.22-.55.56-1.06 1.01-1.42.39-.29.84-.47 1.31-.56.46-.08.94-.06 1.41.01.93.15 1.82.51 2.73.78 2.6.78 5.35.76 8 1.35 1.66.36 3.26.97 4.91 1.41 2.75.76 5.63 1.08 8.46.75 3.04-.36 6.01-1.46 9.07-1.38 1.26.03 2.5.26 3.71.62s2.42.87 3.34 1.8c.65.67 1.13 1.52 1.51 2.4.57 1.29.96 2.69.95 4.11-.01.74-.12 1.47-.19 2.21-.06.74-.08 1.49.09 2.2.18.72.55 1.37.97 1.96s.9 1.12 1.34 1.7c1.22 1.61 2.1 3.49 3.05 5.3s2.02 3.6 3.53 4.91c2.05 1.77 4.7 2.48 6.99 3.89.67.41 1.31.89 1.78 1.55.38.52.63 1.15.73 1.81.09.65.03 1.34-.17 1.96" clip-path="url(#linux-al)" filter="url(#linux-an)"/><path fill="url(#linux-ao)" d="M148.08 181.58c2.82-.76 5.22 1.38 7.27 2.99 1.32 1.13 3.24.85 4.86.9 2.69-.09 5.36.45 8.05.12 5.3-.45 10.49-1.75 15.81-1.97 2.54-.16 5.4-.31 7.59 1.17.89.62 2.2 3.23 3.07 2.25-.36-2.74-2.39-5.39-5.11-6.12-2.14-.34-4.3.25-6.46.06-6.39-.15-12.75-1.34-19.16-1-4.46.04-8.91-.17-13.37-.34-1.75-.36-2.37 1.19-3.32 1.79.25.19.34.25.77.15" clip-path="url(#linux-al)" filter="url(#linux-ap)"/><path fill="url(#linux-aq)" d="M185.49 187.61c-.48-.95-1.36-1.66-2.35-2.07-.98-.41-2.06-.55-3.13-.54-2.13.02-4.25.57-6.38.39-1.79-.16-3.49-.83-5.24-1.26-1.81-.44-3.73-.61-5.52-.12-1.92.52-3.61 1.81-4.67 3.49-.94 1.48-1.38 3.23-1.52 4.98s.01 3.5.19 5.25c.12 1.26.27 2.52.57 3.75.31 1.23.78 2.43 1.52 3.46 1.07 1.48 2.66 2.54 4.37 3.17 2.8 1.03 5.98.98 8.73-.15 4.88-2.12 9.01-5.92 11.52-10.6.91-1.68 1.61-3.47 2.06-5.31.18-.74.32-1.49.32-2.25.01-.75-.12-1.52-.47-2.19" clip-path="url(#linux-al)" filter="url(#linux-ar)" opacity=".35"/><path fill="url(#linux-as)" d="M185.49 184.89c-.48-.69-1.36-1.2-2.35-1.5-.98-.3-2.06-.39-3.13-.39-2.13.02-4.25.42-6.38.28-1.79-.11-3.49-.6-5.24-.9-1.81-.32-3.73-.45-5.52-.09-1.92.37-3.61 1.3-4.67 2.52-.94 1.07-1.38 2.34-1.52 3.6s.01 2.53.19 3.79c.12.91.27 1.83.57 2.72.31.89.78 1.76 1.52 2.5 1.07 1.07 2.66 1.83 4.37 2.29 2.8.75 5.98.71 8.73-.11 4.88-1.53 9.01-4.28 11.52-7.66.91-1.22 1.61-2.51 2.06-3.84.18-.54.32-1.08.32-1.62.01-.55-.12-1.11-.47-1.59" clip-path="url(#linux-al)" filter="url(#linux-at)" opacity=".35"/><path id="linux-G" fill="#020204" d="M189.55 178.72c-.35-.95-.97-1.79-1.72-2.47s-1.64-1.2-2.57-1.6c-1.86-.79-3.89-1.09-5.89-1.46-1.87-.35-3.74-.78-5.62-1.1-1.96-.33-3.98-.55-5.92-.11-1.69.38-3.26 1.26-4.54 2.43s-2.28 2.63-3 4.21c-1.27 2.79-1.67 5.92-1.43 8.97.18 2.27.76 4.61 2.25 6.32 1.21 1.39 2.92 2.26 4.68 2.78 3.04.9 6.35.85 9.36-.13a24.7 24.7 0 0 0 12.35-9.29c.98-1.43 1.82-2.98 2.2-4.66.29-1.28.3-2.66-.15-3.89"/><defs><path id="linux-au" d="M168.89 171.07c-.47.03-.93.08-1.4.17-2.99.53-5.73 2.42-7.27 5.03-1.09 1.85-1.58 4.03-1.43 6.17.07-1.5.46-2.97 1.19-4.28 1.23-2.23 3.47-3.91 5.98-4.37 1.54-.28 3.13-.11 4.68.08 1.5.19 3 .39 4.47.7 2.28.5 4.53 1.26 6.44 2.59.44.31.86.66 1.21 1.08.35.41.62.89.73 1.42.15.78-.07 1.6-.46 2.29-.39.7-.92 1.3-1.48 1.86-.46.46-.94.89-1.43 1.32 2.21-.43 4.44-1.03 6.28-2.31.77-.55 1.48-1.2 1.94-2.02.46-.83.65-1.83.43-2.75-.16-.62-.5-1.19-.92-1.67s-.93-.87-1.45-1.24a17.3 17.3 0 0 0-7.81-2.99c-1.8-.33-3.61-.61-5.42-.83-1.41-.18-2.86-.33-4.28-.25"/></defs><use xlink:href="#linux-au" fill="url(#linux-av)" clip-path="url(#linux-aw)" filter="url(#linux-ax)" href="#linux-au"/><use xlink:href="#linux-au" fill="url(#linux-ay)" clip-path="url(#linux-aw)" filter="url(#linux-ax)" href="#linux-au"/><path id="linux-H" fill="url(#linux-az)" d="M84.45 38.28c-1.53.08-3 .79-4.12 1.84-1.13 1.05-1.92 2.43-2.41 3.88-.97 2.92-.75 6.08-.53 9.15.2 2.77.41 5.6 1.45 8.18.52 1.3 1.25 2.51 2.22 3.51.97.99 2.2 1.76 3.55 2.09 1.26.32 2.62.26 3.86-.13 1.25-.4 2.38-1.11 3.32-2.02 1.36-1.33 2.27-3.07 2.8-4.9s.68-3.75.65-5.66c-.04-2.38-.35-4.77-1.09-7.03-.75-2.26-1.94-4.4-3.6-6.11-.8-.83-1.72-1.55-2.75-2.06-1.04-.51-2.2-.8-3.35-.74"/><path id="linux-I" fill="#020204" d="M80.75 50.99c-.32 1.94-.33 3.97.33 5.81.44 1.22 1.17 2.33 2.05 3.28.57.62 1.23 1.18 1.99 1.55.77.37 1.65.52 2.48.32.76-.19 1.42-.68 1.91-1.29s.82-1.34 1.05-2.09c.69-2.21.58-4.62-.11-6.83-.49-1.61-1.32-3.16-2.6-4.24-.62-.52-1.34-.93-2.12-1.11-.78-.19-1.63-.14-2.36.19-.81.37-1.44 1.07-1.85 1.86s-.62 1.67-.77 2.55"/><path fill="url(#linux-aA)" d="M84.84 49.59c.21.55.91.75 1.3 1.19.37.42.76.87.97 1.4.39 1.01-.39 2.51.43 3.23.25.22.77.23 1.02 0 .99-.9.77-2.71.38-3.99-.36-1.15-1.23-2.25-2.31-2.8-.5-.26-1.25-.47-1.68-.11-.27.24-.24.74-.11 1.08" clip-path="url(#linux-aB)" filter="url(#linux-aC)"/><path fill="url(#linux-aD)" d="M81.14 44.46c2.32-1.38 5.13-1.7 7.82-1.45 2.68.26 5.27 1.04 7.87 1.75 1.91.52 3.84 1 5.63 1.84 1.78.84 3.44 2.08 4.43 3.8.16.27.29.56.46.83s.37.52.62.71.57.32.88.3c.16-.01.32-.05.45-.13.14-.08.26-.2.33-.34.08-.16.11-.35.1-.53s-.05-.36-.1-.54c-.65-2.37-2.19-4.38-3.35-6.55-.7-1.3-1.28-2.66-1.98-3.96-2.43-4.45-6.42-7.94-10.95-10.21s-9.59-3.36-14.65-3.65c-5.86-.35-11.73.35-17.51 1.37-2.51.44-5.06.96-7.27 2.21-1.11.62-2.13 1.42-2.92 2.42-.8.99-1.36 2.18-1.55 3.44-.17 1.22.01 2.47.44 3.62.42 1.15 1.08 2.2 1.86 3.15 1.54 1.91 3.53 3.39 5.36 5.03 1.83 1.63 3.52 3.44 5.57 4.79 1.02.68 2.13 1.24 3.31 1.57s2.44.42 3.64.17c1.24-.25 2.4-.86 3.41-1.64 1.01-.77 1.88-1.7 2.71-2.66 1.66-1.93 3.21-4.04 5.39-5.34" clip-path="url(#linux-aE)"/><path fill="url(#linux-aF)" d="M90.77 36.57c2.16 2.02 3.76 4.52 4.85 7.16-.48-2.91-1.23-5.26-3.13-7.16-1.16-1.09-2.49-2.05-3.98-2.72-1.32-.59-2.77-.96-3.61-.97-.83-.02-1.03 0-1.2.01-.18.01-.31.01.23.08.54.06 1.75.39 3.05.97s2.62 1.54 3.79 2.63" filter="url(#linux-aG)"/><path id="linux-J" fill="url(#linux-aH)" d="M111.61 38.28c-2.39 1.65-4.4 3.94-5.38 6.68-1.24 3.45-.77 7.31.43 10.77 1.22 3.55 3.27 6.93 6.36 9.06 1.54 1.07 3.33 1.8 5.19 2.02 1.87.22 3.8-.09 5.47-.95 2.02-1.06 3.57-2.91 4.53-4.98.96-2.08 1.37-4.37 1.5-6.66.16-2.9-.12-5.86-1.08-8.61-1.04-2.99-2.92-5.75-5.58-7.47-1.32-.86-2.83-1.45-4.4-1.67a9.4 9.4 0 0 0-4.67.52c-.84.33-1.62.78-2.37 1.29"/><path id="linux-K" fill="#020204" d="M117.14 45.52c-.9.06-1.78.37-2.55.85-.76.48-1.41 1.13-1.92 1.88-1.03 1.49-1.48 3.31-1.55 5.12-.05 1.35.1 2.72.55 4s1.2 2.47 2.25 3.33c1.07.89 2.42 1.42 3.81 1.49 1.39.06 2.79-.34 3.93-1.13.91-.63 1.64-1.5 2.16-2.48.52-.97.84-2.05.98-3.15.25-1.93-.03-3.95-.93-5.69-.89-1.74-2.41-3.17-4.24-3.84-.8-.29-1.65-.44-2.49-.38"/><path fill="url(#linux-aI)" d="M122.71 53.36c1-1-.71-3.65-2.05-4.74-.97-.78-3.78-1.61-3.66-.75.12.85 1.39 1.95 2.23 2.79 1.05 1.03 3 3.18 3.48 2.7" clip-path="url(#linux-aJ)" filter="url(#linux-aK)"/><path fill="url(#linux-aL)" d="M102.56 47.01c2.06-1.71 4.45-3.01 7-3.8 5.25-1.62 11.2-.98 15.84 1.97 1.6 1.01 3.03 2.27 4.52 3.45 1.48 1.17 3.06 2.27 4.85 2.9.97.34 2 .54 3.02.43.92-.09 1.81-.44 2.57-.96.76-.53 1.4-1.23 1.88-2.02.96-1.58 1.27-3.5 1.1-5.34-.33-3.69-2.41-6.94-4.15-10.21-.55-1.02-1.07-2.06-1.73-3.01-2.01-2.93-5.23-4.86-8.6-5.99s-6.93-1.54-10.46-1.98c-1.58-.2-3.17-.41-4.74-.22-1.81.22-3.51.95-5.28 1.4-.84.22-1.69.37-2.52.61s-1.65.57-2.33 1.11c-.98.79-1.6 1.98-1.87 3.21-.27 1.24-.21 2.52-.01 3.77.39 2.5 1.33 4.93 1.24 7.46-.06 1.73-.61 3.44-.54 5.17.02.51.12 1.55.21 2.05" clip-path="url(#linux-aM)"/><path fill="url(#linux-aN)" d="M119.93 31.18c-.41.52-.78 1.08-1.07 1.7 1.85.4 3.61 1.16 5.19 2.21 3.06 2.03 5.38 4.99 7.01 8.29.38-.42.72-.87 1.02-1.37-1.64-3.44-4-6.55-7.16-8.65-1.52-1-3.21-1.77-4.99-2.18" filter="url(#linux-aO)"/><path fill-opacity=".259" d="M81.12 89.33c1.47 4.26 4.42 7.89 7.92 10.72 1.16.95 2.39 1.82 3.76 2.43 1.36.62 2.87.97 4.36.84 1.46-.12 2.85-.7 4.13-1.42s2.46-1.59 3.7-2.37c2.12-1.35 4.39-2.44 6.6-3.64 2.65-1.45 5.23-3.1 7.46-5.14 1.03-.93 1.98-1.95 3.11-2.75 1.13-.81 2.49-1.39 3.87-1.29 1.04.07 2.01.51 3.03.73.51.11 1.03.16 1.55.08.51-.08 1.01-.29 1.37-.67.44-.46.64-1.12.61-1.76-.02-.63-.24-1.25-.54-1.81-.59-1.13-1.49-2.1-1.89-3.31-.36-1.08-.29-2.24-.26-3.37.03-1.14.01-2.32-.51-3.33-.4-.76-1.07-1.37-1.83-1.77-.76-.41-1.62-.62-2.48-.7-1.72-.16-3.44.18-5.17.27-2.28.13-4.58-.15-6.87-.02-2.85.18-5.65 1-8.51 1.01-3.26.01-6.52-1.06-9.74-.55-1.39.22-2.71.72-4.03 1.16-1.33.45-2.7.84-4.1.82-1.59-.03-3.13-.58-4.72-.69-.79-.06-1.6 0-2.35.28-.74.28-1.41.79-1.78 1.5-.21.4-.31.86-.33 1.31-.02.46.04.91.15 1.36.22.88.63 1.71.96 2.55 1.2 3.07 1.46 6.42 2.53 9.53" clip-path="url(#linux-O)" filter="url(#linux-aP)"/><path d="M77.03 77.2c2.85 1.76 5.41 3.93 7.56 6.39 1.99 2.29 3.68 4.89 6.29 6.58 1.83 1.2 4.04 1.87 6.28 2.08 2.63.24 5.29-.15 7.83-.84 2.35-.63 4.62-1.53 6.7-2.71 3.97-2.25 7.28-5.55 11.65-7.03.95-.33 1.94-.56 2.86-.96.92-.39 1.79-.99 2.23-1.83.42-.82.4-1.75.54-2.64.15-.96.48-1.88.66-2.83s.2-1.96-.24-2.83c-.37-.72-1.04-1.29-1.81-1.66-.77-.36-1.64-.52-2.51-.56-1.72-.08-3.43.33-5.16.47-2.28.19-4.58-.08-6.87-.01-2.85.08-5.66.67-8.51.8-3.25.14-6.49-.34-9.74-.44-1.41-.05-2.83-.03-4.21.2-1.39.22-2.75.65-3.92 1.37-1.14.69-2.07 1.64-3.11 2.45-.52.41-1.08.78-1.68 1.07-.61.28-1.28.48-1.96.51-.35.01-.71-.01-1.05.04-.59.08-1.13.39-1.47.83-.34.45-.47 1.02-.36 1.55" clip-path="url(#linux-O)" filter="url(#linux-aQ)" opacity=".3"/><path fill="url(#linux-aR)" d="M91.66 58.53c1.53-1.71 2.57-3.8 4.03-5.56.73-.88 1.58-1.69 2.57-2.26s2.15-.89 3.29-.79c1.27.11 2.46.74 3.39 1.61s1.62 1.97 2.17 3.12c.53 1.11.95 2.28 1.71 3.24.81 1.02 1.94 1.71 2.97 2.52.51.4 1.01.83 1.41 1.34.41.51.72 1.1.86 1.74.13.65.06 1.33-.16 1.95-.23.62-.61 1.18-1.09 1.64-.95.92-2.25 1.42-3.56 1.6-2.62.37-5.27-.41-7.92-.34-2.67.08-5.29 1.02-7.97.93-1.33-.05-2.69-.38-3.79-1.14-.55-.39-1.03-.88-1.38-1.45a4.1 4.1 0 0 1-.58-1.9c-.02-.64.13-1.28.39-1.86.25-.59.61-1.12 1.01-1.62.81-.99 1.8-1.81 2.65-2.77"/><path id="linux-L" fill="url(#linux-aS)" d="M77.14 75.05c.06.26.15.5.28.73.23.38.57.69.93.95.36.27.75.49 1.13.72 2.01 1.27 3.65 3.04 5.11 4.92 1.95 2.52 3.68 5.31 6.29 7.14 1.84 1.3 4.04 2.03 6.28 2.26 2.63.26 5.29-.16 7.83-.91 2.35-.69 4.62-1.66 6.7-2.95 3.97-2.44 7.28-6.02 11.65-7.63.95-.35 1.94-.6 2.86-1.03.92-.44 1.79-1.08 2.23-2 .42-.88.4-1.9.54-2.87.15-1.03.48-2.03.66-3.06s.2-2.13-.24-3.08c-.37-.78-1.04-1.4-1.81-1.79-.77-.4-1.64-.58-2.51-.62-1.72-.08-3.43.36-5.16.52-2.28.21-4.58-.09-6.87-.02-2.85.09-5.66.73-8.51.87-3.25.15-6.49-.35-9.74-.48-1.41-.06-2.83-.04-4.22.2-1.39.23-2.75.71-3.91 1.51-1.13.78-2.03 1.84-3.07 2.74-.52.45-1.08.86-1.7 1.16-.61.3-1.29.49-1.98.47-.35-.01-.72-.06-1.05.04-.21.07-.4.2-.56.35-.16.16-.29.34-.41.52-.29.42-.54.87-.75 1.34"/><path fill="#d9b30d" d="M89.9 78.56a5.77 5.77 0 0 0 .56 4.11c.68 1.24 1.84 2.2 3.19 2.65 1.7.57 3.62.29 5.21-.54.93-.48 1.77-1.16 2.3-2.06.27-.44.46-.94.53-1.46.06-.51.02-1.05-.16-1.54-.2-.53-.56-1-.99-1.37a4.5 4.5 0 0 0-1.5-.82c-1.08-.36-2.77-.66-3.91-.68-2.02-.04-4.9.34-5.23 1.71" clip-path="url(#linux-aT)" filter="url(#linux-aU)"/><path fill="#604405" d="M84.31 67.86c-1.16.68-2.27 1.43-3.36 2.2-.57.41-1.15.84-1.45 1.47-.21.44-.26.94-.27 1.43 0 .5.03.99-.04 1.48-.04.33-.13.66-.14.99-.01.17 0 .34.04.5.05.16.13.32.24.44.15.16.35.26.56.32s.42.09.64.14c1.01.24 1.89.86 2.66 1.56.77.69 1.47 1.48 2.28 2.13 2.18 1.78 5.07 2.52 7.89 2.56 2.82.05 5.61-.54 8.36-1.16 2.16-.49 4.32-.99 6.39-1.76 3.2-1.18 6.16-2.96 8.72-5.19 1.17-1.01 2.26-2.12 3.57-2.94 1.15-.73 2.44-1.21 3.62-1.9.11-.06.21-.13.3-.2.1-.08.18-.18.24-.28.09-.19.09-.42.03-.62s-.18-.38-.31-.55c-.15-.18-.31-.34-.49-.5-1.23-1.05-2.89-1.43-4.51-1.56-1.61-.12-3.24-.03-4.83-.3-1.5-.25-2.92-.81-4.37-1.27-1.52-.49-3.07-.87-4.64-1.13-3.71-.61-7.52-.49-11.19.27-3.49.73-6.87 2.05-9.94 3.87" clip-path="url(#linux-aT)" filter="url(#linux-aV)"/><path id="linux-M" fill="url(#linux-aW)" d="M83.94 63.95a20.8 20.8 0 0 0-4.43 4.04c-.72.89-1.38 1.86-1.74 2.94-.29.86-.39 1.76-.57 2.65-.07.33-.15.66-.14 1 0 .16.02.33.07.5.05.16.14.31.25.43.2.2.47.31.74.37.28.05.56.06.84.09 1.25.15 2.4.75 3.44 1.47 1.04.71 2 1.55 3.07 2.22 2.35 1.49 5.16 2.15 7.95 2.26 2.78.11 5.56-.31 8.3-.86 2.17-.43 4.33-.95 6.39-1.76 3.16-1.25 6.01-3.16 8.72-5.19 1.24-.92 2.46-1.87 3.57-2.94.37-.37.74-.74 1.14-1.08.4-.33.85-.62 1.35-.78.76-.24 1.58-.17 2.37-.04.59.1 1.18.23 1.78.21.3-.02.6-.07.88-.18s.54-.28.73-.52c.25-.3.38-.7.38-1.09 0-.4-.12-.79-.32-1.13-.4-.68-1.09-1.14-1.81-1.46-.99-.44-2.06-.65-3.11-.91-3.23-.78-6.37-1.93-9.34-3.41-1.48-.73-2.92-1.54-4.37-2.32-1.5-.8-3.02-1.57-4.64-2.07-3.64-1.1-7.6-.74-11.19.51a23.9 23.9 0 0 0-10.31 7.05"/><path fill="#f6da4a" d="M109.45 64.75c-.2-.24-.48-.42-.78-.51s-.62-.09-.93-.04c-.62.11-1.18.44-1.7.8-1.47 1.01-2.77 2.26-3.91 3.64-1.5 1.83-2.74 3.94-3.16 6.27-.07.39-.11.8-.07 1.19.05.4.2.79.49 1.07.24.25.58.4.92.45.35.05.71 0 1.04-.11.66-.22 1.21-.69 1.74-1.15 2.87-2.58 5.47-5.66 6.51-9.38.1-.37.19-.75.19-1.14s-.1-.78-.34-1.09" clip-path="url(#linux-aX)" filter="url(#linux-aY)"/><path fill="url(#linux-aZ)" d="M92.72 59.06c-.77-.25-2.03 1.1-1.62 1.79.11.19.46.43.7.3.35-.19.64-.89 1.02-1.16.25-.18.2-.84-.1-.93" filter="url(#linux-ba)" opacity=".8"/><path fill="url(#linux-bb)" d="M102.56 59.42c.2.64 1.23.53 1.83.84.52.27.94.86 1.53.88.56.01 1.44-.2 1.51-.76.09-.73-.98-1.2-1.67-1.47-.89-.34-2.03-.52-2.86-.06-.19.11-.4.36-.34.57" filter="url(#linux-bc)" opacity=".8"/><path fill="url(#linux-bd)" d="M129.27 69.15a2.42 3.1 16.94 0 1-2.81 3.04 2.42 3.1 16.94 0 1-2.12-3.04 2.42 3.1 16.94 0 1 2.81-3.05 2.42 3.1 16.94 0 1 2.12 3.05" clip-path="url(#linux-be)" filter="url(#linux-bf)"/></svg>',
    'truenas': '<svg viewBox="0 10 90 71" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" role="img" aria-hidden="true"><g fill="none"><path fill="#31BEEC" d="M90 38.197v19.137L48.942 80.999V61.864z"/><path fill="#0095D5" d="M41.086 61.863V81L0 57.333V38.197l18.566 10.687q.03.025.067.04z"/><path fill="#AEADAE" d="m61.621 45.506-16.607 9.576-16.622-9.576 16.622-9.575z"/><path fill="#0095D5" d="M86.086 31.416 69.464 40.99 48.942 29.15V10z"/><path fill="#31BEEC" d="M41.086 10v19.15l-20.55 11.827-16.621-9.561z"/></g></svg>',
}

def _brand_logo(key: str) -> str:
    return _BRAND_LOGOS[key]



def _http_toolkit_yaml(
    key: str, *, port: int, path_prefixes: list[str], header: str | None,
    methods: list[str] = ("GET", "POST"), credential_kind: str = "api_key_header",
    credential: bool = True, scheme: str = "http",
) -> str:
    prefixes = "\n".join(f'      - "{p}"' for p in path_prefixes)
    methods_line = ", ".join(f'"{m}"' for m in methods)
    if not credential:
        # Netdata: no auth by default. Still a valid toolkit -- `credential`
        # on `Toolkit` is optional (execute_http.py only resolves one when
        # `toolkit.credential` is set), the same as any http toolkit that
        # simply doesn't need one.
        credential_block = (
            "    # This service has no auth by default; add 'credential: "
            f"{key}' (kind=bearer) here if you've enabled bearer_protection.\n"
        )
    elif credential_kind == "url_query":
        # SABnzbd's classic API has no header option at all -- the one
        # other documented exception to FR-8.14 besides Telegram's
        # url_path, this time on the query side (url_query, credentials.py).
        credential_block = (
            f"    credential: {key}\n"
            f"    # kind=url_query: injected as '?{header}=...' -- this service "
            "has no header-auth option (FR-8.14's preferred path), so gatekeeper "
            "falls back to its one documented query-param exception.\n"
        )
    else:
        credential_block = (
            f"    credential: {key}\n"
            f"    # Sends the credential as '{header}'. Never as a ?apikey= query "
            "param (FR-8.14) -- that would end up in the target's access logs.\n"
        )
    return (
        f"  {key}:\n"
        "    executor: http\n"
        f'    base_url: "{scheme}://CHANGEME:{port}"\n'
        f"    allowed_methods: [{methods_line}]\n"
        "    allowed_path_prefixes:\n"
        f"{prefixes}\n"
        "    allowed_cidrs:\n"
        # 203.0.113.0/24 is RFC 5737 TEST-NET-3, reserved for documentation --
        # a syntactically valid placeholder that can never resolve to a real
        # host, so a copy-pasted-but-unedited block fails closed rather than
        # silently allowing an unintended address.
        '      - "203.0.113.1/32"  # CHANGEME -- e.g. 192.168.1.42/32, this one host\n'
        f"{credential_block}"
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


def _tool_argv(
    tool_id: str, *, toolkit: str, title: str, description: str, binary: str,
    argv: list[str], category: str = "read", idempotent: bool = True,
    parameters: dict[str, Any] | None = None, required_scopes: list[str] | None = None,
    timeout_seconds: int = 15, max_output_bytes: int = 65536,
) -> dict[str, Any]:
    """The `docker`/`local`/`ssh`-shaped counterpart to `_tool()` above --

    binary + argv (FR-5.3/5.4) instead of method + path.
    """
    return {
        "id": tool_id, "toolkit": toolkit, "version": 1, "title": title,
        "description": description, "category": category, "idempotent": idempotent,
        "enabled": False, "binary": binary, "argv": argv,
        "parameters": parameters or {}, "required_scopes": required_scopes or [],
        "timeout_seconds": timeout_seconds, "max_output_bytes": max_output_bytes,
    }


#: The *-arr apps and Jellyfin share one auth shape: an API key in a
#: fixed header name, key query param also accepted by the target but
#: never used by gatekeeper (FR-8.14).
_ARR_QUERY_PARAM = {"api_key_header": "X-Api-Key"}

_INTEGRATIONS_LIST: list[Integration] = [
    Integration(
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
    Integration(
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
    Integration(
        key="jellyfin",
        display_name="Jellyfin",
        logo_svg=_brand_logo("jellyfin"),
        toolkit_yaml=_http_toolkit_yaml(
            "jellyfin", port=8096, path_prefixes=["/Library", "/Sessions"],
            header="X-Emby-Token", methods=["GET"],
        ),
        credential_kind="api_key_header",
        notes="Read-only in this integration, matching the v1 toolkit catalog.",
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
    Integration(
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
    Integration(
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
    Integration(
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
    Integration(
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
    Integration(
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
    Integration(
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
            "This integration targets its read-only status-page JSON endpoint "
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
    Integration(
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
    Integration(
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
    Integration(
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
            "and are NOT covered by this integration -- gatekeeper's v1 http executor "
            "supports static credentials only (FR-8.11), no authorization-code "
            "flow. This integration is scoped to API-key-eligible APIs such as "
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
    Integration(
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
    Integration(
        key="pfsense",
        display_name="pfSense",
        logo_svg=_brand_logo("pfsense"),
        toolkit_yaml=_http_toolkit_yaml(
            "pfsense", port=443, path_prefixes=["/api/v2/"], header="X-API-Key",
            scheme="https",
        ),
        credential_kind="api_key_header",
        notes=(
            "Targets the community 'pfSense REST API' package (pfrest.org, "
            "formerly jaredhendrickson13/pfsense-api) -- not a built-in "
            "pfSense feature; install it as a pfSense package first. "
            "Endpoint naming has changed across package versions -- verify "
            "paths against your installed version's own /api/v2 docs "
            "(Swagger UI at /api/v2/documentation) before relying on these."
        ),
        tool_specs=(
            _tool(
                "pfsense.list_firewall_rules", toolkit="pfsense",
                title="List firewall rules",
                description="Lists configured firewall rules.",
                method="GET", path="/api/v2/firewall/rules",
            ),
            _tool(
                "pfsense.list_interfaces", toolkit="pfsense", title="List interfaces",
                description="Lists configured network interfaces and their status.",
                method="GET", path="/api/v2/interface",
            ),
        ),
    ),
    Integration(
        key="jellystat",
        display_name="Jellystat",
        logo_svg=_monogram("Js", "#8e44ad"),
        toolkit_yaml=_http_toolkit_yaml(
            "jellystat", port=3000, path_prefixes=["/stats/", "/api/"],
            header="x-api-token",
        ),
        credential_kind="api_key_header",
        notes="Generate the API key under Jellystat's own Settings -> API Keys page.",
        tool_specs=(
            _tool(
                "jellystat.library_overview", toolkit="jellystat",
                title="Library overview",
                description="Summary watch/item stats per Jellyfin library.",
                method="GET", path="/stats/getLibraryOverview",
            ),
            _tool(
                "jellystat.libraries", toolkit="jellystat", title="List libraries",
                description="Lists tracked Jellyfin libraries.",
                method="GET", path="/api/getLibraries",
            ),
            _tool(
                "jellystat.recently_added", toolkit="jellystat",
                title="Recently added",
                description="Lists recently added media across tracked libraries.",
                method="GET", path="/api/getRecentlyAdded",
            ),
        ),
    ),
    Integration(
        key="netdata",
        display_name="Netdata",
        logo_svg=_brand_logo("netdata"),
        toolkit_yaml=_http_toolkit_yaml(
            "netdata", port=19999, path_prefixes=["/api/v1/"], header=None,
            methods=["GET"], credential=False,
        ),
        credential_kind="bearer",
        notes=(
            "Unauthenticated by default on the local agent -- only needed "
            "if you've enabled 'bearer_protection' (Netdata's own setting); "
            "add a 'credential:' line and set kind=bearer here if so."
        ),
        tool_specs=(
            _tool(
                "netdata.info", toolkit="netdata", title="Agent info",
                description="Netdata agent version, host, and basic info.",
                method="GET", path="/api/v1/info",
            ),
            _tool(
                "netdata.charts", toolkit="netdata", title="List charts",
                description="Lists all metric charts available on this node.",
                method="GET", path="/api/v1/charts",
            ),
            _tool(
                "netdata.chart_data", toolkit="netdata", title="Chart data",
                description="Reads recent data points for one chart.",
                method="GET", path="/api/v1/data",
                query={"chart": "{chart}"},
                parameters={
                    "chart": {"type": "string", "required": True,
                               "pattern": "^[A-Za-z0-9_.:-]{1,128}$",
                               "description": "Chart ID, e.g. system.cpu."},
                },
            ),
        ),
    ),
    Integration(
        key="sabnzbd",
        display_name="SABnzbd",
        logo_svg=_brand_logo("sabnzbd"),
        toolkit_yaml=_http_toolkit_yaml(
            "sabnzbd", port=8080, path_prefixes=["/api"], header="apikey",
            credential_kind="url_query",
        ),
        credential_kind="url_query",
        notes=(
            "SABnzbd's classic API has no header-auth option at all -- the "
            "key must be sent as '?apikey=' (credentials.py's url_query "
            "kind: FR-8.14's one other documented exception besides "
            "Telegram's url_path)."
        ),
        tool_specs=(
            _tool(
                "sabnzbd.queue", toolkit="sabnzbd", title="Queue status",
                description="Lists queued downloads and their progress.",
                method="GET", path="/api",
                query={"mode": "queue", "output": "json"},
            ),
            _tool(
                "sabnzbd.history", toolkit="sabnzbd", title="History",
                description="Lists completed and failed downloads.",
                method="GET", path="/api",
                query={"mode": "history", "output": "json"},
            ),
            _tool(
                "sabnzbd.add_url", toolkit="sabnzbd", title="Add NZB by URL",
                description=(
                    "Queues a new download from an NZB URL. Not idempotent -- "
                    "calling again queues a second download."
                ),
                method="GET", path="/api", category="write", idempotent=False,
                query={"mode": "addurl", "output": "json", "name": "{url}"},
                parameters={
                    "url": {"type": "string", "required": True,
                             "pattern": "^https?://.{1,500}$",
                             "description": "URL of the .nzb file to queue."},
                },
            ),
        ),
    ),
    Integration(
        key="paperless",
        display_name="Paperless-ngx",
        logo_svg=_brand_logo("paperless"),
        toolkit_yaml=_http_toolkit_yaml(
            "paperless", port=8000, path_prefixes=["/api/documents/"],
            header="Authorization",
        ),
        credential_kind="api_key_header",
        notes=(
            "Store the credential value as 'Token <your-api-token>' "
            "(including the word Token, generated under Paperless-ngx's own "
            "Django admin or via 'python manage.py drf_create_token') -- it "
            "expects 'Authorization: Token <token>', not the Bearer scheme, "
            "and gatekeeper's api_key_header kind sends the value verbatim."
        ),
        tool_specs=(
            _tool(
                "paperless.list_documents", toolkit="paperless",
                title="List documents",
                description="Lists documents, most recently added first.",
                method="GET", path="/api/documents/",
            ),
            _tool(
                "paperless.search", toolkit="paperless", title="Search documents",
                description="Full-text search across document title and content.",
                method="GET", path="/api/documents/",
                query={"query": "{query}"},
                parameters={
                    "query": {"type": "string", "required": True,
                               "pattern": "^.{1,200}$", "description": "Search text."},
                },
            ),
        ),
    ),
    Integration(
        key="docker",
        display_name="Docker",
        logo_svg=_brand_logo("docker"),
        # Mirrors config/examples/toolkits.yaml's own 'docker' entry --
        # not http-shaped: binaries/denied_args/path_roots, the same
        # allowlist model as `local`, executed via the mounted socket.
        toolkit_yaml=(
            "  docker:\n"
            "    executor: docker\n"
            '    binaries: ["/usr/bin/docker"]\n'
            "    denied_args:\n"
            "      - rm\n"
            "      - kill\n"
            "      - exec\n"
            "      - build\n"
            "      - push\n"
            "      - login\n"
            "      - system\n"
            "      - prune\n"
            "      - cp\n"
            "      - --privileged\n"
            "      - --force\n"
            "      - -v\n"
            "      - --volumes\n"
            "      - --rmi\n"
            "    path_roots:\n"
            '      - "/mnt/raid"   # CHANGEME -- where your compose.yaml files live\n'
            "    protected_resources:\n"
            '      - "gatekeeper"   # CHANGEME -- stacks that must never be touched\n'
            "    max_timeout_seconds: 300\n"
            "    max_output_bytes: 262144\n"
        ),
        credential_kind="docker_tls",
        notes=(
            "Uses the mounted Docker socket by default -- no credential "
            "needed. Add 'credential: <name>' (kind=docker_tls) plus "
            "'docker_host'/'docker_tls: true' only for a remote, "
            "TLS-secured daemon instead (FR-8.3g). See "
            "config/examples/toolkits.yaml and tools.yaml for the full "
            "worked docker.compose_* example these starter tools mirror."
        ),
        tool_specs=(
            _tool_argv(
                "docker.compose_ps", toolkit="docker", title="Stack status",
                description=(
                    "State of a compose stack's containers as JSON records. Read-only."
                ),
                binary="/usr/bin/docker",
                argv=["compose", "-p", "{stack}", "-f", "{compose_path}", "ps",
                      "--format", "json"],
                parameters={
                    "stack": {"type": "string", "required": True,
                               "pattern": "^[a-z0-9][a-z0-9_-]{0,62}$",
                               "description": "Stack name, matching a directory under path_roots."},
                    "compose_path": {
                        "type": "path", "derived": "/mnt/raid/{stack}/compose.yaml",
                        "must_resolve_under": "/mnt/raid",
                        "description": "Built by the server from the stack name.",
                    },
                },
                required_scopes=["stack:{stack}"],
                timeout_seconds=30, max_output_bytes=65536,
            ),
            _tool_argv(
                "docker.compose_up", toolkit="docker", title="Start stack",
                description=(
                    "Starts or updates a compose stack ('docker compose up -d'). "
                    "Idempotent -- calling it again on a running stack has no effect."
                ),
                binary="/usr/bin/docker",
                argv=["compose", "-p", "{stack}", "-f", "{compose_path}", "up", "-d"],
                category="write",
                parameters={
                    "stack": {"type": "string", "required": True,
                               "pattern": "^[a-z0-9][a-z0-9_-]{0,62}$",
                               "description": "Stack name."},
                    "compose_path": {
                        "type": "path", "derived": "/mnt/raid/{stack}/compose.yaml",
                        "must_resolve_under": "/mnt/raid",
                        "description": "Built by the server.",
                    },
                },
                required_scopes=["stack:{stack}"],
                timeout_seconds=180, max_output_bytes=65536,
            ),
        ),
    ),
    Integration(
        key="linux",
        display_name="Linux",
        logo_svg=_brand_logo("linux"),
        toolkit_yaml=(
            "  linux:\n"
            "    executor: ssh\n"
            '    ssh_host: "CHANGEME"          # e.g. 192.168.1.50\n'
            "    ssh_port: 22\n"
            '    ssh_user: "CHANGEME"          # a dedicated, unprivileged user -- not root\n'
            '    ssh_known_hosts: "CHANGEME"   # output of: ssh-keyscan -t ed25519 <host>\n'
            '    binaries: ["/usr/bin/uptime", "/usr/bin/free", "/usr/bin/df"]\n'
            "    denied_args: []\n"
            "    path_roots: []\n"
            "    credential: linux\n"
            "    max_timeout_seconds: 15\n"
            "    max_output_bytes: 16384\n"
        ),
        credential_kind="ssh_private_key",
        notes=(
            "Deliberately narrow: a small, fixed set of read-only "
            "diagnostics over SSH on one remote host, the same "
            "binary-allowlist model as the docker/local executors -- never "
            "an arbitrary-command 'Linux CLI' tool, which has no boundary "
            "to validate against (REQUIREMENTS.md §17). Generate a "
            "dedicated ed25519 keypair for gatekeeper, put the public half "
            "in that user's ~/.ssh/authorized_keys on the target host, and "
            "store the private half here as the credential."
        ),
        tool_specs=(
            _tool_argv(
                "linux.uptime", toolkit="linux", title="Uptime and load",
                description="Uptime and load average of the remote host.",
                binary="/usr/bin/uptime", argv=[],
                timeout_seconds=10, max_output_bytes=4096,
            ),
            _tool_argv(
                "linux.memory", toolkit="linux", title="Memory usage",
                description="Memory usage of the remote host.",
                binary="/usr/bin/free", argv=["-h"],
                timeout_seconds=10, max_output_bytes=4096,
            ),
            _tool_argv(
                "linux.disk", toolkit="linux", title="Disk usage",
                description="Filesystem usage of the remote host.",
                binary="/usr/bin/df", argv=["-h"],
                timeout_seconds=10, max_output_bytes=8192,
            ),
        ),
    ),
]

INTEGRATIONS: dict[str, Integration] = {integration.key: integration for integration in _INTEGRATIONS_LIST}
