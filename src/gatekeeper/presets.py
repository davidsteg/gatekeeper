"""A small library of starter definitions for common homelab/SaaS services.

This is the "simplify adding tools" half of the http/truenas executor work:
once an admin has pasted a preset's `toolkit_yaml` into `toolkits.yaml` and
redeployed (Tier 1 stays a manual, deploy-time step -- FR-4.11, presets do
not and must not change that), picking one of its `tool_specs` in
`/ui/tools/presets` pre-fills the *existing* tool editor instead of a blank
textarea. The preset never bypasses `parse_tool_spec`/Tier 1 validation --
it only saves typing what would otherwise be hand-written YAML.

Logos are small inline-SVG monograms, not the services' actual trademarked
marks: the console's CSP (`img-src 'self' data:`, no external requests) and
copyright both argue against embedding real brand assets, and a schematic
badge in the service's own accent color is enough to make a preset
recognizable in a gallery of many.
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
        logo_svg=_monogram("So", "#3b5998"),
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
        logo_svg=_monogram("Ra", "#ffc230"),
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
        logo_svg=_monogram("Jf", "#00a4dc"),
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
        logo_svg=_monogram("Bz", "#a32424"),
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
        logo_svg=_monogram("Pr", "#f5751e"),
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
        logo_svg=_monogram("Ha", "#41bdf5"),
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
        logo_svg=_monogram("n8", "#ea4b71"),
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
        logo_svg=_monogram("Uk", "#5cdd8b"),
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
        logo_svg=_monogram("Im", "#4250af"),
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
        logo_svg=_monogram("Tg", "#26a5e4"),
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
        logo_svg=_monogram("G", "#4285f4"),
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
        logo_svg=_monogram("Tn", "#0095d5"),
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
