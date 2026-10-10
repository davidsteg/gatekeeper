"""The console's JSON API, `/api/v1` (FastAPI, inside the gatekeeper process).

Deliberately light at import time: `ui.py` imports the shared session store
and read model from `api.session`/`api.service`, and must not pull FastAPI
in for that. The ASGI app itself is built by `api.app.build_api_app`.
"""

#: Mount point of the API inside the Starlette app. Versioned in the path so
#: a later breaking change can live next to this one rather than replace it.
API_PREFIX = "/api/v1"
