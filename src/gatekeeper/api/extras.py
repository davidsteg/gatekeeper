"""Stats, bundled docs and OAuth sign-in for `/api/v1` -- the last pages
the legacy console had that the React console did not (0.57.0).

OAuth: `POST /oauth/{provider}/authorize` starts a flow exactly as
`/ui/oauth/<provider>/authorize` does -- same gates (session, `admin`,
CSRF), same single-use state (one `OAuthStateStore`, shared with the
callback route), same audit record -- and answers the consent URL as
data. The browser then leaves for the provider and comes back to the
unchanged callback path, so the redirect URI registered with Google or
Microsoft keeps working; because the state says the flow came from
`/app`, the callback redirects there with a result code instead of
rendering a page.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Query, Request

from .. import oauth
from . import models
from . import service as rm
from .deps import ApiContext, ApiError, ctx, require_admin, require_viewer
from .session import Session


def register_extra_routes(app: FastAPI) -> None:
    @app.get("/stats", response_model=models.Stats, tags=["stats"])
    def stats(
        window: str = Query("24h", pattern="^(24h|7d|30d)$"),
        _s: Session = Depends(require_viewer), context: ApiContext = Depends(ctx),
    ) -> Any:
        return rm.stats_view(context.service, window)

    @app.get("/documents", response_model=list[models.DocEntry], tags=["documents"])
    def docs(_s: Session = Depends(require_viewer)) -> Any:
        return rm.docs_index()

    @app.get("/documents/{slug}", response_model=models.Doc, tags=["documents"],
             responses={404: {"model": models.Problem}})
    def doc(slug: str, _s: Session = Depends(require_viewer)) -> Any:
        found = rm.doc_text(slug)
        if found is None:
            raise ApiError(404, f"No document {slug!r}.")
        return found

    @app.get("/oauth/providers", response_model=list[models.OAuthProvider], tags=["oauth"])
    def oauth_providers(
        _s: Session = Depends(require_viewer), context: ApiContext = Depends(ctx),
    ) -> Any:
        """Providers some toolkit uses, with the credentials it names."""
        out = []
        for spec in oauth.PROVIDERS.values():
            names = oauth.oauth_credential_names(context.service, spec)
            if names:
                out.append({
                    "key": spec.key, "label": spec.label, "credentials": names,
                    "callback_path": spec.callback_path,
                })
        return out

    @app.post(
        "/oauth/{provider}/authorize", response_model=models.OAuthStart, tags=["oauth"],
        responses={400: {"model": models.Problem}, 404: {"model": models.Problem},
                   409: {"model": models.Problem}},
    )
    def oauth_authorize(
        provider: str, body: models.OAuthStartBody, request: Request,
        session: Session = Depends(require_admin), context: ApiContext = Depends(ctx),
    ) -> Any:
        spec = oauth.PROVIDERS.get(provider)
        if spec is None:
            raise ApiError(404, f"No sign-in provider {provider!r}.")
        if context.credentials is None or context.oauth_states is None:
            raise ApiError(409, "This console cannot write credentials (no credential store).")
        name = body.credential.strip()
        available = oauth.oauth_credential_names(context.service, spec)
        if not name:
            if len(available) == 1:
                name = available[0]
            elif not available:
                raise ApiError(
                    400,
                    f"No {spec.key} toolkit in toolkits.yaml names a credential, so there "
                    "is nothing to connect. Toolkits are deploy-time only (FR-4.11).",
                )
            else:
                raise ApiError(
                    400, f"Several {spec.key} toolkits name different credentials "
                    f"({', '.join(available)}); say which one to connect.",
                )
        try:
            client_id, _secret = oauth.oauth_client(context.credentials, name, spec)
        except oauth.OAuthExchangeError as exc:
            raise ApiError(400, str(exc)) from None
        redirect_uri = oauth._public_base_url(request) + spec.callback_path
        scopes = oauth.oauth_scopes(context.service, spec)
        verifier, challenge = oauth._pkce_pair() if spec.uses_pkce else ("", "")
        state = context.oauth_states.issue(
            identity=session.identity, credential=name, redirect_uri=redirect_uri,
            scopes=scopes, provider=spec.key, code_verifier=verifier, return_to="app",
        )
        if spec.key == "microsoft":
            consent_url = oauth._microsoft_consent_url(
                client_id=client_id, redirect_uri=redirect_uri, scopes=scopes,
                state=state, code_challenge=challenge,
            )
        else:
            consent_url = oauth._google_consent_url(
                client_id=client_id, redirect_uri=redirect_uri, scopes=scopes, state=state,
            )
        # Names and scopes only -- no client id, no code, no token, no verifier.
        context.audit.write({
            "kind": "ui_oauth", "actor": session.identity,
            "action": f"{spec.key}_authorize", "credential": name,
            "scopes": scopes, "redirect_uri": redirect_uri, "surface": "api",
        })
        return {
            "provider": spec.key, "label": spec.label, "credential": name,
            "consent_url": consent_url, "callback_uri": redirect_uri, "scopes": scopes,
            "registration_console": spec.registration_console,
            "mismatch_error": spec.mismatch_error,
        }
