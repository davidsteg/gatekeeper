//! What is left of `/ui` after the 1.0.0 cutover to the React console --
//! port of `ui.py`, framework-independent.
//!
//! - Redirects: `/ui/...` -> `/app/...` (308, query kept); `/` -> `/app/`
//!   (303) and `/favicon.ico` -> `/app/favicon.svg` (308). Anything but
//!   `GET`/`HEAD` on a `/ui` path gets 410: an old form is not replayed
//!   against the new API.
//! - The OAuth callbacks (`oauth::callback`), whose paths are the redirect
//!   URIs registered with Google and Microsoft. They must not move.
//! - [`has_ui_identity`], the startup check for "can anyone sign in".

use crate::identity::IdentityStore;
use crate::oauth::{OAuthProviderSpec, GOOGLE_OAUTH, MICROSOFT_OAUTH};

pub const UI_PREFIX: &str = "/ui";
pub const APP_PREFIX: &str = "/app";

/// Paths a browser requests on its own when someone types the address.
/// Applies only when the console is enabled.
pub const UI_COMPANION_PATHS: [&str; 2] = ["/", "/favicon.ico"];

pub const GONE_MESSAGE: &str = "The /ui console was replaced by /app in gatekeeper 1.0.0. \
Nothing was changed; reload the page under /app.\n";

/// `/ui/<rest>?<query>` -> `/app/<rest>?<query>`. The target always starts
/// with `/app/`, so no request can turn it into a redirect to another
/// origin; the query is kept because pages read it.
pub fn app_path_for(path: &str, query: &str) -> String {
    let rest = path.get(UI_PREFIX.len()..).unwrap_or("").trim_start_matches('/');
    let mut out = format!("{APP_PREFIX}/{rest}");
    if !query.is_empty() {
        out.push('?');
        out.push_str(query);
    }
    out
}

/// Starlette's `RedirectResponse` Location quoting:
/// `quote(url, safe=":/%#?=@[]!$&'()*+,;")`.
pub fn quote_location(url: &str) -> String {
    const SAFE: &[u8] = b":/%#?=@[]!$&'()*+,;_.-~";
    let mut out = String::with_capacity(url.len());
    for b in url.bytes() {
        if b.is_ascii_alphanumeric() || SAFE.contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A finished response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiResponse {
    /// Status and an already-quoted `Location`, empty body.
    Redirect { status: u16, location: String },
    /// 410, `text/plain; charset=utf-8`, body [`GONE_MESSAGE`].
    Gone { status: u16, body: &'static str },
}

/// What the `/ui` routes make of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiRoute {
    /// Hand to `oauth::callback` with this provider (GET/HEAD only).
    OAuthCallback(&'static OAuthProviderSpec),
    Respond(UiResponse),
    /// The path is one of these routes but the method is not (Starlette 405).
    MethodNotAllowed,
    /// Not a `/ui` route at all (`/uixyz`, `/app/...`).
    NotMatched,
}

/// Routes one request. `path` is the percent-decoded path (Starlette's
/// `scope["path"]`), `query` the raw query string. Mirrors
/// `build_ui_routes`' order: callbacks first, then `/`, `/favicon.ico`,
/// `/ui` and `/ui/{path:path}`.
pub fn route(method: &str, path: &str, query: &str) -> UiRoute {
    let get_or_head = method == "GET" || method == "HEAD";
    for spec in [&GOOGLE_OAUTH, &MICROSOFT_OAUTH] {
        // Starlette adds HEAD to a GET route. Any other method is a partial
        // match there, and the catch-all below answers it (410).
        if path == spec.callback_path && get_or_head {
            return UiRoute::OAuthCallback(spec);
        }
    }
    if path == "/" {
        if !get_or_head {
            return UiRoute::MethodNotAllowed;
        }
        return UiRoute::Respond(UiResponse::Redirect { status: 303, location: format!("{APP_PREFIX}/") });
    }
    if path == "/favicon.ico" {
        if !get_or_head {
            return UiRoute::MethodNotAllowed;
        }
        return UiRoute::Respond(UiResponse::Redirect {
            status: 308,
            location: format!("{APP_PREFIX}/favicon.svg"),
        });
    }
    if path == UI_PREFIX || path.starts_with("/ui/") {
        const EVERY: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];
        if !EVERY.contains(&method) {
            return UiRoute::MethodNotAllowed;
        }
        if !get_or_head {
            return UiRoute::Respond(UiResponse::Gone { status: 410, body: GONE_MESSAGE });
        }
        return UiRoute::Respond(UiResponse::Redirect {
            status: 308,
            location: quote_location(&app_path_for(path, query)),
        });
    }
    UiRoute::NotMatched
}

/// Is there anyone at all who could sign in? Role *and* password.
pub fn has_ui_identity(identities: &IdentityStore) -> bool {
    identities.identities.values().any(|i| i.can_sign_in())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirect(method: &str, path: &str, query: &str) -> (u16, String) {
        match route(method, path, query) {
            UiRoute::Respond(UiResponse::Redirect { status, location }) => (status, location),
            other => panic!("{path}: {other:?}"),
        }
    }

    #[test]
    fn ui_paths_redirect_to_the_same_page_under_app() {
        for (path, query, target) in [
            ("/ui", "", "/app/"),
            ("/ui/", "", "/app/"),
            ("/ui/requests", "", "/app/requests"),
            ("/ui/tools/new", "", "/app/tools/new"),
            ("/ui//evil.example/x", "", "/app/evil.example/x"),
            // The query rides along: pages read it.
            ("/ui/requests", "tab=change", "/app/requests?tab=change"),
            ("/ui//evil.example", "next=//x", "/app/evil.example?next=//x"),
        ] {
            assert_eq!(redirect("GET", path, query), (308, target.to_string()), "{path}");
        }
        assert_eq!(redirect("HEAD", "/ui/x", ""), (308, "/app/x".to_string()));
    }

    #[test]
    fn the_location_is_quoted_like_starlette() {
        assert_eq!(redirect("GET", "/ui/a b", "").1, "/app/a%20b");
        assert_eq!(redirect("GET", "/ui/ä", "q=%20").1, "/app/%C3%A4?q=%20");
    }

    #[test]
    fn an_old_form_post_is_gone_not_replayed() {
        for path in ["/ui/login", "/ui/tools/save", "/ui/pending/approve", "/ui"] {
            match route("POST", path, "") {
                UiRoute::Respond(UiResponse::Gone { status, body }) => {
                    assert_eq!(status, 410);
                    assert!(body.contains("/app"));
                }
                other => panic!("{path}: {other:?}"),
            }
        }
        // POST to a callback path is the catch-all's: gone, not a callback.
        assert!(matches!(
            route("POST", "/ui/oauth/google/callback", ""),
            UiRoute::Respond(UiResponse::Gone { .. })
        ));
        assert_eq!(route("OPTIONS", "/ui/x", ""), UiRoute::MethodNotAllowed);
    }

    #[test]
    fn browser_noise_goes_to_app() {
        assert_eq!(redirect("GET", "/", ""), (303, "/app/".to_string()));
        assert_eq!(redirect("GET", "/favicon.ico", ""), (308, "/app/favicon.svg".to_string()));
        assert_eq!(route("POST", "/", ""), UiRoute::MethodNotAllowed);
    }

    #[test]
    fn similar_prefixes_are_not_ui_paths() {
        for path in ["/uixyz", "/appxyz", "/app/", "/api/v1/session"] {
            assert_eq!(route("GET", path, ""), UiRoute::NotMatched, "{path}");
        }
    }

    #[test]
    fn the_callbacks_keep_their_paths() {
        assert_eq!(route("GET", "/ui/oauth/google/callback", "code=x"), UiRoute::OAuthCallback(&GOOGLE_OAUTH));
        assert_eq!(
            route("HEAD", "/ui/oauth/microsoft/callback", ""),
            UiRoute::OAuthCallback(&MICROSOFT_OAUTH)
        );
    }
}
