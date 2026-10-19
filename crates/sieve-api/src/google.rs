use std::time::Duration;

use axum::extract::{Query, Request, State};
use axum::http::{HeaderValue, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use log::warn;
use serde_json::json;
use sha2::{Digest, Sha256};
use sieve_common::LogError;
use sieve_common::audit::{Action, Target, TargetKind};
use sieve_common::database::users;
use sieve_common::jwt::{OAUTH_TTL, OAuthState, SESSION_TTL};
use uuid::Uuid;

use crate::audit;
use crate::auth::{self, Principal};
use crate::client::ClientInfo;
use crate::config::GoogleConfig;
use crate::error::{ApiError, IntoApiError};
use crate::state::AppState;

const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const ISSUERS: [&str; 2] = ["https://accounts.google.com", "accounts.google.com"];
pub(crate) const REDIRECT_PATH: &str = "/auth/redirect/google";
const STATE_COOKIE: &str = "sieve_oauth";
const LEEWAY_SECONDS: i64 = 60;

pub(crate) struct Google {
    client_id: Box<str>,
    client_secret: Box<str>,
    redirect_uri: Box<str>,
    pub(crate) token_url: Box<str>,
    http: reqwest::Client,
}

impl Google {
    pub fn new(config: GoogleConfig) -> Self {
        Self {
            redirect_uri: format!("{}{REDIRECT_PATH}", config.public_url.trim_end_matches('/'))
                .into(),
            client_id: config.client_id,
            client_secret: config.client_secret,
            token_url: TOKEN_URL.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("the default TLS backend is available"),
        }
    }

    fn authorization_url(&self, oauth: &OAuthState) -> url::Url {
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(oauth.verifier.as_bytes()));
        let mut url = url::Url::parse(AUTH_URL).expect("AUTH_URL is a valid URL");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email")
            .append_pair("state", &oauth.state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "select_account");
        url
    }

    /// Trades the authorization code for the user's ID token.
    async fn exchange(&self, code: &str, verifier: &str) -> Result<Box<str>, Box<str>> {
        #[derive(serde::Deserialize)]
        struct TokenResponse {
            id_token: Box<str>,
        }

        let response = self
            .http
            .post(&*self.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("code_verifier", verifier),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("redirect_uri", &self.redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| format!("token request failed: {e}"))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(format!("token endpoint returned {status}: {body}").into());
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| format!("failed to read token response: {e}"))?;
        serde_json::from_slice::<TokenResponse>(&body)
            .map(|response| response.id_token)
            .map_err(|e| format!("unexpected token response: {e}").into())
    }

    /// The ID token comes straight from Google's token endpoint over TLS, so its signature
    /// needn't be checked (OpenID Connect Core 3.1.3.7), but its claims still must be.
    fn identity(&self, id_token: &str, now: i64) -> Result<Identity, Box<str>> {
        #[derive(serde::Deserialize)]
        struct IdClaims {
            iss: Box<str>,
            aud: Box<str>,
            sub: Box<str>,
            exp: i64,
            email: Option<Box<str>>,
            #[serde(default)]
            email_verified: bool,
        }

        let payload = id_token.split('.').nth(1).ok_or("ID token is not a JWT")?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|e| format!("ID token payload is not base64: {e}"))?;
        let claims: IdClaims = serde_json::from_slice(&payload)
            .map_err(|e| format!("unexpected ID token claims: {e}"))?;

        if !ISSUERS.contains(&claims.iss.as_ref()) {
            return Err(format!("ID token issued by {}", claims.iss).into());
        }
        if claims.aud != self.client_id {
            return Err(format!("ID token is for another client: {}", claims.aud).into());
        }
        if claims.exp + LEEWAY_SECONDS < now {
            return Err("ID token has expired".into());
        }
        match claims.email {
            Some(email) if claims.email_verified => Ok(Identity { sub: claims.sub, email }),
            _ => Err(format!("Google account {} has no verified email", claims.sub).into()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    sub: Box<str>,
    email: Box<str>,
}

// Only same-site paths, so a crafted link can't bounce users elsewhere after signing in.
fn safe_next(next: Option<&str>) -> &str {
    match next {
        Some(next) if next.starts_with('/') && !next.starts_with("//") && !next.contains('\\') => {
            next
        }
        _ => "/",
    }
}

// Lax, unlike the session cookie: it has to come back on the top-level navigation from Google.
fn state_cookie(token: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{STATE_COOKIE}={token}; HttpOnly; Secure; SameSite=Lax; Path=/auth; Max-Age={max_age}"
    ))
    .expect("JWTs and integers are valid header characters")
}

fn random_token() -> String {
    Uuid::new_v4().simple().to_string()
}

#[derive(serde::Deserialize)]
pub(crate) struct StartParams {
    next: Option<Box<str>>,
}

/// Sends the browser to Google, remembering the sign-in in a short-lived signed cookie.
pub(crate) async fn start(
    State(state): State<AppState>,
    Query(params): Query<StartParams>,
) -> Result<Response, ApiError> {
    let google = state.google.as_deref().ok_or(ApiError::NotFound)?;

    let oauth = OAuthState {
        state: random_token().into(),
        verifier: format!("{}{}", random_token(), random_token()).into(),
        next: safe_next(params.next.as_deref()).into(),
    };
    let token = state
        .keys
        .issue_oauth(&oauth)
        .log_error("failed to issue sign-in state")
        .as_internal_server_error()?;

    let mut response = Redirect::to(google.authorization_url(&oauth).as_str()).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, state_cookie(&token, OAUTH_TTL.num_seconds()));
    Ok(response)
}

#[derive(serde::Deserialize)]
pub(crate) struct CallbackParams {
    code: Option<Box<str>>,
    state: Option<Box<str>>,
    error: Option<Box<str>>,
}

enum Failure {
    /// Google, the browser or the user didn't complete the sign-in; back to the login page.
    Rejected(Box<str>),
    Internal(ApiError),
}

impl From<ApiError> for Failure {
    fn from(e: ApiError) -> Self {
        Self::Internal(e)
    }
}

impl From<&str> for Failure {
    fn from(reason: &str) -> Self {
        Self::Rejected(reason.into())
    }
}

/// Where Google sends the browser back to, with an authorization code or an error.
pub(crate) async fn callback(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, ApiError> {
    let google = state.google.clone().ok_or(ApiError::NotFound)?;
    let client = ClientInfo::from_request(&request, &state.trusted_proxies);
    let params = Query::<CallbackParams>::try_from_uri(request.uri())
        .map_err(|_| ApiError::BadRequest("malformed sign-in response"))?
        .0;
    let oauth = auth::cookie(request.headers(), STATE_COOKIE)
        .and_then(|token| state.keys.verify_oauth(token));
    let next = oauth.as_ref().map_or_else(|| "/".into(), |oauth| oauth.next.clone());

    let mut response = match sign_in(&state, &google, params, oauth, client).await {
        Ok(token) => {
            let mut response = continue_to(&next);
            response
                .headers_mut()
                .append(header::SET_COOKIE, auth::session_cookie(&token, SESSION_TTL.num_seconds()));
            response
        }
        Err(Failure::Rejected(reason)) => {
            warn!("Google sign-in failed: {reason}");
            let mut login = "/login?error=google".to_owned();
            if &*next != "/" {
                login.push_str("&next=");
                login.extend(url::form_urlencoded::byte_serialize(next.as_bytes()));
            }
            Redirect::to(&login).into_response()
        }
        Err(Failure::Internal(e)) => return Err(e),
    };
    response.headers_mut().append(header::SET_COOKIE, state_cookie("", 0));
    Ok(response)
}

/// Returns a session token for the Google account, creating its user on first sign-in.
async fn sign_in(
    state: &AppState,
    google: &Google,
    params: CallbackParams,
    oauth: Option<OAuthState>,
    client: ClientInfo,
) -> Result<Box<str>, Failure> {
    if let Some(error) = params.error {
        return Err(Failure::Rejected(format!("Google returned {error}").into()));
    }
    let oauth = oauth.ok_or("the sign-in cookie is missing or expired")?;
    if params.state.as_deref() != Some(&*oauth.state) {
        return Err("the sign-in state doesn't match".into());
    }
    let code = params.code.ok_or("Google returned no authorization code")?;

    let id_token = google
        .exchange(&code, &oauth.verifier)
        .await
        .map_err(Failure::Rejected)?;
    let identity = google
        .identity(&id_token, Utc::now().timestamp())
        .map_err(Failure::Rejected)?;

    let mut tx = state.begin().await?;
    let existing = users::find_by_google_sub(&mut tx, &identity.sub)
        .await
        .log_error("failed to look up user")
        .as_internal_server_error()?;
    let (user, created) = match existing {
        Some(user) => (user, false),
        None => {
            let user = users::create_google(&mut tx, &identity.email, &identity.sub)
                .await
                .log_error("failed to create user")
                .as_internal_server_error()?;
            (user, true)
        }
    };

    let actor = Principal::User(user.clone()).actor(client);
    let target = || Some(Target::new(TargetKind::User, user.id));
    if created {
        let details = json!({ "username": user.username, "email": identity.email, "via": "google" });
        audit::record(&mut tx, &actor, None, Action::UserCreate, target(), details).await?;
    }
    let details = json!({ "username": user.username, "method": "google" });
    audit::record(&mut tx, &actor, None, Action::AuthLogin, target(), details).await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(state
        .keys
        .issue_user(user.id)
        .log_error("failed to issue session token")
        .as_internal_server_error()?)
}

/// Navigates on from a page of this site rather than redirecting: a redirect would still be
/// part of the cross-site navigation from Google, so the SameSite=Strict session cookie
/// wouldn't be sent with it.
fn continue_to(next: &str) -> Response {
    let target = serde_json::to_string(next)
        .expect("strings serialize")
        .replace('<', "\\u003c");
    Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Signing in…</title>\
         <script>location.replace({target})</script>"
    ))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn google() -> Google {
        Google::new(GoogleConfig {
            client_id: "client".into(),
            client_secret: "secret".into(),
            public_url: "https://sieve.example.com/".into(),
        })
    }

    fn id_token(claims: serde_json::Value) -> String {
        format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()))
    }

    fn claims() -> serde_json::Value {
        json!({
            "iss": "https://accounts.google.com",
            "aud": "client",
            "sub": "1234",
            "exp": 1000,
            "email": "amanda@example.com",
            "email_verified": true,
        })
    }

    #[test]
    fn accepts_verified_identities_for_this_client() {
        let identity = google().identity(&id_token(claims()), 1000).unwrap();
        assert_eq!(identity, Identity { sub: "1234".into(), email: "amanda@example.com".into() });
    }

    #[test]
    fn rejects_foreign_expired_and_unverified_tokens() {
        let google = google();
        let with = |key: &str, value: serde_json::Value| {
            let mut claims = claims();
            claims[key] = value;
            id_token(claims)
        };

        assert!(google.identity(&with("aud", json!("other")), 1000).is_err());
        assert!(google.identity(&with("iss", json!("https://evil.example")), 1000).is_err());
        assert!(google.identity(&with("email_verified", json!(false)), 1000).is_err());
        assert!(google.identity(&with("email", json!(null)), 1000).is_err());
        assert!(google.identity(&id_token(claims()), 1000 + LEEWAY_SECONDS + 1).is_err());
        assert!(google.identity("not-a-jwt", 1000).is_err());
    }

    #[test]
    fn authorization_url_uses_pkce_and_the_redirect_path() {
        let oauth = OAuthState { state: "st".into(), verifier: "v".repeat(64).into(), next: "/".into() };
        let url = google().authorization_url(&oauth);
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();

        assert_eq!(query["redirect_uri"], "https://sieve.example.com/auth/redirect/google");
        assert_eq!(query["state"], "st");
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["code_challenge"], URL_SAFE_NO_PAD.encode(Sha256::digest("v".repeat(64))));
    }

    #[test]
    fn only_follows_same_site_paths() {
        assert_eq!(safe_next(Some("/w/1/sites?x=1")), "/w/1/sites?x=1");
        for next in [None, Some(""), Some("https://evil.example"), Some("//evil.example"), Some("/\\evil")] {
            assert_eq!(safe_next(next), "/");
        }
    }

    #[test]
    fn continue_page_escapes_the_target() {
        let response = continue_to("/a</script><script>alert(1)//");
        let body = futures_util::FutureExt::now_or_never(
            http_body_util::BodyExt::collect(response.into_body()),
        )
        .unwrap()
        .unwrap()
        .to_bytes();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(!body.contains("</script><script>alert"), "{body}");
    }
}
