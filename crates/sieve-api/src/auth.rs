use axum::Json;
use axum::extract::{FromRequest, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{Router, get, post};
use log::warn;
use serde_json::json;
use sieve_common::LogError;
use sieve_common::audit::{Action, Actor, ActorKind, Target, TargetKind};
use sieve_common::database::devices::{self, Device};
use sieve_common::database::users::{self, User};
use sieve_common::database::workspaces::{self, Membership};
use sieve_common::jwt::{Claims, SESSION_TTL};
use sieve_common::password;

use crate::audit;
use crate::client::ClientInfo;
use crate::error::{ApiError, IntoApiError};
use crate::state::AppState;

pub(crate) const SESSION_COOKIE: &str = "sieve_session";

/// Routes for a signed-in user.
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/logout", post(logout))
        .route("/me", get(me))
}

/// Routes that must work without a session.
pub(crate) fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/providers", get(providers))
}

#[derive(Debug, Clone)]
pub(crate) enum Principal {
    User(User),
    Device(Device),
}

impl Principal {
    pub(crate) fn actor(&self, client: ClientInfo) -> Actor {
        let (kind, id, label) = match self {
            Self::User(user) => (ActorKind::User, user.id.to_string(), user.username.clone()),
            Self::Device(device) => (ActorKind::Device, device.id.to_string(), device.name.clone()),
        };

        Actor {
            kind,
            id: Some(id.into()),
            label,
            ip: client.ip,
            user_agent: client.user_agent,
        }
    }
}

fn token(headers: &HeaderMap) -> Option<&str> {
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    bearer
        .or_else(|| cookie(headers, SESSION_COOKIE))
        .filter(|token| !token.is_empty())
}

pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<Principal, ApiError> {
    let claims = token(headers)
        .and_then(|token| state.keys.verify(token))
        .ok_or(ApiError::Unauthorized)?;

    let mut conn = state.conn().await?;
    match claims {
        Claims::User { sub, .. } => {
            let id = sub.parse().map_err(|_| ApiError::Unauthorized)?;
            users::get(&mut conn, id)
                .await
                .log_error("failed to look up user")
                .as_internal_server_error()?
                .map(Principal::User)
                .ok_or(ApiError::Unauthorized)
        }
        Claims::Device { sub, ws, .. } => {
            let id = sub.parse().map_err(|_| ApiError::Unauthorized)?;
            devices::get_active(&mut conn, id)
                .await
                .log_error("failed to look up device")
                .as_internal_server_error()?
                .filter(|device| device.workspace_id == ws)
                .map(Principal::Device)
                .ok_or(ApiError::Unauthorized)
        }
        Claims::Invite { .. } | Claims::OAuth { .. } => Err(ApiError::Unauthorized),
    }
}

/// Rejects unauthenticated requests with 401 and attaches the `Principal` and audit `Actor`.
pub(crate) async fn require_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let principal = authenticate(&state, request.headers()).await?;
    let actor = principal.actor(ClientInfo::from_request(&request, &state.trusted_proxies));

    request.extensions_mut().insert(principal);
    request.extensions_mut().insert(actor);
    Ok(next.run(request).await)
}

const STATIC_EXTENSIONS: &[&str] = &[
    "css", "ico", "jpeg", "jpg", "js", "json", "map", "png", "svg", "txt", "webmanifest", "webp",
    "woff", "woff2",
];

// Matched on known extensions, not any dot: invite links end in a JWT, which contains dots.
fn is_public_page(path: &str) -> bool {
    let file_name = path.rsplit('/').next().unwrap_or_default();
    let is_static_file = file_name
        .rsplit_once('.')
        .is_some_and(|(_, extension)| STATIC_EXTENSIONS.contains(&extension));
    path == "/login" || path.starts_with("/assets/") || is_static_file
}

/// Sends unauthenticated page navigations to the login page, keeping where they were going.
pub(crate) async fn redirect_to_login(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if is_public_page(request.uri().path()) {
        return Ok(next.run(request).await);
    }

    match authenticate(&state, request.headers()).await {
        Ok(_) => Ok(next.run(request).await),
        Err(ApiError::Unauthorized) => {
            let target = request
                .uri()
                .path_and_query()
                .map_or("/", |path| path.as_str());
            let next = url::form_urlencoded::byte_serialize(target.as_bytes()).collect::<String>();
            Ok(Redirect::to(&format!("/login?next={next}")).into_response())
        }
        Err(e) => Err(e),
    }
}

/// The authenticated user; devices are refused with 403.
pub(crate) struct AuthUser(pub User);

impl<S: Send + Sync> FromRequestParts<S> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        match parts.extensions.get::<Principal>() {
            Some(Principal::User(user)) => Ok(Self(user.clone())),
            Some(Principal::Device(_)) => Err(ApiError::Forbidden),
            None => Err(ApiError::Unauthorized),
        }
    }
}

pub(crate) fn session_cookie(token: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"
    ))
    .expect("JWTs and integers are valid header characters")
}

#[derive(serde::Serialize)]
pub(crate) struct Session {
    user: User,
    workspaces: Vec<Membership>,
}

async fn session(state: &AppState, user: User) -> Result<Session, ApiError> {
    let mut conn = state.conn().await?;
    let workspaces = workspaces::list_for_user(&mut conn, user.id)
        .await
        .log_error("failed to list workspaces")
        .as_internal_server_error()?;
    Ok(Session { user, workspaces })
}

#[derive(serde::Deserialize)]
pub(crate) struct LoginRequest {
    username: Box<str>,
    password: Box<str>,
}

pub(crate) async fn login(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, ApiError> {
    let client = ClientInfo::from_request(&request, &state.trusted_proxies);
    let Json(body) = Json::<LoginRequest>::from_request(request, &state)
        .await
        .map_err(|_| ApiError::BadRequest("expected JSON with username and password"))?;

    let mut conn = state.conn().await?;
    let credentials = users::find_credentials(&mut conn, &body.username)
        .await
        .log_error("failed to look up user")
        .as_internal_server_error()?;
    drop(conn);

    let password = body.password.clone();
    let hash = credentials.as_ref().map(|c| c.password_hash.clone());
    let valid = tokio::task::spawn_blocking(move || match hash {
        Some(hash) => password::verify(&password, &hash),
        None => {
            password::verify_dummy(&password);
            false
        }
    })
    .await
    .log_error("failed to join password verification")
    .as_internal_server_error()?;

    let mut tx = state.begin().await?;

    let Some(credentials) = credentials.filter(|_| valid) else {
        warn!("failed login for '{}'", body.username);
        let actor = Actor {
            kind: ActorKind::Anonymous,
            id: None,
            label: "anonymous".into(),
            ip: client.ip,
            user_agent: client.user_agent,
        };
        audit::record(
            &mut tx,
            &actor,
            None,
            Action::AuthLoginFailed,
            None,
            json!({ "username": body.username }),
        )
        .await?;
        tx.commit().await.log_error("failed to commit").as_internal_server_error()?;
        return Err(ApiError::Unauthorized);
    };

    let user = credentials.user();
    let actor = Principal::User(user.clone()).actor(client);
    audit::record(
        &mut tx,
        &actor,
        None,
        Action::AuthLogin,
        Some(Target::new(TargetKind::User, user.id)),
        json!({ "username": user.username }),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    let token = state
        .keys
        .issue_user(user.id)
        .log_error("failed to issue session token")
        .as_internal_server_error()?;

    let mut response = Json(session(&state, user).await?).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&token, SESSION_TTL.num_seconds()));
    Ok(response)
}

pub(crate) async fn logout(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    axum::Extension(actor): axum::Extension<Actor>,
) -> Result<Response, ApiError> {
    let mut tx = state.begin().await?;
    audit::record(
        &mut tx,
        &actor,
        None,
        Action::AuthLogout,
        Some(Target::new(TargetKind::User, user.id)),
        json!({ "username": user.username }),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie("", 0));
    Ok(response)
}

/// Which sign-in methods the login page should offer besides a password.
pub(crate) async fn providers(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({ "google": state.google.is_some() }))
}

pub(crate) async fn me(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(session(&state, user).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_bearer_before_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("a=b; sieve_session=cookie"));
        assert_eq!(token(&headers), Some("cookie"));

        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer bearer"));
        assert_eq!(token(&headers), Some("bearer"));

        assert_eq!(token(&HeaderMap::new()), None);
    }

    #[test]
    fn public_pages() {
        assert!(is_public_page("/login"));
        assert!(is_public_page("/assets/index-abc.js"));
        assert!(is_public_page("/favicon.ico"));
        assert!(!is_public_page("/"));
        assert!(!is_public_page("/index.html"));
        assert!(!is_public_page("/w/123/sites"));
        assert!(!is_public_page("/invite/eyJhbGciOiJIUzI1NiJ9.eyJraW5kIjoiaW52aXRlIn0.c2lnbmF0dXJl"));
    }
}
