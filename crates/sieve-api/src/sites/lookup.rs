use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use sieve_common::LogError;
use sieve_common::database::sites::{self, Domain, Path, Scheme};

use crate::error::{ApiError, IntoApiError};
use crate::state::AppState;
use crate::workspace::Workspace;

#[derive(Debug, serde::Deserialize)]
pub(super) struct LookupParams {
    url: Box<str>,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct LookupResponse {
    scheme: Scheme,
    domain: Box<str>,
    path: Box<str>,
    domain_entry: Option<Domain>,
    path_entry: Option<Path>,
}

pub(super) async fn get(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Query(query): Query<LookupParams>,
) -> Result<impl IntoResponse, ApiError> {
    let url = url::Url::parse(&query.url).map_err(|_| ApiError::BadRequest("invalid url"))?;
    let scheme = Scheme::try_from(url.scheme())
        .map_err(|_| ApiError::BadRequest("unsupported url scheme"))?;
    let domain: Box<str> = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or(ApiError::BadRequest("url has no host"))?
        .into();
    let path: Box<str> = url.path().into();

    let mut conn = state.conn().await?;
    let domain_entry = sites::find_domain(&mut conn, workspace, scheme, &domain)
        .await
        .log_error("failed to find domain")
        .as_internal_server_error()?;
    let path_entry = match &domain_entry {
        Some(entry) => sites::find_path(&mut conn, workspace, entry.id(), &path)
            .await
            .log_error("failed to find path")
            .as_internal_server_error()?,
        None => None,
    };

    Ok(Json(LookupResponse {
        scheme,
        domain,
        path,
        domain_entry,
        path_entry,
    }))
}
