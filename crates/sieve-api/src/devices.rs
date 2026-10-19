use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::{Router, delete, get};
use axum::{Extension, Json};
use sieve_common::audit::Actor;
use sieve_common::database::devices::{self, Device};
use sieve_common::{LogError, enrollment};
use uuid::Uuid;

use crate::error::{ApiError, IntoApiError};
use crate::state::AppState;
use crate::workspace::OwnerWorkspace;

const MAX_NAME_LEN: usize = 100;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{device_id}", delete(revoke))
}

#[derive(serde::Deserialize)]
pub(crate) struct DeviceParams {
    device_id: Uuid,
}

pub(crate) async fn list(
    State(state): State<AppState>,
    OwnerWorkspace(workspace): OwnerWorkspace,
) -> Result<impl IntoResponse, ApiError> {
    let mut conn = state.conn().await?;
    let devices = devices::list(&mut conn, workspace)
        .await
        .log_error("failed to list devices")
        .as_internal_server_error()?;

    Ok(Json(devices))
}

#[derive(serde::Deserialize)]
pub(crate) struct CreateRequest {
    name: Box<str>,
}

#[derive(serde::Serialize)]
pub(crate) struct CreateResponse {
    device: Device,
    token: Box<str>,
    proxy_password: Box<str>,
}

/// The token and proxy password are returned here and never again.
pub(crate) async fn create(
    State(state): State<AppState>,
    OwnerWorkspace(workspace): OwnerWorkspace,
    Extension(actor): Extension<Actor>,
    Json(body): Json<CreateRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(ApiError::BadRequest("device name must be 1 to 100 characters"));
    }

    let mut tx = state.begin().await?;
    let new = enrollment::enroll(&mut tx, &state.keys, &actor, workspace, name)
        .await
        .log_error("failed to enroll device")
        .as_internal_server_error()?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(CreateResponse {
        device: new.device,
        token: new.token,
        proxy_password: new.proxy_password,
    }))
}

pub(crate) async fn revoke(
    State(state): State<AppState>,
    OwnerWorkspace(workspace): OwnerWorkspace,
    Extension(actor): Extension<Actor>,
    Path(params): Path<DeviceParams>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.begin().await?;
    let device = enrollment::revoke(&mut tx, &actor, params.device_id, Some(workspace))
        .await
        .log_error("failed to revoke device")
        .as_internal_server_error()?
        .ok_or(ApiError::NotFound)?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(device))
}
