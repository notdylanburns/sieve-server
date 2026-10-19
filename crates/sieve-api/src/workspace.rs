use axum::extract::{FromRequestParts, Path};
use axum::http::request::Parts;
use sieve_common::LogError;
use sieve_common::database::WorkspaceId;
use sieve_common::database::workspaces::{self, Role};

use crate::auth::Principal;
use crate::error::{ApiError, IntoApiError};
use crate::state::AppState;

/// The `{workspace}` path segment, for a workspace the authenticated user belongs to.
/// Non-members get 404 so the response doesn't reveal whether the workspace exists; devices get 403.
pub(crate) struct Workspace(pub WorkspaceId);

/// Like `Workspace`, but the user must be an owner of it.
pub(crate) struct OwnerWorkspace(pub WorkspaceId);

/// Like `Workspace`, but also accepts a device enrolled in the workspace.
pub(crate) struct ClientWorkspace(pub WorkspaceId);

#[derive(serde::Deserialize)]
struct WorkspaceParam {
    workspace: WorkspaceId,
}

async fn path_workspace(parts: &mut Parts, state: &AppState) -> Result<WorkspaceId, ApiError> {
    Path::<WorkspaceParam>::from_request_parts(parts, state)
        .await
        .map(|Path(WorkspaceParam { workspace })| workspace)
        .map_err(|_| ApiError::NotFound)
}

async fn resolve(parts: &mut Parts, state: &AppState) -> Result<(WorkspaceId, Role), ApiError> {
    let user = match parts.extensions.get::<Principal>() {
        Some(Principal::User(user)) => user.clone(),
        Some(Principal::Device(_)) => return Err(ApiError::Forbidden),
        None => return Err(ApiError::Unauthorized),
    };

    let workspace = path_workspace(parts, state).await?;

    let mut conn = state.conn().await?;
    let role = workspaces::member_role(&mut conn, workspace, user.id)
        .await
        .log_error("failed to look up workspace membership")
        .as_internal_server_error()?
        .ok_or(ApiError::NotFound)?;

    Ok((workspace, role))
}

impl FromRequestParts<AppState> for Workspace {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        resolve(parts, state).await.map(|(workspace, _)| Self(workspace))
    }
}

impl FromRequestParts<AppState> for ClientWorkspace {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        if let Some(Principal::Device(device)) = parts.extensions.get::<Principal>() {
            let enrolled = device.workspace_id;
            return match path_workspace(parts, state).await? {
                workspace if workspace == enrolled => Ok(Self(workspace)),
                _ => Err(ApiError::NotFound),
            };
        }

        resolve(parts, state).await.map(|(workspace, _)| Self(workspace))
    }
}

impl FromRequestParts<AppState> for OwnerWorkspace {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        match resolve(parts, state).await? {
            (workspace, Role::Owner) => Ok(Self(workspace)),
            (_, Role::Member) => Err(ApiError::Forbidden),
        }
    }
}
