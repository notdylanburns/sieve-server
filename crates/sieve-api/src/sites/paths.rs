use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use sieve_common::LogError;
use sieve_common::audit::{Action, Actor, Target, TargetKind};
use sieve_common::database::sites::{self, Domain};
use sieve_common::database::{PgConnection, WorkspaceId};

use crate::audit;
use crate::common::PaginationParams;
use crate::error::{ApiError, IntoApiError};
use crate::state::AppState;
use crate::workspace::Workspace;

#[derive(serde::Deserialize)]
pub(super) struct DomainParams {
    domain_id: i64,
}

#[derive(serde::Deserialize)]
pub(super) struct PathParams {
    domain_id: i64,
    path_id: i64,
}

pub(super) async fn get(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Query(query): Query<PaginationParams>,
    Path(params): Path<DomainParams>,
) -> Result<impl IntoResponse, ApiError> {
    let mut conn = state.conn().await?;
    let paths = sites::list_paths(
        &mut conn,
        workspace,
        params.domain_id,
        query.offset(),
        query.limit(),
    )
    .await
    .log_error("failed to list paths for domain")
    .as_internal_server_error()?;

    Ok(Json(paths))
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PostRequest {
    path: Box<str>,
    approved: bool,
}

async fn parent_domain(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    domain_id: i64,
) -> Result<Domain, ApiError> {
    sites::get_domain(conn, workspace, domain_id)
        .await
        .log_error("failed to get domain")
        .as_internal_server_error()?
        .ok_or(ApiError::NotFound)
}

async fn existing_path(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    params: &PathParams,
) -> Result<sites::Path, ApiError> {
    sites::get_path(conn, workspace, params.path_id)
        .await
        .log_error("failed to get path")
        .as_internal_server_error()?
        .filter(|path| path.domain_id == params.domain_id)
        .ok_or(ApiError::NotFound)
}

pub async fn post(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Extension(actor): Extension<Actor>,
    Path(params): Path<DomainParams>,
    Json(body): Json<PostRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let path = body.path.split(['?', '#']).next().unwrap_or_default().trim();
    let path = format!("/{}", path.trim_start_matches('/'));

    let mut tx = state.begin().await?;
    let parent = parent_domain(&mut tx, workspace, params.domain_id).await?;
    let before = sites::find_path(&mut tx, workspace, params.domain_id, &path)
        .await
        .log_error("failed to find path")
        .as_internal_server_error()?;
    let path = sites::add_path(&mut tx, workspace, params.domain_id, &path, body.approved)
        .await
        .log_error("failed to add path for domain")
        .as_internal_server_error()?
        .ok_or(ApiError::NotFound)?;

    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::PathCreate,
        Some(Target::new(TargetKind::Path, path.id())),
        audit::path_changes(&parent, before.as_ref(), Some(&path)),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(path))
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PatchRequest {
    approved: bool,
}

pub async fn patch(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Extension(actor): Extension<Actor>,
    Path(params): Path<PathParams>,
    Json(body): Json<PatchRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.begin().await?;
    let parent = parent_domain(&mut tx, workspace, params.domain_id).await?;
    let before = existing_path(&mut tx, workspace, &params).await?;
    sites::modify_path(
        &mut tx,
        workspace,
        params.domain_id,
        params.path_id,
        body.approved,
    )
    .await
    .log_error("failed to modify path")
    .as_internal_server_error()?;
    let after = existing_path(&mut tx, workspace, &params).await?;

    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::PathUpdate,
        Some(Target::new(TargetKind::Path, params.path_id)),
        audit::path_changes(&parent, Some(&before), Some(&after)),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(()))
}

pub async fn delete(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Extension(actor): Extension<Actor>,
    Path(params): Path<PathParams>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.begin().await?;
    let parent = parent_domain(&mut tx, workspace, params.domain_id).await?;
    let before = existing_path(&mut tx, workspace, &params).await?;
    sites::delete_path(&mut tx, workspace, params.domain_id, params.path_id)
        .await
        .log_error("failed to delete path")
        .as_internal_server_error()?;

    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::PathDelete,
        Some(Target::new(TargetKind::Path, params.path_id)),
        audit::path_changes(&parent, Some(&before), None),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(()))
}
