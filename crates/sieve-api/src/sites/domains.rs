use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use sieve_common::LogError;
use sieve_common::audit::{Action, Actor, Target, TargetKind};
use sieve_common::database::sites::{self, Scheme};

use crate::audit;
use crate::common::PaginationParams;
use crate::error::{ApiError, IntoApiError};
use crate::state::AppState;
use crate::workspace::Workspace;

#[derive(serde::Deserialize)]
pub(super) struct DomainParams {
    domain_id: i64,
}

pub(super) async fn get(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Query(query): Query<PaginationParams>,
) -> Result<impl IntoResponse, ApiError> {
    let mut conn = state.conn().await?;
    let domains = sites::list_domains(&mut conn, workspace, query.offset(), query.limit())
        .await
        .log_error("failed to list domains")
        .as_internal_server_error()?;

    Ok(Json(domains))
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PostRequest {
    scheme: Scheme,
    domain: Box<str>,
    approved: Option<bool>,
}

pub(super) async fn post(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Extension(actor): Extension<Actor>,
    Json(body): Json<PostRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.begin().await?;
    let before = sites::find_domain(&mut tx, workspace, body.scheme, &body.domain)
        .await
        .log_error("failed to find domain")
        .as_internal_server_error()?;
    let domain = match body.approved {
        Some(approved) => {
            sites::add_domain(&mut tx, workspace, body.scheme, &body.domain, Some(approved)).await
        }
        None => sites::add_domain_no_approval(&mut tx, workspace, body.scheme, &body.domain).await,
    }
    .log_error("failed to add domain")
    .as_internal_server_error()?;

    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::DomainCreate,
        Some(Target::new(TargetKind::Domain, domain.id())),
        audit::changes(before.as_ref().map(audit::domain), Some(audit::domain(&domain))),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(domain))
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PatchRequest {
    approved: Option<bool>,
}

pub(super) async fn patch(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Extension(actor): Extension<Actor>,
    Path(params): Path<DomainParams>,
    Json(body): Json<PatchRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.begin().await?;
    let before = sites::get_domain(&mut tx, workspace, params.domain_id)
        .await
        .log_error("failed to get domain")
        .as_internal_server_error()?
        .ok_or(ApiError::NotFound)?;
    sites::modify_domain(&mut tx, workspace, params.domain_id, body.approved)
        .await
        .log_error("failed to modify domain")
        .as_internal_server_error()?;
    let after = sites::get_domain(&mut tx, workspace, params.domain_id)
        .await
        .log_error("failed to get domain")
        .as_internal_server_error()?;

    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::DomainUpdate,
        Some(Target::new(TargetKind::Domain, params.domain_id)),
        audit::changes(Some(audit::domain(&before)), after.as_ref().map(audit::domain)),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(()))
}

pub(super) async fn delete(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Extension(actor): Extension<Actor>,
    Path(params): Path<DomainParams>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.begin().await?;
    let before = sites::get_domain(&mut tx, workspace, params.domain_id)
        .await
        .log_error("failed to get domain")
        .as_internal_server_error()?
        .ok_or(ApiError::NotFound)?;
    sites::delete_domain(&mut tx, workspace, params.domain_id)
        .await
        .log_error("failed to delete domain")
        .as_internal_server_error()?;

    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::DomainDelete,
        Some(Target::new(TargetKind::Domain, params.domain_id)),
        audit::changes(Some(audit::domain(&before)), None),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(()))
}
