use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use sieve_common::LogError;
use sieve_common::audit::{Action, Actor, Target, TargetKind};
use sieve_common::database::videos::{self, Video};
use sieve_common::database::{PgConnection, WorkspaceId};

use crate::audit;
use crate::common::PaginationParams;
use crate::error::{ApiError, IntoApiError};
use crate::state::AppState;
use crate::workspace::Workspace;

#[derive(serde::Deserialize)]
pub(super) struct VideoParams {
    video_id: i64,
}

pub(super) async fn get(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Query(query): Query<PaginationParams>,
) -> Result<impl IntoResponse, ApiError> {
    let mut conn = state.conn().await?;
    let videos = videos::list_videos(&mut conn, workspace, query.offset(), query.limit())
        .await
        .log_error("failed to list videos")
        .as_internal_server_error()?;

    Ok(Json(videos))
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PostRequest {
    url: Box<str>,
    #[serde(default)]
    download: bool,
}

pub(super) async fn post(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Extension(actor): Extension<Actor>,
    Json(body): Json<PostRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let url = url::Url::parse(body.url.trim())
        .ok()
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .ok_or(ApiError::BadRequest("url must be an http or https URL"))?;

    let mut tx = state.begin().await?;
    let before = videos::find_video(&mut tx, workspace, url.as_str())
        .await
        .log_error("failed to find video")
        .as_internal_server_error()?;
    let video = videos::add_video(&mut tx, workspace, url.as_str(), body.download)
        .await
        .log_error("failed to add video")
        .as_internal_server_error()?;

    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::VideoCreate,
        Some(Target::new(TargetKind::Video, video.id)),
        audit::changes(before.as_ref().map(audit::video), Some(audit::video(&video))),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(video))
}

async fn existing_video(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    video_id: i64,
) -> Result<Video, ApiError> {
    videos::get_video(conn, workspace, video_id)
        .await
        .log_error("failed to get video")
        .as_internal_server_error()?
        .ok_or(ApiError::NotFound)
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PatchRequest {
    download: bool,
}

pub(super) async fn patch(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Extension(actor): Extension<Actor>,
    Path(params): Path<VideoParams>,
    Json(body): Json<PatchRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.begin().await?;
    let before = existing_video(&mut tx, workspace, params.video_id).await?;
    videos::modify_video(&mut tx, workspace, params.video_id, body.download)
        .await
        .log_error("failed to modify video")
        .as_internal_server_error()?;
    let after = existing_video(&mut tx, workspace, params.video_id).await?;

    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::VideoUpdate,
        Some(Target::new(TargetKind::Video, params.video_id)),
        audit::changes(Some(audit::video(&before)), Some(audit::video(&after))),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(()))
}

pub(super) async fn delete(
    State(state): State<AppState>,
    Workspace(workspace): Workspace,
    Extension(actor): Extension<Actor>,
    Path(params): Path<VideoParams>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.begin().await?;
    let before = existing_video(&mut tx, workspace, params.video_id).await?;
    videos::delete_video(&mut tx, workspace, params.video_id)
        .await
        .log_error("failed to delete video")
        .as_internal_server_error()?;

    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::VideoDelete,
        Some(Target::new(TargetKind::Video, params.video_id)),
        audit::changes(Some(audit::video(&before)), None),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(()))
}
