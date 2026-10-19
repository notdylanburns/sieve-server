use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde_json::{Value, json};
use sieve_common::LogError;
use sieve_common::audit::{self, Action, Actor, Filter, Target};
use sieve_common::database::sites::{Domain, Path};
use sieve_common::database::videos::Video;
use sieve_common::database::{PgConnection, WorkspaceId};

use crate::error::{ApiError, IntoApiError};
use crate::state::AppState;
use crate::workspace::OwnerWorkspace;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

pub(crate) async fn record(
    conn: &mut PgConnection,
    actor: &Actor,
    workspace: Option<WorkspaceId>,
    action: Action,
    target: Option<Target>,
    details: Value,
) -> Result<(), ApiError> {
    audit::record(conn, actor, workspace, action, target, details)
        .await
        .log_error("failed to write audit log")
        .as_internal_server_error()
}

pub(crate) fn changes(before: Option<Value>, after: Option<Value>) -> Value {
    json!({ "before": before, "after": after })
}

pub(crate) fn domain(domain: &Domain) -> Value {
    json!({
        "scheme": domain.scheme,
        "domain": domain.domain,
        "approved": domain.approved(),
    })
}

pub(crate) fn path(path: &Path) -> Value {
    json!({ "path": path.path, "approved": path.approved() })
}

pub(crate) fn path_changes(parent: &Domain, before: Option<&Path>, after: Option<&Path>) -> Value {
    json!({
        "domain": { "id": parent.id(), "scheme": parent.scheme, "domain": parent.domain },
        "before": before.map(path),
        "after": after.map(path),
    })
}

pub(crate) fn video(video: &Video) -> Value {
    json!({ "url": video.url, "download": video.download })
}

#[derive(serde::Deserialize)]
pub(crate) struct ListParams {
    before: Option<i64>,
    limit: Option<i64>,
    action: Option<Box<str>>,
    actor: Option<Box<str>>,
}

pub(crate) async fn get(
    State(state): State<AppState>,
    OwnerWorkspace(workspace): OwnerWorkspace,
    Query(params): Query<ListParams>,
) -> Result<impl IntoResponse, ApiError> {
    let filter = Filter {
        workspace: Some(workspace),
        before: params.before,
        since: None,
        action: params.action.as_deref(),
        actor: params.actor.as_deref(),
        limit: params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT),
    };

    let mut conn = state.conn().await?;
    let entries = audit::list(&mut conn, &filter)
        .await
        .log_error("failed to list audit log")
        .as_internal_server_error()?;

    Ok(Json(entries))
}
