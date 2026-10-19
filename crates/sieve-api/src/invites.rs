use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::routing::{Router, delete, get, post};
use axum::{Extension, Json};
use chrono::{DateTime, TimeDelta, Utc};
use serde_json::json;
use sieve_common::LogError;
use sieve_common::audit::{Action, Actor, Target, TargetKind};
use sieve_common::database::invites::{self, Invite};
use sieve_common::database::workspaces::{self, Membership, Role};
use sieve_common::database::{PgConnection, WorkspaceId};
use sieve_common::jwt::Keys;
use uuid::Uuid;

use crate::audit;
use crate::auth::AuthUser;
use crate::error::{ApiError, IntoApiError};
use crate::state::AppState;
use crate::workspace::OwnerWorkspace;

const DEFAULT_EXPIRY_DAYS: u32 = 7;
const MAX_EXPIRY_DAYS: u32 = 30;
const MAX_USES: i32 = 1000;

/// Managing a workspace's invites, for its owners.
pub(crate) fn workspace_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{invite_id}", delete(revoke))
}

/// Opening an invite link, for whoever it was sent to.
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/{token}", get(preview))
        .route("/{token}/accept", post(accept))
}

#[derive(serde::Serialize)]
pub(crate) struct InviteView {
    #[serde(flatten)]
    invite: Invite,
    token: Box<str>,
}

fn view(keys: &Keys, invite: Invite) -> Result<InviteView, ApiError> {
    let token = keys
        .issue_invite(invite.id, invite.workspace_id, invite.expires_at)
        .log_error("failed to sign invite")
        .as_internal_server_error()?;
    Ok(InviteView { invite, token })
}

pub(crate) async fn list(
    State(state): State<AppState>,
    OwnerWorkspace(workspace): OwnerWorkspace,
) -> Result<impl IntoResponse, ApiError> {
    let mut conn = state.conn().await?;
    let invites = invites::list_usable(&mut conn, workspace)
        .await
        .log_error("failed to list invites")
        .as_internal_server_error()?;

    let views = invites
        .into_iter()
        .map(|invite| view(&state.keys, invite))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(views))
}

#[derive(serde::Deserialize)]
pub(crate) struct CreateRequest {
    role: Option<Role>,
    expires_in_days: Option<u32>,
    max_uses: Option<i32>,
}

pub(crate) async fn create(
    State(state): State<AppState>,
    OwnerWorkspace(workspace): OwnerWorkspace,
    AuthUser(user): AuthUser,
    Extension(actor): Extension<Actor>,
    Json(body): Json<CreateRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let days = body.expires_in_days.unwrap_or(DEFAULT_EXPIRY_DAYS);
    if !(1..=MAX_EXPIRY_DAYS).contains(&days) {
        return Err(ApiError::BadRequest("invites must expire in 1 to 30 days"));
    }
    if body.max_uses.is_some_and(|uses| !(1..=MAX_USES).contains(&uses)) {
        return Err(ApiError::BadRequest("max_uses must be between 1 and 1000"));
    }

    let role = body.role.unwrap_or(Role::Member);
    let expires_at = Utc::now() + TimeDelta::days(i64::from(days));

    let mut tx = state.begin().await?;
    let invite = invites::create(&mut tx, workspace, role, user.id, expires_at, body.max_uses)
        .await
        .log_error("failed to create invite")
        .as_internal_server_error()?;
    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::InviteCreate,
        Some(Target::new(TargetKind::Invite, invite.id)),
        json!({ "role": role, "expires_at": invite.expires_at, "max_uses": invite.max_uses }),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(view(&state.keys, invite)?))
}

#[derive(serde::Deserialize)]
pub(crate) struct InviteParams {
    invite_id: Uuid,
}

pub(crate) async fn revoke(
    State(state): State<AppState>,
    OwnerWorkspace(workspace): OwnerWorkspace,
    Extension(actor): Extension<Actor>,
    Path(params): Path<InviteParams>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.begin().await?;
    let invite = invites::revoke(&mut tx, workspace, params.invite_id)
        .await
        .log_error("failed to revoke invite")
        .as_internal_server_error()?
        .ok_or(ApiError::NotFound)?;
    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::InviteRevoke,
        Some(Target::new(TargetKind::Invite, invite.id)),
        json!({ "role": invite.role, "uses": invite.uses }),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(invite))
}

#[derive(serde::Deserialize)]
pub(crate) struct TokenParams {
    token: Box<str>,
}

struct Resolved {
    invite: Invite,
    workspace_name: Box<str>,
    /// The user's current role in the invite's workspace, if any.
    membership: Option<Role>,
}

/// The invite behind a genuinely signed token, and the user's standing in its workspace.
/// Members are told so whatever state the invite is in; anyone else needs a usable invite.
/// Every failure is the same 404, so a link reveals nothing about why it doesn't work.
async fn resolve(
    conn: &mut PgConnection,
    keys: &Keys,
    token: &str,
    user_id: i64,
) -> Result<Resolved, ApiError> {
    let (id, workspace) = keys.verify_invite(token).ok_or(ApiError::NotFound)?;

    let invite = invites::get(conn, id)
        .await
        .log_error("failed to look up invite")
        .as_internal_server_error()?
        .filter(|invite| invite.workspace_id == workspace)
        .ok_or(ApiError::NotFound)?;

    let membership = workspaces::member_role(conn, workspace, user_id)
        .await
        .log_error("failed to look up membership")
        .as_internal_server_error()?;

    if membership.is_none() && !invite.is_usable(Utc::now()) {
        return Err(ApiError::NotFound);
    }

    let workspace_name = workspaces::name(conn, workspace)
        .await
        .log_error("failed to look up workspace")
        .as_internal_server_error()?
        .ok_or(ApiError::NotFound)?;

    Ok(Resolved {
        invite,
        workspace_name,
        membership,
    })
}

#[derive(serde::Serialize)]
struct WorkspaceSummary {
    id: WorkspaceId,
    name: Box<str>,
}

#[derive(serde::Serialize)]
pub(crate) struct Preview {
    workspace: WorkspaceSummary,
    role: Role,
    invited_by: Option<Box<str>>,
    expires_at: DateTime<Utc>,
    /// The user's current role, when they already belong to the workspace.
    membership: Option<Role>,
}

pub(crate) async fn preview(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(params): Path<TokenParams>,
) -> Result<impl IntoResponse, ApiError> {
    let mut conn = state.conn().await?;
    let resolved = resolve(&mut conn, &state.keys, &params.token, user.id).await?;

    Ok(Json(Preview {
        workspace: WorkspaceSummary {
            id: resolved.invite.workspace_id,
            name: resolved.workspace_name,
        },
        role: resolved.invite.role,
        invited_by: resolved.invite.created_by,
        expires_at: resolved.invite.expires_at,
        membership: resolved.membership,
    }))
}

/// Joins the signed-in user to the invite's workspace. Existing members keep their role and
/// don't use up the invite.
pub(crate) async fn accept(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Extension(actor): Extension<Actor>,
    Path(params): Path<TokenParams>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.begin().await?;
    let resolved = resolve(&mut tx, &state.keys, &params.token, user.id).await?;
    let workspace = resolved.invite.workspace_id;
    let name = resolved.workspace_name;

    if let Some(role) = resolved.membership {
        return Ok(Json(Membership { id: workspace, name, role }));
    }

    let invite = invites::consume(&mut tx, resolved.invite.id)
        .await
        .log_error("failed to use invite")
        .as_internal_server_error()?
        .ok_or(ApiError::NotFound)?;

    let added = workspaces::add_member_if_absent(&mut tx, workspace, user.id, invite.role)
        .await
        .log_error("failed to add member")
        .as_internal_server_error()?;
    if !added {
        return Err(ApiError::NotFound);
    }

    audit::record(
        &mut tx,
        &actor,
        Some(workspace),
        Action::InviteAccept,
        Some(Target::new(TargetKind::User, user.id)),
        json!({ "invite": invite.id, "username": user.username, "role": invite.role }),
    )
    .await?;
    tx.commit().await.log_error("failed to commit").as_internal_server_error()?;

    Ok(Json(Membership {
        id: workspace,
        name,
        role: invite.role,
    }))
}
