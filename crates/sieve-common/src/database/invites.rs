use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::workspaces::Role;
use super::{PgConnection, Result, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Invite {
    pub id: Uuid,
    pub workspace_id: WorkspaceId,
    pub role: Role,
    pub created_by: Option<Box<str>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: Option<i32>,
    pub uses: i32,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct InviteRow {
    id: Uuid,
    workspace_id: WorkspaceId,
    role: Box<str>,
    created_by: Option<Box<str>>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    max_uses: Option<i32>,
    uses: i32,
    revoked_at: Option<DateTime<Utc>>,
}

impl TryFrom<InviteRow> for Invite {
    type Error = sqlx::Error;

    fn try_from(row: InviteRow) -> Result<Self> {
        Ok(Self {
            id: row.id,
            workspace_id: row.workspace_id,
            role: row
                .role
                .parse()
                .map_err(|e: Box<str>| sqlx::Error::Decode(e.into_string().into()))?,
            created_by: row.created_by,
            created_at: row.created_at,
            expires_at: row.expires_at,
            max_uses: row.max_uses,
            uses: row.uses,
            revoked_at: row.revoked_at,
        })
    }
}

impl Invite {
    pub fn is_usable(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none()
            && self.expires_at > now
            && self.max_uses.is_none_or(|max| self.uses < max)
    }
}

// The creator's username is joined in; a macro so queries stay 'static for sqlx.
macro_rules! invite_select {
    ($($sql:literal),* $(,)?) => {
        concat!(
        "
        SELECT
            invites.id, invites.workspace_id, invites.role, users.username AS created_by,
            invites.created_at, invites.expires_at, invites.max_uses, invites.uses,
            invites.revoked_at
        FROM invites
        LEFT JOIN users
        ON users.id = invites.created_by
        ",
            $($sql),*
        )
    };
}

async fn by_id(conn: &mut PgConnection, id: Uuid) -> Result<Option<Invite>> {
    sqlx::query_as::<_, InviteRow>(invite_select!("WHERE invites.id = $1"))
        .bind(id)
        .fetch_optional(conn)
        .await?
        .map(Invite::try_from)
        .transpose()
}

pub async fn create(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    role: Role,
    created_by: i64,
    expires_at: DateTime<Utc>,
    max_uses: Option<i32>,
) -> Result<Invite> {
    let id: Uuid = sqlx::query_scalar(
        "
        INSERT INTO invites (workspace_id, role, created_by, expires_at, max_uses)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        ",
    )
    .bind(workspace)
    .bind(role.as_str())
    .bind(created_by)
    .bind(expires_at)
    .bind(max_uses)
    .fetch_one(&mut *conn)
    .await?;

    by_id(conn, id).await?.ok_or(sqlx::Error::RowNotFound)
}

/// Returns the invite in any state; check `is_usable` before honouring it.
pub async fn get(conn: &mut PgConnection, id: Uuid) -> Result<Option<Invite>> {
    by_id(conn, id).await
}

/// Invites in the workspace that can still be accepted, newest first.
pub async fn list_usable(conn: &mut PgConnection, workspace: WorkspaceId) -> Result<Vec<Invite>> {
    sqlx::query_as::<_, InviteRow>(invite_select!(
        "
        WHERE invites.workspace_id = $1
        AND invites.revoked_at IS NULL
        AND invites.expires_at > now()
        AND (invites.max_uses IS NULL OR invites.uses < invites.max_uses)
        ORDER BY invites.created_at DESC
        "
    ))
    .bind(workspace)
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(Invite::try_from)
    .collect()
}

/// Returns None when the invite is unknown, already revoked, or in another workspace.
pub async fn revoke(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    id: Uuid,
) -> Result<Option<Invite>> {
    let revoked: Option<Uuid> = sqlx::query_scalar(
        "
        UPDATE invites
        SET revoked_at = now()
        WHERE id = $1
        AND workspace_id = $2
        AND revoked_at IS NULL
        RETURNING id
        ",
    )
    .bind(id)
    .bind(workspace)
    .fetch_optional(&mut *conn)
    .await?;

    match revoked {
        Some(id) => by_id(conn, id).await,
        None => Ok(None),
    }
}

/// Counts one use, atomically refusing invites that are revoked, expired or used up.
pub async fn consume(conn: &mut PgConnection, id: Uuid) -> Result<Option<Invite>> {
    let consumed: Option<Uuid> = sqlx::query_scalar(
        "
        UPDATE invites
        SET uses = uses + 1
        WHERE id = $1
        AND revoked_at IS NULL
        AND expires_at > now()
        AND (max_uses IS NULL OR uses < max_uses)
        RETURNING id
        ",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;

    match consumed {
        Some(id) => by_id(conn, id).await,
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeDelta;
    use sqlx::PgPool;

    use super::*;
    use crate::database::{users, workspaces};

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn single_use_invites_are_consumed_once(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let c = &mut *conn;
        let ws = workspaces::create(c, "home").await.unwrap();
        let owner = users::create(c, "owner", "hash").await.unwrap();
        let expires = Utc::now() + TimeDelta::days(1);

        let invite = create(c, ws, Role::Member, owner.id, expires, Some(1)).await.unwrap();
        assert_eq!(invite.created_by.as_deref(), Some("owner"));
        assert!(invite.is_usable(Utc::now()));
        assert_eq!(list_usable(c, ws).await.unwrap(), vec![invite.clone()]);

        let used = consume(c, invite.id).await.unwrap().unwrap();
        assert_eq!(used.uses, 1);
        assert!(!used.is_usable(Utc::now()));
        assert_eq!(consume(c, invite.id).await.unwrap(), None);
        assert!(list_usable(c, ws).await.unwrap().is_empty());
        assert_eq!(get(c, invite.id).await.unwrap(), Some(used));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn expired_and_revoked_invites_are_refused(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let c = &mut *conn;
        let ws = workspaces::create(c, "home").await.unwrap();
        let other = workspaces::create(c, "other").await.unwrap();
        let owner = users::create(c, "owner", "hash").await.unwrap();

        let expired = create(c, ws, Role::Member, owner.id, Utc::now() - TimeDelta::seconds(1), None)
            .await
            .unwrap();
        assert!(!expired.is_usable(Utc::now()));
        assert_eq!(consume(c, expired.id).await.unwrap(), None);

        let open = create(c, ws, Role::Owner, owner.id, Utc::now() + TimeDelta::days(1), None)
            .await
            .unwrap();
        assert_eq!(consume(c, open.id).await.unwrap().unwrap().uses, 1);
        assert_eq!(consume(c, open.id).await.unwrap().unwrap().uses, 2);

        assert_eq!(revoke(c, other, open.id).await.unwrap(), None);
        let revoked = revoke(c, ws, open.id).await.unwrap().unwrap();
        assert!(revoked.revoked_at.is_some());
        assert_eq!(revoke(c, ws, open.id).await.unwrap(), None);
        assert_eq!(consume(c, open.id).await.unwrap(), None);
        assert!(list_usable(c, ws).await.unwrap().is_empty());
    }
}
