use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{PgConnection, Result, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct Device {
    pub id: Uuid,
    pub workspace_id: WorkspaceId,
    pub name: Box<str>,
    pub proxy_username: Box<str>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub async fn create(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    name: &str,
    proxy_username: &str,
    proxy_password_hash: &str,
) -> Result<Device> {
    sqlx::query_as(
        "
        INSERT INTO devices (workspace_id, name, proxy_username, proxy_password_hash)
        VALUES ($1, $2, $3, $4)
        RETURNING id, workspace_id, name, proxy_username, revoked_at, created_at
        ",
    )
    .bind(workspace)
    .bind(name)
    .bind(proxy_username)
    .bind(proxy_password_hash)
    .fetch_one(conn)
    .await
}

/// Returns None for unknown and revoked devices.
pub async fn get_active(conn: &mut PgConnection, id: Uuid) -> Result<Option<Device>> {
    sqlx::query_as(
        "
        SELECT id, workspace_id, name, proxy_username, revoked_at, created_at
        FROM devices
        WHERE id = $1
        AND revoked_at IS NULL
        ",
    )
    .bind(id)
    .fetch_optional(conn)
    .await
}

/// The workspace and password hash for an active device's proxy username.
pub async fn find_proxy_credentials(
    conn: &mut PgConnection,
    proxy_username: &str,
) -> Result<Option<(WorkspaceId, Box<str>)>> {
    sqlx::query_as(
        "
        SELECT workspace_id, proxy_password_hash
        FROM devices
        WHERE proxy_username = $1
        AND revoked_at IS NULL
        ",
    )
    .bind(proxy_username)
    .fetch_optional(conn)
    .await
}

/// All devices in the workspace, revoked ones included, newest first.
pub async fn list(conn: &mut PgConnection, workspace: WorkspaceId) -> Result<Vec<Device>> {
    sqlx::query_as(
        "
        SELECT id, workspace_id, name, proxy_username, revoked_at, created_at
        FROM devices
        WHERE workspace_id = $1
        ORDER BY created_at DESC
        ",
    )
    .bind(workspace)
    .fetch_all(conn)
    .await
}

/// Returns None when the device is unknown, already revoked, or (with `workspace`) in another workspace.
pub async fn revoke(
    conn: &mut PgConnection,
    id: Uuid,
    workspace: Option<WorkspaceId>,
) -> Result<Option<Device>> {
    sqlx::query_as(
        "
        UPDATE devices
        SET revoked_at = now()
        WHERE id = $1
        AND ($2::uuid IS NULL OR workspace_id = $2)
        AND revoked_at IS NULL
        RETURNING id, workspace_id, name, proxy_username, revoked_at, created_at
        ",
    )
    .bind(id)
    .bind(workspace)
    .fetch_optional(conn)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::workspaces;
    use sqlx::PgPool;

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn revoked_devices_are_inactive(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let c = &mut *conn;
        let ws = workspaces::create(c, "test").await.unwrap();
        let device = create(c, ws, "laptop", "dev-1", "hash").await.unwrap();

        let other = workspaces::create(c, "other").await.unwrap();
        assert_eq!(get_active(c, device.id).await.unwrap(), Some(device.clone()));
        assert_eq!(list(c, ws).await.unwrap(), vec![device.clone()]);
        assert!(list(c, other).await.unwrap().is_empty());

        assert_eq!(
            find_proxy_credentials(c, "dev-1").await.unwrap(),
            Some((ws, "hash".into()))
        );
        assert_eq!(find_proxy_credentials(c, "dev-2").await.unwrap(), None);

        assert_eq!(revoke(c, device.id, Some(other)).await.unwrap(), None);
        let revoked = revoke(c, device.id, Some(ws)).await.unwrap().unwrap();
        assert!(revoked.revoked_at.is_some());
        assert_eq!(get_active(c, device.id).await.unwrap(), None);
        assert_eq!(find_proxy_credentials(c, "dev-1").await.unwrap(), None);
        assert_eq!(revoke(c, device.id, None).await.unwrap(), None);
        assert_eq!(list(c, ws).await.unwrap(), vec![revoked]);
    }
}
