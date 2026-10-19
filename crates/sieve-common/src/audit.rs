use std::net::IpAddr;

use chrono::{DateTime, Utc};
use sqlx::Connection;

use crate::database::{PgConnection, Result, WorkspaceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    User,
    Device,
    Cli,
    Anonymous,
}

impl ActorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Device => "device",
            Self::Cli => "cli",
            Self::Anonymous => "anonymous",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub kind: ActorKind,
    pub id: Option<Box<str>>,
    pub label: Box<str>,
    pub ip: Option<IpAddr>,
    pub user_agent: Option<Box<str>>,
}

impl Actor {
    pub fn cli() -> Self {
        Self {
            kind: ActorKind::Cli,
            id: None,
            label: std::env::var("USER").map_or_else(|_| "unknown".into(), String::into_boxed_str),
            ip: None,
            user_agent: None,
        }
    }
}

macro_rules! actions {
    ($($variant:ident = $name:literal),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Action {
            $($variant,)*
        }

        impl Action {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)*
                }
            }
        }
    };
}

actions! {
    AuthLogin = "auth.login",
    AuthLoginFailed = "auth.login_failed",
    AuthLogout = "auth.logout",
    DomainCreate = "domain.create",
    DomainUpdate = "domain.update",
    DomainDelete = "domain.delete",
    PathCreate = "path.create",
    PathUpdate = "path.update",
    PathDelete = "path.delete",
    VideoCreate = "video.create",
    VideoUpdate = "video.update",
    VideoDelete = "video.delete",
    DeviceCreate = "device.create",
    DeviceRevoke = "device.revoke",
    InviteCreate = "invite.create",
    InviteRevoke = "invite.revoke",
    InviteAccept = "invite.accept",
    WorkspaceCreate = "workspace.create",
    MemberAdd = "member.add",
    MemberRemove = "member.remove",
    UserCreate = "user.create",
    UserPasswd = "user.passwd",
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Domain,
    Path,
    Video,
    Device,
    Invite,
    User,
    Workspace,
}

impl TargetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Path => "path",
            Self::Video => "video",
            Self::Device => "device",
            Self::Invite => "invite",
            Self::User => "user",
            Self::Workspace => "workspace",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub kind: TargetKind,
    pub id: String,
}

impl Target {
    pub fn new(kind: TargetKind, id: impl ToString) -> Self {
        Self {
            kind,
            id: id.to_string(),
        }
    }
}

/// Run inside the same transaction as the change being recorded, so neither commits without the other.
pub async fn record(
    conn: &mut PgConnection,
    actor: &Actor,
    workspace: Option<WorkspaceId>,
    action: Action,
    target: Option<Target>,
    details: serde_json::Value,
) -> Result<()> {
    sqlx::query(
        "
        INSERT INTO audit_log (
            workspace_id, actor_kind, actor_id, actor_label,
            action, target_kind, target_id, details, ip, user_agent
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ",
    )
    .bind(workspace)
    .bind(actor.kind.as_str())
    .bind(actor.id.as_deref())
    .bind(actor.label.as_ref())
    .bind(action.as_str())
    .bind(target.as_ref().map(|target| target.kind.as_str()))
    .bind(target.as_ref().map(|target| target.id.as_str()))
    .bind(details)
    .bind(actor.ip)
    .bind(actor.user_agent.as_deref())
    .execute(conn)
    .await?;

    Ok(())
}

#[derive(Debug, Default)]
pub struct Filter<'a> {
    pub workspace: Option<WorkspaceId>,
    /// Only entries with a smaller id, for paging backwards from the newest.
    pub before: Option<i64>,
    pub since: Option<DateTime<Utc>>,
    pub action: Option<&'a str>,
    pub actor: Option<&'a str>,
    pub limit: i64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, sqlx::FromRow)]
pub struct Entry {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub workspace_id: Option<WorkspaceId>,
    pub actor_kind: Box<str>,
    pub actor_id: Option<Box<str>>,
    pub actor_label: Box<str>,
    pub action: Box<str>,
    pub target_kind: Option<Box<str>>,
    pub target_id: Option<Box<str>>,
    pub details: serde_json::Value,
    pub ip: Option<Box<str>>,
    pub user_agent: Option<Box<str>>,
}

/// Newest first. `actor` matches the actor label.
pub async fn list(conn: &mut PgConnection, filter: &Filter<'_>) -> Result<Vec<Entry>> {
    sqlx::query_as(
        "
        SELECT
            id, occurred_at, workspace_id, actor_kind, actor_id, actor_label,
            action, target_kind, target_id, details, host(ip) AS ip, user_agent
        FROM audit_log
        WHERE ($1::uuid IS NULL OR workspace_id = $1)
        AND ($2::bigint IS NULL OR id < $2)
        AND ($3::timestamptz IS NULL OR occurred_at >= $3)
        AND ($4::text IS NULL OR action = $4)
        AND ($5::text IS NULL OR actor_label = $5)
        ORDER BY id DESC
        LIMIT $6
        ",
    )
    .bind(filter.workspace)
    .bind(filter.before)
    .bind(filter.since)
    .bind(filter.action)
    .bind(filter.actor)
    .bind(filter.limit)
    .fetch_all(conn)
    .await
}

/// Deletes entries older than `days`. The append-only trigger only allows this with `sieve.audit_purge` set.
pub async fn purge_older_than(conn: &mut PgConnection, days: u32) -> Result<u64> {
    let mut tx = conn.begin().await?;

    sqlx::query("SELECT set_config('sieve.audit_purge', 'on', true)")
        .execute(&mut *tx)
        .await?;

    let result = sqlx::query(
        "DELETE FROM audit_log WHERE occurred_at < now() - make_interval(days => $1)",
    )
    .bind(i32::try_from(days).unwrap_or(i32::MAX))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::workspaces;
    use serde_json::json;
    use sqlx::PgPool;

    fn user() -> Actor {
        Actor {
            kind: ActorKind::User,
            id: Some("1".into()),
            label: "amanda".into(),
            ip: Some("192.0.2.7".parse().unwrap()),
            user_agent: Some("test".into()),
        }
    }

    async fn count(conn: &mut PgConnection) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(conn)
            .await
            .unwrap()
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn records_entry(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let ws = workspaces::create(&mut conn, "test").await.unwrap();

        record(
            &mut conn,
            &user(),
            Some(ws),
            Action::DomainUpdate,
            Some(Target::new(TargetKind::Domain, 12)),
            json!({"before": {"approved": false}, "after": {"approved": true}}),
        )
        .await
        .unwrap();

        let row: (WorkspaceId, String, String, String, String, String, serde_json::Value, String) =
            sqlx::query_as(
                "
                SELECT workspace_id, actor_kind, actor_label, action, target_kind, target_id,
                       details, host(ip)
                FROM audit_log
                ",
            )
            .fetch_one(&mut *conn)
            .await
            .unwrap();

        assert_eq!(row.0, ws);
        assert_eq!(row.1, "user");
        assert_eq!(row.2, "amanda");
        assert_eq!(row.3, "domain.update");
        assert_eq!(row.4, "domain");
        assert_eq!(row.5, "12");
        assert_eq!(row.6["after"]["approved"], true);
        assert_eq!(row.7, "192.0.2.7");
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn lists_newest_first_with_filters(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let c = &mut *conn;
        let a = workspaces::create(c, "a").await.unwrap();
        let b = workspaces::create(c, "b").await.unwrap();

        record(c, &user(), Some(a), Action::DomainCreate, None, json!({})).await.unwrap();
        record(c, &user(), Some(b), Action::DomainCreate, None, json!({})).await.unwrap();
        record(c, &Actor::cli(), Some(a), Action::MemberAdd, None, json!({})).await.unwrap();
        record(c, &user(), Some(a), Action::DomainDelete, None, json!({})).await.unwrap();

        let all_a = list(c, &Filter { workspace: Some(a), limit: 10, ..Default::default() })
            .await
            .unwrap();
        let actions: Vec<&str> = all_a.iter().map(|entry| entry.action.as_ref()).collect();
        assert_eq!(actions, ["domain.delete", "member.add", "domain.create"]);
        assert_eq!(all_a[0].ip.as_deref(), Some("192.0.2.7"));

        let page = list(
            c,
            &Filter { workspace: Some(a), before: Some(all_a[0].id), limit: 1, ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].action.as_ref(), "member.add");

        let by_actor = list(
            c,
            &Filter { workspace: Some(a), actor: Some("amanda"), limit: 10, ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(by_actor.len(), 2);

        let by_action = list(c, &Filter { action: Some("domain.create"), limit: 10, ..Default::default() })
            .await
            .unwrap();
        assert_eq!(by_action.len(), 2);

        let future = list(
            c,
            &Filter { since: Some(Utc::now() + chrono::TimeDelta::hours(1)), limit: 10, ..Default::default() },
        )
        .await
        .unwrap();
        assert!(future.is_empty());
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn rolled_back_change_leaves_no_entry(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let mut tx = conn.begin().await.unwrap();
        record(&mut tx, &Actor::cli(), None, Action::UserCreate, None, json!({}))
            .await
            .unwrap();
        tx.rollback().await.unwrap();

        assert_eq!(count(&mut conn).await, 0);
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn entries_cannot_be_changed(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        record(&mut conn, &user(), None, Action::AuthLogin, None, json!({}))
            .await
            .unwrap();

        for statement in [
            "UPDATE audit_log SET actor_label = 'someone else'",
            "DELETE FROM audit_log",
            "TRUNCATE audit_log",
        ] {
            let error = sqlx::query(statement).execute(&mut *conn).await.unwrap_err();
            assert!(error.to_string().contains("append-only"), "{statement}: {error}");
        }

        assert_eq!(count(&mut conn).await, 1);
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn purge_removes_only_old_entries(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        record(&mut conn, &user(), None, Action::AuthLogin, None, json!({}))
            .await
            .unwrap();
        sqlx::query(
            "
            INSERT INTO audit_log (occurred_at, actor_kind, actor_label, action)
            VALUES (now() - interval '40 days', 'cli', 'root', 'user.create')
            ",
        )
        .execute(&mut *conn)
        .await
        .unwrap();

        assert_eq!(purge_older_than(&mut conn, 30).await.unwrap(), 1);
        assert_eq!(count(&mut conn).await, 1);

        let error = sqlx::query("DELETE FROM audit_log")
            .execute(&mut *conn)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("append-only"));
    }
}
