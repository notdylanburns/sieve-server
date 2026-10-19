use super::{PgConnection, Result, WorkspaceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Member,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Member => "member",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = Box<str>;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "owner" => Ok(Self::Owner),
            "member" => Ok(Self::Member),
            _ => Err(format!("unknown role '{s}'").into()),
        }
    }
}

fn parse_role(role: &str) -> Result<Role> {
    role.parse()
        .map_err(|e: Box<str>| sqlx::Error::Decode(e.into_string().into()))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Membership {
    pub id: WorkspaceId,
    pub name: Box<str>,
    pub role: Role,
}

pub async fn create(conn: &mut PgConnection, name: &str) -> Result<WorkspaceId> {
    sqlx::query_scalar("INSERT INTO workspaces (name) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(conn)
        .await
}

pub async fn exists(conn: &mut PgConnection, id: WorkspaceId) -> Result<bool> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM workspaces WHERE id = $1)")
        .bind(id)
        .fetch_one(conn)
        .await
}

pub async fn list_ids(conn: &mut PgConnection) -> Result<Vec<WorkspaceId>> {
    sqlx::query_scalar("SELECT id FROM workspaces ORDER BY created_at")
        .fetch_all(conn)
        .await
}

/// Adds the user, or changes their role if they are already a member.
pub async fn add_member(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    user_id: i64,
    role: Role,
) -> Result<()> {
    sqlx::query(
        "
        INSERT INTO workspace_members (workspace_id, user_id, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (workspace_id, user_id) DO
        UPDATE SET role = excluded.role
        ",
    )
    .bind(workspace)
    .bind(user_id)
    .bind(role.as_str())
    .execute(conn)
    .await?;

    Ok(())
}

/// Adds the user unless they are already a member, leaving an existing role alone.
/// Returns whether they were added.
pub async fn add_member_if_absent(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    user_id: i64,
    role: Role,
) -> Result<bool> {
    let result = sqlx::query(
        "
        INSERT INTO workspace_members (workspace_id, user_id, role)
        VALUES ($1, $2, $3)
        ON CONFLICT (workspace_id, user_id) DO NOTHING
        ",
    )
    .bind(workspace)
    .bind(user_id)
    .bind(role.as_str())
    .execute(conn)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn name(conn: &mut PgConnection, id: WorkspaceId) -> Result<Option<Box<str>>> {
    sqlx::query_scalar("SELECT name FROM workspaces WHERE id = $1")
        .bind(id)
        .fetch_optional(conn)
        .await
}

/// Returns false when the user was not a member.
pub async fn remove_member(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    user_id: i64,
) -> Result<bool> {
    let result =
        sqlx::query("DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2")
            .bind(workspace)
            .bind(user_id)
            .execute(conn)
            .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn member_role(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    user_id: i64,
) -> Result<Option<Role>> {
    let role: Option<Box<str>> = sqlx::query_scalar(
        "SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2",
    )
    .bind(workspace)
    .bind(user_id)
    .fetch_optional(conn)
    .await?;

    role.as_deref().map(parse_role).transpose()
}

pub async fn list_for_user(conn: &mut PgConnection, user_id: i64) -> Result<Vec<Membership>> {
    let rows: Vec<(WorkspaceId, Box<str>, Box<str>)> = sqlx::query_as(
        "
        SELECT workspaces.id, workspaces.name, workspace_members.role
        FROM workspace_members
        JOIN workspaces
        ON workspaces.id = workspace_members.workspace_id
        WHERE workspace_members.user_id = $1
        ORDER BY workspaces.created_at
        ",
    )
    .bind(user_id)
    .fetch_all(conn)
    .await?;

    rows.into_iter()
        .map(|(id, name, role)| {
            Ok(Membership {
                id,
                name,
                role: parse_role(&role)?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::users;
    use sqlx::PgPool;

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn membership_roles(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let c = &mut *conn;
        let a = create(c, "a").await.unwrap();
        let b = create(c, "b").await.unwrap();
        let user = users::create(c, "amanda", "hash").await.unwrap();

        assert_eq!(member_role(c, a, user.id).await.unwrap(), None);
        assert!(list_for_user(c, user.id).await.unwrap().is_empty());

        add_member(c, a, user.id, Role::Member).await.unwrap();
        add_member(c, b, user.id, Role::Owner).await.unwrap();
        add_member(c, a, user.id, Role::Owner).await.unwrap();

        assert_eq!(member_role(c, a, user.id).await.unwrap(), Some(Role::Owner));
        let memberships = list_for_user(c, user.id).await.unwrap();
        assert_eq!(memberships.len(), 2);
        assert_eq!(memberships[0].id, a);
        assert_eq!(memberships[0].name.as_ref(), "a");

        assert!(!add_member_if_absent(c, a, user.id, Role::Member).await.unwrap());
        assert_eq!(member_role(c, a, user.id).await.unwrap(), Some(Role::Owner), "not downgraded");
        assert_eq!(name(c, a).await.unwrap().as_deref(), Some("a"));

        assert!(remove_member(c, a, user.id).await.unwrap());
        assert!(add_member_if_absent(c, a, user.id, Role::Member).await.unwrap());
        assert_eq!(member_role(c, a, user.id).await.unwrap(), Some(Role::Member));
        assert!(remove_member(c, a, user.id).await.unwrap());
        assert!(!remove_member(c, a, user.id).await.unwrap());
        assert_eq!(member_role(c, a, user.id).await.unwrap(), None);
        assert_eq!(member_role(c, b, user.id).await.unwrap(), Some(Role::Owner));
    }
}
