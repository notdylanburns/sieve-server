use std::collections::HashSet;

use super::{MetadataStatus, PgConnection, Result, WorkspaceId};

macro_rules! scheme_enum {
    (
        $(
            $variant:ident($scheme:literal) = $value:literal
        ),*$(,)?
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize, sqlx::Type)]
        #[serde(rename_all = "lowercase")]
        #[repr(i16)]
        pub enum Scheme {
            $($variant = $value,)*
        }

        impl Scheme {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $scheme,)*
                }
            }
        }

        impl TryFrom<&str> for Scheme {
            type Error = ();

            fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
                match value {
                    $($scheme => Ok(Self::$variant),)*
                    _ => Err(()),
                }
            }
        }

        impl serde::Serialize for Scheme {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }
    };
}

scheme_enum! {
    Any("*") = 0,
    Http("http") = 1,
    Https("https") = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize, sqlx::FromRow)]
pub struct Domain {
    id: i64,
    pub scheme: Scheme,
    pub domain: Box<str>,
    approved: Option<bool>,
    pub title: Option<Box<str>>,
    pub icon: Option<Box<str>>,
    pub fetch_error: Option<Box<str>>,
}

impl Domain {
    pub fn id(&self) -> i64 {
        self.id
    }

    pub fn approved(&self) -> Option<bool> {
        self.approved
    }
}

// Macros rather than consts so the trailing SQL is joined at compile time; sqlx requires 'static queries.
macro_rules! domain_select {
    ($($sql:literal),* $(,)?) => {
        concat!(
        "
        SELECT
            domains.id,
            domains.scheme,
            domains.domain,
            domains.approved,
            domain_metadata.title,
            domain_metadata.icon,
            domain_metadata.fetch_error
        FROM domains
        LEFT JOIN domain_metadata
        ON domain_metadata.domain_id = domains.id
        ",
            $($sql),*
        )
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize, sqlx::FromRow)]
pub struct Path {
    id: i64,
    pub domain_id: i64,
    pub path: Box<str>,
    approved: bool,
    pub title: Option<Box<str>>,
    pub fetch_error: Option<Box<str>>,
}

impl Path {
    pub fn id(&self) -> i64 {
        self.id
    }

    pub fn approved(&self) -> bool {
        self.approved
    }
}

macro_rules! path_select {
    ($($sql:literal),* $(,)?) => {
        concat!(
        "
        SELECT
            paths.id,
            paths.domain_id,
            paths.path,
            paths.approved,
            path_metadata.title,
            path_metadata.fetch_error
        FROM paths
        JOIN domains
        ON domains.id = paths.domain_id
        LEFT JOIN path_metadata
        ON path_metadata.path_id = paths.id
        ",
            $($sql),*
        )
    };
}

#[derive(Debug)]
pub struct SiteApplication {
    pub domain_id: i64,
    pub path_id: Option<i64>,
    pub url: Box<str>,
    pub title: Option<Box<str>>,
    pub icon: Option<Box<str>>,
}

#[derive(sqlx::FromRow)]
struct SiteApplicationRow {
    domain_id: i64,
    path_id: Option<i64>,
    scheme: Scheme,
    domain: Box<str>,
    path: Box<str>,
    title: Option<Box<str>>,
    icon: Option<Box<str>>,
}

impl From<SiteApplicationRow> for SiteApplication {
    fn from(row: SiteApplicationRow) -> Self {
        Self {
            domain_id: row.domain_id,
            path_id: row.path_id,
            url: format!("{}://{}{}", row.scheme.as_str(), row.domain, row.path).into(),
            title: row.title,
            icon: row.icon,
        }
    }
}

const LIST_DOMAINS_DEFAULT_LIMIT: i64 = 100;
const LIST_DOMAIN_PATHS_DEFAULT_LIMIT: i64 = 100;

pub async fn get_domain(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    id: i64,
) -> Result<Option<Domain>> {
    sqlx::query_as(domain_select!(
        "WHERE domains.workspace_id = $1 AND domains.id = $2"
    ))
    .bind(workspace)
    .bind(id)
    .fetch_optional(conn)
    .await
}

pub async fn get_path(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    id: i64,
) -> Result<Option<Path>> {
    sqlx::query_as(path_select!(
        "WHERE domains.workspace_id = $1 AND paths.id = $2"
    ))
    .bind(workspace)
    .bind(id)
    .fetch_optional(conn)
    .await
}

pub async fn query_domain(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    scheme: Scheme,
    domain: &str,
) -> Result<Option<(i64, Option<bool>)>> {
    sqlx::query_as(
        "
        SELECT id, approved
        FROM domains
        WHERE workspace_id = $1
        AND scheme = $2
        AND domain = $3
        ",
    )
    .bind(workspace)
    .bind(scheme)
    .bind(domain)
    .fetch_optional(conn)
    .await
}

// domain_id must come from a workspace-scoped lookup such as query_domain.
pub async fn query_path(
    conn: &mut PgConnection,
    domain_id: i64,
    path: &str,
) -> Result<Option<bool>> {
    sqlx::query_scalar(
        "
        SELECT approved
        FROM paths
        WHERE domain_id = $1
        AND path = $2
        ",
    )
    .bind(domain_id)
    .bind(path)
    .fetch_optional(conn)
    .await
}

pub async fn find_domain(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    scheme: Scheme,
    domain: &str,
) -> Result<Option<Domain>> {
    sqlx::query_as(domain_select!(
        "WHERE domains.workspace_id = $1 AND domains.scheme = $2 AND domains.domain = $3"
    ))
    .bind(workspace)
    .bind(scheme)
    .bind(domain)
    .fetch_optional(conn)
    .await
}

pub async fn find_path(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    domain_id: i64,
    path: &str,
) -> Result<Option<Path>> {
    sqlx::query_as(path_select!(
        "WHERE domains.workspace_id = $1 AND paths.domain_id = $2 AND paths.path = $3"
    ))
    .bind(workspace)
    .bind(domain_id)
    .bind(path)
    .fetch_optional(conn)
    .await
}

pub async fn add_domain(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    scheme: Scheme,
    domain: &str,
    approved: Option<bool>,
) -> Result<Domain> {
    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO domains (workspace_id, scheme, domain, approved)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (workspace_id, scheme, domain) DO
        UPDATE SET approved = excluded.approved
        RETURNING id
        ",
    )
    .bind(workspace)
    .bind(scheme)
    .bind(domain)
    .bind(approved)
    .fetch_one(&mut *conn)
    .await?;

    get_domain(conn, workspace, id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}

pub async fn add_domain_no_approval(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    scheme: Scheme,
    domain: &str,
) -> Result<Domain> {
    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO domains (workspace_id, scheme, domain, approved)
        VALUES ($1, $2, $3, NULL)
        ON CONFLICT (workspace_id, scheme, domain) DO
        UPDATE SET domain = excluded.domain
        RETURNING id
        ",
    )
    .bind(workspace)
    .bind(scheme)
    .bind(domain)
    .fetch_one(&mut *conn)
    .await?;

    get_domain(conn, workspace, id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}

pub async fn list_domains(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<Vec<Domain>> {
    sqlx::query_as(domain_select!(
        "
        WHERE domains.workspace_id = $1
        AND domains.id >= $2
        ORDER BY domains.id
        LIMIT $3
        ",
    ))
    .bind(workspace)
    .bind(offset.unwrap_or(0))
    .bind(limit.unwrap_or(LIST_DOMAINS_DEFAULT_LIMIT))
    .fetch_all(conn)
    .await
}

/// Returns false when the domain does not exist in the workspace.
pub async fn modify_domain(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    id: i64,
    approved: Option<bool>,
) -> Result<bool> {
    let result = sqlx::query(
        "
        UPDATE domains
        SET approved = $3
        WHERE workspace_id = $1
        AND id = $2
        ",
    )
    .bind(workspace)
    .bind(id)
    .bind(approved)
    .execute(conn)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Returns false when the domain does not exist in the workspace.
pub async fn delete_domain(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    id: i64,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM domains WHERE workspace_id = $1 AND id = $2")
        .bind(workspace)
        .bind(id)
        .execute(conn)
        .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn list_paths(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    domain_id: i64,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<Vec<Path>> {
    sqlx::query_as(path_select!(
        "
        WHERE domains.workspace_id = $1
        AND paths.domain_id = $2
        AND paths.id >= $3
        ORDER BY paths.id
        LIMIT $4
        ",
    ))
    .bind(workspace)
    .bind(domain_id)
    .bind(offset.unwrap_or(0))
    .bind(limit.unwrap_or(LIST_DOMAIN_PATHS_DEFAULT_LIMIT))
    .fetch_all(conn)
    .await
}

/// Returns None when the domain does not exist in the workspace.
pub async fn add_path(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    domain_id: i64,
    path: &str,
    approved: bool,
) -> Result<Option<Path>> {
    let id: Option<i64> = sqlx::query_scalar(
        "
        INSERT INTO paths (domain_id, path, approved)
        SELECT id, $3, $4
        FROM domains
        WHERE workspace_id = $1
        AND id = $2
        ON CONFLICT (domain_id, path) DO
        UPDATE SET approved = excluded.approved
        RETURNING id
        ",
    )
    .bind(workspace)
    .bind(domain_id)
    .bind(path)
    .bind(approved)
    .fetch_optional(&mut *conn)
    .await?;

    match id {
        Some(id) => get_path(conn, workspace, id).await,
        None => Ok(None),
    }
}

/// Returns false when the path does not exist under that domain in the workspace.
pub async fn modify_path(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    domain_id: i64,
    path_id: i64,
    approved: bool,
) -> Result<bool> {
    let result = sqlx::query(
        "
        UPDATE paths
        SET approved = $4
        FROM domains
        WHERE domains.id = paths.domain_id
        AND domains.workspace_id = $1
        AND paths.domain_id = $2
        AND paths.id = $3
        ",
    )
    .bind(workspace)
    .bind(domain_id)
    .bind(path_id)
    .bind(approved)
    .execute(conn)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Returns false when the path does not exist under that domain in the workspace.
pub async fn delete_path(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    domain_id: i64,
    path_id: i64,
) -> Result<bool> {
    let result = sqlx::query(
        "
        DELETE FROM paths
        USING domains
        WHERE domains.id = paths.domain_id
        AND domains.workspace_id = $1
        AND paths.domain_id = $2
        AND paths.id = $3
        ",
    )
    .bind(workspace)
    .bind(domain_id)
    .bind(path_id)
    .execute(conn)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_domain_metadata_status(
    conn: &mut PgConnection,
    domain_id: i64,
) -> Result<Option<MetadataStatus>> {
    sqlx::query_as(
        "
        SELECT fetched_at, fetch_error IS NOT NULL AS failed
        FROM domain_metadata
        WHERE domain_id = $1
        AND fetched_at IS NOT NULL
        ",
    )
    .bind(domain_id)
    .fetch_optional(conn)
    .await
}

pub async fn get_path_metadata_status(
    conn: &mut PgConnection,
    path_id: i64,
) -> Result<Option<MetadataStatus>> {
    sqlx::query_as(
        "
        SELECT fetched_at, fetch_error IS NOT NULL AS failed
        FROM path_metadata
        WHERE path_id = $1
        AND fetched_at IS NOT NULL
        ",
    )
    .bind(path_id)
    .fetch_optional(conn)
    .await
}

pub async fn set_domain_metadata(
    conn: &mut PgConnection,
    domain_id: i64,
    title: Option<&str>,
    icon: Option<&str>,
    error: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "
        INSERT INTO domain_metadata (domain_id, title, icon, fetched_at, fetch_error)
        VALUES ($1, $2, $3, now(), $4)
        ON CONFLICT (domain_id) DO
        UPDATE SET
            title = COALESCE(excluded.title, domain_metadata.title),
            icon = COALESCE(excluded.icon, domain_metadata.icon),
            fetched_at = excluded.fetched_at,
            fetch_error = excluded.fetch_error
        ",
    )
    .bind(domain_id)
    .bind(title)
    .bind(icon)
    .bind(error)
    .execute(conn)
    .await?;

    Ok(())
}

pub async fn set_path_metadata(
    conn: &mut PgConnection,
    path_id: i64,
    title: Option<&str>,
    error: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "
        INSERT INTO path_metadata (path_id, title, fetched_at, fetch_error)
        VALUES ($1, $2, now(), $3)
        ON CONFLICT (path_id) DO
        UPDATE SET
            title = COALESCE(excluded.title, path_metadata.title),
            fetched_at = excluded.fetched_at,
            fetch_error = excluded.fetch_error
        ",
    )
    .bind(path_id)
    .bind(title)
    .bind(error)
    .execute(conn)
    .await?;

    Ok(())
}

/// Icons referenced by any workspace; the icon store is shared.
pub async fn list_icons(conn: &mut PgConnection) -> Result<HashSet<Box<str>>> {
    let icons: Vec<Box<str>> = sqlx::query_scalar(
        "
        SELECT DISTINCT icon
        FROM domain_metadata
        WHERE icon IS NOT NULL
        ",
    )
    .fetch_all(conn)
    .await?;

    Ok(icons.into_iter().collect())
}

pub async fn get_web_applications(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
) -> Result<Vec<SiteApplication>> {
    let rows: Vec<SiteApplicationRow> = sqlx::query_as(
        "
        SELECT
            domains.id AS domain_id,
            NULL::BIGINT AS path_id,
            domains.scheme,
            domains.domain,
            '/' AS path,
            domain_metadata.title,
            domain_metadata.icon
        FROM domains
        LEFT JOIN domain_metadata
        ON domain_metadata.domain_id = domains.id
        WHERE domains.workspace_id = $1
        AND domains.approved IS TRUE
        AND NOT EXISTS (
            SELECT 1 FROM paths
            WHERE paths.domain_id = domains.id
            AND paths.path = '/'
            AND NOT paths.approved
        )

        UNION ALL

        SELECT
            domains.id,
            paths.id,
            domains.scheme,
            domains.domain,
            paths.path,
            path_metadata.title,
            domain_metadata.icon
        FROM paths
        JOIN domains
        ON domains.id = paths.domain_id
        LEFT JOIN path_metadata
        ON path_metadata.path_id = paths.id
        LEFT JOIN domain_metadata
        ON domain_metadata.domain_id = domains.id
        WHERE domains.workspace_id = $1
        AND domains.approved IS NOT TRUE
        AND paths.approved

        ORDER BY 1, 2 NULLS FIRST
        ",
    )
    .bind(workspace)
    .fetch_all(conn)
    .await?;

    Ok(rows.into_iter().map(SiteApplication::from).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::workspaces;
    use chrono::{TimeDelta, Utc};
    use sqlx::PgPool;
    use sqlx::pool::PoolConnection;
    use sqlx::postgres::Postgres;

    async fn open(pool: &PgPool) -> (PoolConnection<Postgres>, WorkspaceId) {
        let mut conn = pool.acquire().await.unwrap();
        let ws = workspaces::create(&mut conn, "test").await.unwrap();
        (conn, ws)
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn web_applications_use_domain_icon_and_own_title(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let hello = add_domain(c, ws, Scheme::Https, "hello.com", Some(true)).await.unwrap();
        let wiki = add_domain(c, ws, Scheme::Https, "en.wikipedia.org", Some(false)).await.unwrap();
        add_domain(c, ws, Scheme::Https, "blocked.com", Some(false)).await.unwrap();
        let page = add_path(c, ws, wiki.id, "/wiki/Enrique_Iglesias", true).await.unwrap().unwrap();
        add_path(c, ws, wiki.id, "/wiki/Other", false).await.unwrap();

        set_domain_metadata(c, wiki.id, Some("Wikipedia"), Some("wiki.png"), None).await.unwrap();
        set_path_metadata(c, page.id, Some("Enrique Iglesias"), None).await.unwrap();

        let apps = get_web_applications(c, ws).await.unwrap();
        assert_eq!(apps.len(), 2);

        assert_eq!(apps[0].domain_id, hello.id);
        assert_eq!(apps[0].path_id, None);
        assert_eq!(apps[0].url.as_ref(), "https://hello.com/");
        assert_eq!(apps[0].title, None);
        assert_eq!(apps[0].icon, None);

        assert_eq!(apps[1].domain_id, wiki.id);
        assert_eq!(apps[1].path_id, Some(page.id));
        assert_eq!(apps[1].url.as_ref(), "https://en.wikipedia.org/wiki/Enrique_Iglesias");
        assert_eq!(apps[1].title.as_deref(), Some("Enrique Iglesias"));
        assert_eq!(apps[1].icon.as_deref(), Some("wiki.png"));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn paths_only_domain_lists_approved_paths_as_applications(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let wiki = add_domain_no_approval(c, ws, Scheme::Https, "en.wikipedia.org").await.unwrap();
        let page = add_path(c, ws, wiki.id, "/wiki/Enrique_Iglesias", true).await.unwrap().unwrap();
        add_path(c, ws, wiki.id, "/wiki/Other", false).await.unwrap();

        assert_eq!(
            query_domain(c, ws, Scheme::Https, "en.wikipedia.org").await.unwrap(),
            Some((wiki.id, None))
        );

        let apps = get_web_applications(c, ws).await.unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].path_id, Some(page.id));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn add_domain_no_approval_keeps_existing_approval(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let hello = add_domain(c, ws, Scheme::Https, "hello.com", Some(false)).await.unwrap();
        add_domain_no_approval(c, ws, Scheme::Https, "hello.com").await.unwrap();

        assert_eq!(
            query_domain(c, ws, Scheme::Https, "hello.com").await.unwrap(),
            Some((hello.id, Some(false)))
        );

        assert!(modify_domain(c, ws, hello.id, None).await.unwrap());
        assert_eq!(
            query_domain(c, ws, Scheme::Https, "hello.com").await.unwrap(),
            Some((hello.id, None))
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn approved_domain_with_blocked_path_is_still_an_application(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let hello = add_domain(c, ws, Scheme::Https, "hello.com", Some(true)).await.unwrap();
        add_path(c, ws, hello.id, "/private", false).await.unwrap();
        let root_blocked = add_domain(c, ws, Scheme::Https, "root.com", Some(true)).await.unwrap();
        add_path(c, ws, root_blocked.id, "/", false).await.unwrap();

        let apps = get_web_applications(c, ws).await.unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].domain_id, hello.id);
        assert_eq!(apps[0].path_id, None);
        assert_eq!(apps[0].url.as_ref(), "https://hello.com/");
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn metadata_is_deleted_with_domain(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let wiki = add_domain(c, ws, Scheme::Https, "en.wikipedia.org", Some(false)).await.unwrap();
        let page = add_path(c, ws, wiki.id, "/wiki/Enrique_Iglesias", true).await.unwrap().unwrap();
        set_domain_metadata(c, wiki.id, None, Some("wiki.png"), None).await.unwrap();
        set_path_metadata(c, page.id, Some("Enrique Iglesias"), None).await.unwrap();

        assert!(delete_domain(c, ws, wiki.id).await.unwrap());

        let remaining: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM domain_metadata) + (SELECT COUNT(*) FROM path_metadata)",
        )
        .fetch_one(&mut *c)
        .await
        .unwrap();
        assert_eq!(remaining, 0);
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn failed_fetch_keeps_previous_metadata(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let wiki = add_domain(c, ws, Scheme::Https, "en.wikipedia.org", Some(false)).await.unwrap();
        let page = add_path(c, ws, wiki.id, "/wiki/Enrique_Iglesias", true).await.unwrap().unwrap();

        assert_eq!(get_domain_metadata_status(c, wiki.id).await.unwrap(), None);
        assert_eq!(get_path_metadata_status(c, page.id).await.unwrap(), None);

        set_domain_metadata(c, wiki.id, None, Some("wiki.png"), None).await.unwrap();
        set_path_metadata(c, page.id, Some("Enrique Iglesias"), None).await.unwrap();
        assert!(!get_domain_metadata_status(c, wiki.id).await.unwrap().unwrap().failed);

        set_domain_metadata(c, wiki.id, None, None, Some("timeout")).await.unwrap();
        set_path_metadata(c, page.id, None, Some("timeout")).await.unwrap();
        assert!(get_domain_metadata_status(c, wiki.id).await.unwrap().unwrap().failed);
        assert!(get_path_metadata_status(c, page.id).await.unwrap().unwrap().failed);

        let apps = get_web_applications(c, ws).await.unwrap();
        assert_eq!(apps[0].title.as_deref(), Some("Enrique Iglesias"));
        assert_eq!(apps[0].icon.as_deref(), Some("wiki.png"));
        assert_eq!(
            list_icons(c).await.unwrap(),
            ["wiki.png".into()].into_iter().collect()
        );
    }

    #[test]
    fn metadata_staleness() {
        let day = TimeDelta::days(1);
        let epoch = chrono::DateTime::<Utc>::UNIX_EPOCH;
        let ok = Some(MetadataStatus { fetched_at: epoch, failed: false });
        let failed = Some(MetadataStatus { fetched_at: epoch, failed: true });

        assert!(MetadataStatus::is_stale(None, epoch));
        assert!(!MetadataStatus::is_stale(ok, epoch + day * 29));
        assert!(MetadataStatus::is_stale(ok, epoch + day * 30));
        assert!(!MetadataStatus::is_stale(failed, epoch + day - TimeDelta::seconds(1)));
        assert!(MetadataStatus::is_stale(failed, epoch + day));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn find_domain_and_path(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let wiki = add_domain(c, ws, Scheme::Https, "en.wikipedia.org", Some(false)).await.unwrap();
        let page = add_path(c, ws, wiki.id, "/wiki/Enrique_Iglesias", true).await.unwrap().unwrap();

        assert_eq!(
            find_domain(c, ws, Scheme::Https, "en.wikipedia.org").await.unwrap(),
            Some(wiki.clone())
        );
        assert_eq!(find_domain(c, ws, Scheme::Http, "en.wikipedia.org").await.unwrap(), None);
        assert_eq!(
            find_path(c, ws, wiki.id, "/wiki/Enrique_Iglesias").await.unwrap(),
            Some(page)
        );
        assert_eq!(find_path(c, ws, wiki.id, "/wiki/Other").await.unwrap(), None);
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn domains_and_paths_include_metadata(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let hello = add_domain(c, ws, Scheme::Https, "hello.com", Some(true)).await.unwrap();
        let wiki = add_domain(c, ws, Scheme::Https, "en.wikipedia.org", Some(false)).await.unwrap();
        let page = add_path(c, ws, wiki.id, "/wiki/Enrique_Iglesias", true).await.unwrap().unwrap();
        let other = add_path(c, ws, wiki.id, "/wiki/Other", true).await.unwrap().unwrap();

        set_domain_metadata(c, hello.id, Some("Hello"), Some("hello.png"), None).await.unwrap();
        set_domain_metadata(c, wiki.id, None, None, Some("timeout")).await.unwrap();
        set_path_metadata(c, page.id, Some("Enrique Iglesias"), None).await.unwrap();

        let domains = list_domains(c, ws, None, None).await.unwrap();
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0].title.as_deref(), Some("Hello"));
        assert_eq!(domains[0].icon.as_deref(), Some("hello.png"));
        assert_eq!(domains[0].fetch_error, None);
        assert_eq!(domains[1].title, None);
        assert_eq!(domains[1].icon, None);
        assert_eq!(domains[1].fetch_error.as_deref(), Some("timeout"));

        let paths = list_paths(c, ws, wiki.id, None, None).await.unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].title.as_deref(), Some("Enrique Iglesias"));
        assert_eq!(paths[1].id, other.id);
        assert_eq!(paths[1].title, None);

        assert_eq!(
            get_domain(c, ws, hello.id).await.unwrap().unwrap().icon.as_deref(),
            Some("hello.png")
        );
        assert_eq!(
            get_path(c, ws, page.id).await.unwrap().unwrap().title.as_deref(),
            Some("Enrique Iglesias")
        );

        let json = serde_json::to_value(&domains[0]).unwrap();
        assert_eq!(json["title"], "Hello");
        assert_eq!(json["icon"], "hello.png");
        assert!(json["fetch_error"].is_null());
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn workspaces_are_isolated(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let other = workspaces::create(c, "other").await.unwrap();

        let wiki = add_domain(c, ws, Scheme::Https, "en.wikipedia.org", Some(true)).await.unwrap();
        let page = add_path(c, ws, wiki.id, "/wiki/Page", false).await.unwrap().unwrap();
        let same = add_domain(c, other, Scheme::Https, "en.wikipedia.org", Some(false)).await.unwrap();
        assert_ne!(wiki.id, same.id);

        assert_eq!(get_domain(c, other, wiki.id).await.unwrap(), None);
        assert_eq!(get_path(c, other, page.id).await.unwrap(), None);
        assert_eq!(list_domains(c, other, None, None).await.unwrap(), vec![same.clone()]);
        assert!(list_paths(c, other, wiki.id, None, None).await.unwrap().is_empty());
        assert!(get_web_applications(c, other).await.unwrap().is_empty());
        assert_eq!(
            query_domain(c, other, Scheme::Https, "en.wikipedia.org").await.unwrap(),
            Some((same.id, Some(false)))
        );

        assert_eq!(add_path(c, other, wiki.id, "/x", true).await.unwrap(), None);
        assert!(!modify_domain(c, other, wiki.id, Some(false)).await.unwrap());
        assert!(!modify_path(c, other, wiki.id, page.id, true).await.unwrap());
        assert!(!delete_path(c, other, wiki.id, page.id).await.unwrap());
        assert!(!delete_domain(c, other, wiki.id).await.unwrap());

        assert_eq!(get_domain(c, ws, wiki.id).await.unwrap(), Some(wiki));
        assert_eq!(get_path(c, ws, page.id).await.unwrap(), Some(page));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn path_changes_require_matching_domain(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let a = add_domain(c, ws, Scheme::Https, "a.com", Some(true)).await.unwrap();
        let b = add_domain(c, ws, Scheme::Https, "b.com", Some(true)).await.unwrap();
        let path = add_path(c, ws, a.id, "/x", false).await.unwrap().unwrap();

        assert!(!modify_path(c, ws, b.id, path.id, true).await.unwrap());
        assert!(!delete_path(c, ws, b.id, path.id).await.unwrap());
        assert!(modify_path(c, ws, a.id, path.id, true).await.unwrap());
        assert!(get_path(c, ws, path.id).await.unwrap().unwrap().approved);
        assert!(delete_path(c, ws, a.id, path.id).await.unwrap());
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn stale_after_refresh_interval(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let hello = add_domain(c, ws, Scheme::Https, "hello.com", Some(true)).await.unwrap();
        set_domain_metadata(c, hello.id, Some("Hello"), None, None).await.unwrap();

        let status = get_domain_metadata_status(c, hello.id).await.unwrap();
        assert!(!MetadataStatus::is_stale(status, Utc::now()));
        assert!(MetadataStatus::is_stale(status, Utc::now() + TimeDelta::days(31)));
    }
}
