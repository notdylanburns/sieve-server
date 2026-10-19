use std::collections::HashSet;

use super::{MetadataStatus, PgConnection, Result, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize, sqlx::FromRow)]
pub struct Video {
    pub id: i64,
    pub url: Box<str>,
    pub download: bool,
    pub title: Option<Box<str>>,
    pub uploader: Option<Box<str>>,
    pub duration: Option<i32>,
    pub thumbnail: Option<Box<str>>,
    pub fetch_error: Option<Box<str>>,
}

// A macro rather than a const so the trailing SQL is joined at compile time; sqlx requires 'static queries.
macro_rules! video_select {
    ($($sql:literal),* $(,)?) => {
        concat!(
        "
        SELECT
            videos.id,
            videos.url,
            videos.download,
            video_metadata.title,
            video_metadata.uploader,
            video_metadata.duration,
            video_metadata.thumbnail,
            video_metadata.fetch_error
        FROM videos
        LEFT JOIN video_metadata
        ON video_metadata.video_id = videos.id
        ",
            $($sql),*
        )
    };
}

#[derive(Debug, sqlx::FromRow)]
pub struct VideoApplication {
    pub id: i64,
    pub url: Box<str>,
    pub title: Option<Box<str>>,
    pub thumbnail: Option<Box<str>>,
}

#[derive(Debug, Default)]
pub struct VideoMetadata<'a> {
    pub title: Option<&'a str>,
    pub uploader: Option<&'a str>,
    pub duration: Option<u32>,
    pub thumbnail: Option<&'a str>,
}

const LIST_VIDEOS_DEFAULT_LIMIT: i64 = 100;

pub async fn get_video(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    id: i64,
) -> Result<Option<Video>> {
    sqlx::query_as(video_select!(
        "WHERE videos.workspace_id = $1 AND videos.id = $2"
    ))
    .bind(workspace)
    .bind(id)
    .fetch_optional(conn)
    .await
}

pub async fn find_video(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    url: &str,
) -> Result<Option<Video>> {
    sqlx::query_as(video_select!(
        "WHERE videos.workspace_id = $1 AND videos.url = $2"
    ))
    .bind(workspace)
    .bind(url)
    .fetch_optional(conn)
    .await
}

pub async fn add_video(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    url: &str,
    download: bool,
) -> Result<Video> {
    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO videos (workspace_id, url, download)
        VALUES ($1, $2, $3)
        ON CONFLICT (workspace_id, url) DO
        UPDATE SET download = excluded.download
        RETURNING id
        ",
    )
    .bind(workspace)
    .bind(url)
    .bind(download)
    .fetch_one(&mut *conn)
    .await?;

    get_video(conn, workspace, id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}

pub async fn list_videos(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<Vec<Video>> {
    sqlx::query_as(video_select!(
        "
        WHERE videos.workspace_id = $1
        AND videos.id >= $2
        ORDER BY videos.id
        LIMIT $3
        ",
    ))
    .bind(workspace)
    .bind(offset.unwrap_or(0))
    .bind(limit.unwrap_or(LIST_VIDEOS_DEFAULT_LIMIT))
    .fetch_all(conn)
    .await
}

/// Returns false when the video does not exist in the workspace.
pub async fn modify_video(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    id: i64,
    download: bool,
) -> Result<bool> {
    let result = sqlx::query(
        "
        UPDATE videos
        SET download = $3
        WHERE workspace_id = $1
        AND id = $2
        ",
    )
    .bind(workspace)
    .bind(id)
    .bind(download)
    .execute(conn)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Returns false when the video does not exist in the workspace.
pub async fn delete_video(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
    id: i64,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM videos WHERE workspace_id = $1 AND id = $2")
        .bind(workspace)
        .bind(id)
        .execute(conn)
        .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_metadata_status(
    conn: &mut PgConnection,
    video_id: i64,
) -> Result<Option<MetadataStatus>> {
    sqlx::query_as(
        "
        SELECT fetched_at, fetch_error IS NOT NULL AS failed
        FROM video_metadata
        WHERE video_id = $1
        AND fetched_at IS NOT NULL
        ",
    )
    .bind(video_id)
    .fetch_optional(conn)
    .await
}

pub async fn set_metadata(
    conn: &mut PgConnection,
    video_id: i64,
    metadata: &VideoMetadata<'_>,
    error: Option<&str>,
) -> Result<()> {
    let duration = metadata
        .duration
        .map(|duration| i32::try_from(duration).unwrap_or(i32::MAX));

    sqlx::query(
        "
        INSERT INTO video_metadata (video_id, title, uploader, duration, thumbnail, fetched_at, fetch_error)
        VALUES ($1, $2, $3, $4, $5, now(), $6)
        ON CONFLICT (video_id) DO
        UPDATE SET
            title = COALESCE(excluded.title, video_metadata.title),
            uploader = COALESCE(excluded.uploader, video_metadata.uploader),
            duration = COALESCE(excluded.duration, video_metadata.duration),
            thumbnail = COALESCE(excluded.thumbnail, video_metadata.thumbnail),
            fetched_at = excluded.fetched_at,
            fetch_error = excluded.fetch_error
        ",
    )
    .bind(video_id)
    .bind(metadata.title)
    .bind(metadata.uploader)
    .bind(duration)
    .bind(metadata.thumbnail)
    .bind(error)
    .execute(conn)
    .await?;

    Ok(())
}

/// Thumbnails referenced by any workspace; the icon store is shared.
pub async fn list_thumbnails(conn: &mut PgConnection) -> Result<HashSet<Box<str>>> {
    let thumbnails: Vec<Box<str>> = sqlx::query_scalar(
        "
        SELECT DISTINCT thumbnail
        FROM video_metadata
        WHERE thumbnail IS NOT NULL
        ",
    )
    .fetch_all(conn)
    .await?;

    Ok(thumbnails.into_iter().collect())
}

pub async fn get_video_applications(
    conn: &mut PgConnection,
    workspace: WorkspaceId,
) -> Result<Vec<VideoApplication>> {
    sqlx::query_as(
        "
        SELECT
            videos.id,
            videos.url,
            video_metadata.title,
            video_metadata.thumbnail
        FROM videos
        LEFT JOIN video_metadata
        ON video_metadata.video_id = videos.id
        WHERE videos.workspace_id = $1
        ORDER BY videos.id
        ",
    )
    .bind(workspace)
    .fetch_all(conn)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::workspaces;
    use sqlx::PgPool;
    use sqlx::pool::PoolConnection;
    use sqlx::postgres::Postgres;

    async fn open(pool: &PgPool) -> (PoolConnection<Postgres>, WorkspaceId) {
        let mut conn = pool.acquire().await.unwrap();
        let ws = workspaces::create(&mut conn, "test").await.unwrap();
        (conn, ws)
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn videos_include_metadata(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let a = add_video(c, ws, "https://youtu.be/a", false).await.unwrap();
        let b = add_video(c, ws, "https://youtu.be/b", true).await.unwrap();
        assert_eq!(a.title, None);

        set_metadata(
            c,
            a.id,
            &VideoMetadata {
                title: Some("A"),
                uploader: Some("Someone"),
                duration: Some(61),
                thumbnail: Some("a.png"),
            },
            None,
        )
        .await
        .unwrap();

        let list = list_videos(c, ws, None, None).await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].title.as_deref(), Some("A"));
        assert_eq!(list[0].uploader.as_deref(), Some("Someone"));
        assert_eq!(list[0].duration, Some(61));
        assert_eq!(list[0].thumbnail.as_deref(), Some("a.png"));
        assert_eq!(list[1].id, b.id);
        assert!(list[1].download);

        let apps = get_video_applications(c, ws).await.unwrap();
        assert_eq!(apps[0].id, a.id);
        assert_eq!(apps[0].title.as_deref(), Some("A"));
        assert_eq!(apps[0].thumbnail.as_deref(), Some("a.png"));
        assert_eq!(apps[1].thumbnail, None);
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn failed_fetch_keeps_previous_metadata(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let video = add_video(c, ws, "https://youtu.be/a", false).await.unwrap();
        assert_eq!(get_metadata_status(c, video.id).await.unwrap(), None);

        let metadata = VideoMetadata {
            title: Some("A"),
            thumbnail: Some("a.png"),
            ..Default::default()
        };
        set_metadata(c, video.id, &metadata, None).await.unwrap();
        assert!(!get_metadata_status(c, video.id).await.unwrap().unwrap().failed);

        set_metadata(c, video.id, &VideoMetadata::default(), Some("timeout"))
            .await
            .unwrap();
        assert!(get_metadata_status(c, video.id).await.unwrap().unwrap().failed);

        let video = get_video(c, ws, video.id).await.unwrap().unwrap();
        assert_eq!(video.title.as_deref(), Some("A"));
        assert_eq!(video.fetch_error.as_deref(), Some("timeout"));
        assert_eq!(
            list_thumbnails(c).await.unwrap(),
            ["a.png".into()].into_iter().collect()
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn metadata_is_deleted_with_video(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let video = add_video(c, ws, "https://youtu.be/a", false).await.unwrap();
        set_metadata(c, video.id, &VideoMetadata::default(), None)
            .await
            .unwrap();

        assert!(delete_video(c, ws, video.id).await.unwrap());

        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM video_metadata")
            .fetch_one(&mut *c)
            .await
            .unwrap();
        assert_eq!(remaining, 0);
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn workspaces_are_isolated(pool: PgPool) {
        let (mut conn, ws) = open(&pool).await;
        let c = &mut *conn;
        let other = workspaces::create(c, "other").await.unwrap();

        let video = add_video(c, ws, "https://youtu.be/a", false).await.unwrap();
        let same = add_video(c, other, "https://youtu.be/a", true).await.unwrap();
        assert_ne!(video.id, same.id);

        assert_eq!(get_video(c, other, video.id).await.unwrap(), None);
        assert_eq!(find_video(c, ws, "https://youtu.be/a").await.unwrap(), Some(video.clone()));
        assert_eq!(find_video(c, other, "https://youtu.be/a").await.unwrap().map(|v| v.id), Some(same.id));
        assert_eq!(list_videos(c, other, None, None).await.unwrap(), vec![same]);
        assert!(!modify_video(c, other, video.id, true).await.unwrap());
        assert!(!delete_video(c, other, video.id).await.unwrap());
        assert_eq!(get_video(c, ws, video.id).await.unwrap(), Some(video));
    }
}
