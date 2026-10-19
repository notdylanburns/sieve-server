//! Channels published by the triggers in `0002_notify.sql`; payloads are workspace ids.

/// Inserts and updates of domains, paths and videos: entries that may need metadata fetched.
pub const ENTRIES: &str = "sieve_entries";

/// Any change that can alter a workspace's application list, metadata included.
pub const APPLICATIONS: &str = "sieve_applications";

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sqlx::PgPool;
    use sqlx::postgres::PgListener;

    use super::*;
    use crate::database::sites::{self, Scheme};
    use crate::database::videos::{self, VideoMetadata};
    use crate::database::{WorkspaceId, workspaces};

    async fn drain(listener: &mut PgListener) -> Vec<(String, String)> {
        let mut received = Vec::new();
        while let Ok(Ok(notification)) =
            tokio::time::timeout(Duration::from_millis(200), listener.recv()).await
        {
            received.push((notification.channel().to_owned(), notification.payload().to_owned()));
        }
        received
    }

    fn both(ws: WorkspaceId) -> Vec<(String, String)> {
        vec![(APPLICATIONS.into(), ws.to_string()), (ENTRIES.into(), ws.to_string())]
    }

    fn applications(ws: WorkspaceId) -> Vec<(String, String)> {
        vec![(APPLICATIONS.into(), ws.to_string())]
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    async fn changes_notify_their_workspace(pool: PgPool) {
        let mut listener = PgListener::connect_with(&pool).await.unwrap();
        listener.listen_all([ENTRIES, APPLICATIONS]).await.unwrap();

        let mut conn = pool.acquire().await.unwrap();
        let c = &mut *conn;
        let ws = workspaces::create(c, "a").await.unwrap();
        let other = workspaces::create(c, "b").await.unwrap();
        assert!(drain(&mut listener).await.is_empty());

        let domain = sites::add_domain(c, ws, Scheme::Https, "wiki.org", Some(true)).await.unwrap();
        assert_eq!(drain(&mut listener).await, both(ws));

        let path = sites::add_path(c, ws, domain.id(), "/a", true).await.unwrap().unwrap();
        assert_eq!(drain(&mut listener).await, both(ws));

        sites::set_domain_metadata(c, domain.id(), Some("Wiki"), None, None).await.unwrap();
        assert_eq!(drain(&mut listener).await, applications(ws));

        sites::set_path_metadata(c, path.id(), Some("A"), None).await.unwrap();
        assert_eq!(drain(&mut listener).await, applications(ws));

        let video = videos::add_video(c, other, "https://youtu.be/a", false).await.unwrap();
        assert_eq!(drain(&mut listener).await, both(other));

        videos::set_metadata(c, video.id, &VideoMetadata::default(), None).await.unwrap();
        assert_eq!(drain(&mut listener).await, applications(other));

        sites::delete_domain(c, ws, domain.id()).await.unwrap();
        assert_eq!(drain(&mut listener).await, applications(ws));
    }
}
