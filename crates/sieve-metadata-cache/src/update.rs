use std::collections::HashSet;
use std::path::{Path, PathBuf};

use log::{info, warn};
use reqwest::Client;
use sieve_common::config;
use sieve_common::database::videos::{self, VideoMetadata};
use sieve_common::database::{MetadataStatus, PgConnection, WorkspaceId, sites, workspaces};

use crate::fetch::{self, Error, Page};
use crate::{icon, video};

const MAX_PASSES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    All,
    Workspace(WorkspaceId),
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "all workspaces"),
            Self::Workspace(workspace) => write!(f, "workspace {workspace}"),
        }
    }
}

async fn workspace_ids(conn: &mut PgConnection, scope: Scope) -> Result<Vec<WorkspaceId>, Error> {
    Ok(match scope {
        Scope::All => workspaces::list_ids(conn).await?,
        Scope::Workspace(workspace) => vec![workspace],
    })
}

pub struct Config {
    pub database_url: String,
    pub icon_dir: PathBuf,
    pub yt_dlp_bin: String,
}

impl Config {
    pub fn from_env() -> Result<Self, config::Error> {
        Ok(Self {
            database_url: config::database_url()?,
            icon_dir: config::icon_dir()?,
            yt_dlp_bin: config::var_or("YT_DLP_BIN", "yt-dlp")?,
        })
    }
}

/// Fetches stale metadata for the workspaces in `scope`, then removes icons no workspace uses.
pub async fn update(
    conn: &mut PgConnection,
    client: &Client,
    config: &Config,
    scope: Scope,
    force: bool,
) -> Result<(), Error> {
    let icon_dir = config.icon_dir.as_path();

    for pass in 0..MAX_PASSES {
        let force = force && pass == 0;
        if update_sites_pass(conn, client, icon_dir, scope, force).await? == 0 {
            break;
        }
    }

    for pass in 0..MAX_PASSES {
        let force = force && pass == 0;
        let yt_dlp = config.yt_dlp_bin.as_str();
        if update_videos_pass(conn, client, icon_dir, yt_dlp, scope, force).await? == 0 {
            break;
        }
    }

    // The icon store is shared, so this checks references from every workspace whatever the scope.
    let mut referenced = sites::list_icons(conn).await?;
    referenced.extend(videos::list_thumbnails(conn).await?);
    icon::remove_unreferenced(icon_dir, &referenced)?;

    Ok(())
}

async fn update_sites_pass(
    conn: &mut PgConnection,
    client: &Client,
    icon_dir: &Path,
    scope: Scope,
    force: bool,
) -> Result<usize, Error> {
    let now = chrono::Utc::now();
    let mut icon_domains = HashSet::new();
    let mut fetched = 0;

    let mut apps = Vec::new();
    for workspace in workspace_ids(conn, scope).await? {
        apps.extend(sites::get_web_applications(conn, workspace).await?);
    }

    for app in apps {
        let domain_status = sites::get_domain_metadata_status(conn, app.domain_id).await?;
        let domain_stale = force || MetadataStatus::is_stale(domain_status, now);
        let fetch_icon = domain_stale && icon_domains.insert(app.domain_id);
        let fetch_title = match app.path_id {
            None => domain_stale,
            Some(path_id) => {
                let path_status = sites::get_path_metadata_status(conn, path_id).await?;
                force || MetadataStatus::is_stale(path_status, now)
            }
        };

        if !fetch_icon && !fetch_title {
            continue;
        }

        info!("fetching metadata for {}", app.url);
        fetched += 1;
        let page = fetch::page(client, &app.url).await;
        let title = page.as_ref().ok().and_then(|page| page.title.as_deref());
        let page_error = page.as_ref().err().map(ToString::to_string);

        if let Some(error) = &page_error {
            warn!("failed to fetch {}: {error}", app.url);
        }

        if let Some(path_id) = app.path_id
            && fetch_title
        {
            sites::set_path_metadata(conn, path_id, title, page_error.as_deref()).await?;
        }

        if fetch_icon {
            let (icon, error) = match &page {
                Ok(page) => match fetch_icon_file(client, page, icon_dir).await {
                    Ok(icon) => (Some(icon), None),
                    Err(e) => {
                        warn!("failed to fetch icon for {}: {e}", app.url);
                        (None, Some(e.to_string()))
                    }
                },
                Err(_) => (None, page_error.clone()),
            };

            let domain_title = if app.path_id.is_none() { title } else { None };
            sites::set_domain_metadata(
                conn,
                app.domain_id,
                domain_title,
                icon.as_deref(),
                error.as_deref(),
            )
            .await?;
        }
    }

    Ok(fetched)
}

async fn update_videos_pass(
    conn: &mut PgConnection,
    client: &Client,
    icon_dir: &Path,
    yt_dlp_bin: &str,
    scope: Scope,
    force: bool,
) -> Result<usize, Error> {
    let now = chrono::Utc::now();
    let mut fetched = 0;

    let mut apps = Vec::new();
    for workspace in workspace_ids(conn, scope).await? {
        apps.extend(videos::get_video_applications(conn, workspace).await?);
    }

    for app in apps {
        let status = videos::get_metadata_status(conn, app.id).await?;
        if !force && !MetadataStatus::is_stale(status, now) {
            continue;
        }

        info!("fetching metadata for video {}", app.url);
        fetched += 1;

        let info = match video::info(yt_dlp_bin, &app.url).await {
            Ok(info) => info,
            Err(e) => {
                warn!("failed to fetch video metadata for {}: {e}", app.url);
                let error = e.to_string();
                videos::set_metadata(conn, app.id, &VideoMetadata::default(), Some(&error))
                    .await?;
                continue;
            }
        };

        let thumbnail = match info.thumbnail.as_deref() {
            Some(url) => match fetch_thumbnail_file(client, url, icon_dir).await {
                Ok(name) => Some(name),
                Err(e) => {
                    warn!("failed to fetch thumbnail for {}: {e}", app.url);
                    None
                }
            },
            None => None,
        };

        videos::set_metadata(
            conn,
            app.id,
            &VideoMetadata {
                title: info.title.as_deref(),
                uploader: info.uploader(),
                duration: info.duration(),
                thumbnail: thumbnail.as_deref(),
            },
            None,
        )
        .await?;
    }

    Ok(fetched)
}

async fn fetch_thumbnail_file(client: &Client, url: &str, dir: &Path) -> Result<String, Error> {
    let png = &video::thumbnail(client, url).await?;
    let name = icon::store(dir, png)?;
    info!("stored thumbnail from {url} as {name}");
    Ok(name)
}

async fn fetch_icon_file(client: &Client, page: &Page, dir: &Path) -> Result<String, Error> {
    let icon = &icon::best(client, page).await?;
    let name = icon::store(dir, &icon.png)?;
    info!("stored icon from {} as {name}", icon.source);
    Ok(name)
}

#[cfg(test)]
mod tests {
    use sieve_common::database::sites::Scheme;
    use sieve_common::database::videos;
    use sqlx::PgPool;

    use super::*;

    // Fetches go to 127.0.0.1:80 and a failing yt-dlp, so they fail fast without the network;
    // a failure still records a fetch attempt, which is what these tests look for.
    fn config() -> Config {
        let icon_dir = std::env::temp_dir().join(format!("sieve-icons-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&icon_dir).unwrap();
        Config {
            database_url: String::new(),
            icon_dir,
            yt_dlp_bin: "false".into(),
        }
    }

    #[sqlx::test(migrator = "sieve_common::database::MIGRATOR")]
    async fn workspace_scope_only_fetches_that_workspace(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        let c = &mut *conn;
        let a = workspaces::create(c, "a").await.unwrap();
        let b = workspaces::create(c, "b").await.unwrap();
        let in_a = sites::add_domain(c, a, Scheme::Http, "127.0.0.1", Some(true)).await.unwrap();
        let in_b = sites::add_domain(c, b, Scheme::Http, "127.0.0.1", Some(true)).await.unwrap();
        let video_a = videos::add_video(c, a, "https://youtu.be/a", false).await.unwrap();
        let video_b = videos::add_video(c, b, "https://youtu.be/a", false).await.unwrap();

        let client = fetch::client().unwrap();
        update(c, &client, &config(), Scope::Workspace(a), false).await.unwrap();

        assert!(sites::get_domain_metadata_status(c, in_a.id()).await.unwrap().is_some());
        assert!(videos::get_metadata_status(c, video_a.id).await.unwrap().is_some());
        assert_eq!(sites::get_domain_metadata_status(c, in_b.id()).await.unwrap(), None);
        assert_eq!(videos::get_metadata_status(c, video_b.id).await.unwrap(), None);

        update(c, &client, &config(), Scope::All, false).await.unwrap();
        assert!(sites::get_domain_metadata_status(c, in_b.id()).await.unwrap().is_some());
        assert!(videos::get_metadata_status(c, video_b.id).await.unwrap().is_some());
    }
}
