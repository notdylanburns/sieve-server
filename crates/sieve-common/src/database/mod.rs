use chrono::{DateTime, TimeDelta, Utc};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::config;

pub mod devices;
pub mod invites;
pub mod notify;
pub mod sites;
pub mod users;
pub mod videos;
pub mod workspaces;

pub use sqlx::{Error, PgConnection, Result};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

pub async fn connect(url: &str, max_connections: u32) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await
}

pub async fn migrate(pool: &PgPool) -> std::result::Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    sqlx::Type,
)]
#[serde(transparent)]
#[sqlx(transparent)]
pub struct WorkspaceId(pub uuid::Uuid);

impl std::fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for WorkspaceId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
pub struct MetadataStatus {
    pub fetched_at: DateTime<Utc>,
    pub failed: bool,
}

impl MetadataStatus {
    pub fn is_stale(status: Option<Self>, now: DateTime<Utc>) -> bool {
        match status {
            None => true,
            Some(Self { fetched_at, failed }) => {
                let interval = if failed {
                    config::METADATA_RETRY_INTERVAL
                } else {
                    config::METADATA_REFRESH_INTERVAL
                };
                now - fetched_at >= TimeDelta::seconds(interval)
            }
        }
    }
}
