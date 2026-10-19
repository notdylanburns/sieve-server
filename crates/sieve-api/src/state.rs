use std::sync::Arc;

use ipnetwork::IpNetwork;
use sieve_common::LogError;
use sieve_common::jwt::Keys;
use sqlx::pool::PoolConnection;
use sqlx::postgres::Postgres;
use sqlx::{PgPool, Transaction};

use crate::error::{ApiError, IntoApiError};
use crate::events::Hub;

#[derive(Clone)]
pub(crate) struct AppState {
    pool: PgPool,
    pub keys: Arc<Keys>,
    pub trusted_proxies: Arc<[IpNetwork]>,
    pub events: Arc<Hub>,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        keys: Keys,
        trusted_proxies: Box<[IpNetwork]>,
        events: Arc<Hub>,
    ) -> Self {
        Self {
            pool,
            keys: Arc::new(keys),
            trusted_proxies: trusted_proxies.into(),
            events,
        }
    }

    pub async fn conn(&self) -> Result<PoolConnection<Postgres>, ApiError> {
        self.pool
            .acquire()
            .await
            .log_error("failed to acquire database connection")
            .as_internal_server_error()
    }

    pub async fn begin(&self) -> Result<Transaction<'static, Postgres>, ApiError> {
        self.pool
            .begin()
            .await
            .log_error("failed to begin transaction")
            .as_internal_server_error()
    }
}
