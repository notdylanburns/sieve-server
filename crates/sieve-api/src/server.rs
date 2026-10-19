use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use axum::Router;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::routing::{delete, get, post};
use log::{error, info};
use sieve_common::audit;
use sieve_common::database;
use sieve_common::jwt::Keys;
use sqlx::PgPool;

use crate::config::Config;
use crate::error::{self, ApiError};
use crate::events::{self, Hub};
use crate::state::AppState;
use crate::{applications, auth, devices, frontend, icons, invites, proxy_ca, sites, videos};

const RETENTION_INTERVAL: Duration = Duration::from_secs(60 * 60 * 24);

pub(crate) fn router(
    state: AppState,
    icon_dir: &Path,
    frontend_dir: &Path,
    proxy_ca: Option<PathBuf>,
) -> Router {
    let api = Router::new()
        .nest("/{workspace}/sites", sites::routes())
        .nest("/{workspace}/videos", videos::routes())
        .route("/{workspace}/audit", get(crate::audit::get))
        .route("/{workspace}/applications", get(applications::get))
        .route("/{workspace}/events", get(events::get))
        .route("/{workspace}/devices", get(devices::list).post(devices::create))
        .route("/{workspace}/devices/{device_id}", delete(devices::revoke))
        .route("/{workspace}/invites", get(invites::list).post(invites::create))
        .route("/{workspace}/invites/{invite_id}", delete(invites::revoke))
        .route("/invites/{token}", get(invites::preview))
        .route("/invites/{token}/accept", post(invites::accept))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .layer(from_fn_with_state(state.clone(), auth::require_auth))
        // Added after the auth layer, so it stays reachable without a session.
        .route("/auth/login", post(auth::login))
        .route("/proxy-ca.crt", get(move || proxy_ca::get(proxy_ca.clone())))
        .fallback(|| async { ApiError::NotFound })
        .layer(from_fn(error::log_error_responses));

    let icons = Router::new()
        .nest_service("/static/icons", icons::service(icon_dir))
        .layer(from_fn_with_state(state.clone(), auth::require_auth));

    let frontend = Router::new()
        .fallback_service(frontend::service(frontend_dir))
        .layer(from_fn_with_state(state.clone(), auth::redirect_to_login));

    Router::new()
        .nest("/api", api)
        .merge(icons)
        .fallback_service(frontend)
        .with_state(state)
}

fn spawn_audit_retention(pool: PgPool, days: u32) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RETENTION_INTERVAL);
        loop {
            interval.tick().await;
            let result = match pool.acquire().await {
                Ok(mut conn) => audit::purge_older_than(&mut conn, days).await,
                Err(e) => Err(e),
            };
            match result {
                Ok(purged) => info!("purged {purged} audit log entries older than {days} days"),
                Err(e) => error!("failed to purge audit log: {e}"),
            }
        }
    });
}

pub(crate) async fn run() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let keys = match Keys::from_env() {
        Ok(keys) => keys,
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let pool = match database::connect(&config.database_url, config.database_max_connections).await
    {
        Ok(pool) => pool,
        Err(e) => {
            error!("failed to connect to database: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = database::migrate(&pool).await {
        error!("failed to run database migrations: {e}");
        return ExitCode::FAILURE;
    }

    if let Some(days) = config.audit_retention_days {
        spawn_audit_retention(pool.clone(), days);
    }

    let hub = Hub::new(events::DEBOUNCE);
    let _ = events::spawn_listener(pool.clone(), hub.clone());

    let state = AppState::new(pool, keys, config.trusted_proxies, hub);
    let app = router(state, &config.icon_dir, &config.frontend_dir, config.proxy_ca);

    let listener = match tokio::net::TcpListener::bind(config.bind_address).await {
        Ok(listener) => listener,
        Err(e) => {
            error!("failed to bind socket: {e}");
            return ExitCode::FAILURE;
        }
    };

    info!("Listening on http://{}", config.bind_address);
    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        error!("server error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
