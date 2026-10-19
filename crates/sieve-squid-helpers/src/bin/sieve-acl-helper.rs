use log::{error, info};
use sieve_squid_helpers::{acl, protocol};
use sieve_common::{config, database, logger};
use std::{process::ExitCode, sync::Arc};
use tokio::sync::Mutex;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let log_config = logger::LogConfig {
        id: "sieve-acl",
        level: logger::LogLevel::Info,
    };

    if let Err(e) = logger::init(log_config) {
        eprintln!("error: failed to configure logger: {e}");
        return ExitCode::FAILURE;
    };

    let url = match config::database_url() {
        Ok(url) => url,
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
    };

    // Squid runs several helper processes, so each keeps its pool small.
    let pool = match database::connect(&url, 2).await {
        Ok(pool) => pool,
        Err(e) => {
            error!("failed to connect to database: {e}");
            return ExitCode::FAILURE;
        }
    };

    info!("starting request loop...");

    let workspaces = Arc::new(Mutex::new(acl::Workspaces::new(pool.clone())));

    protocol::serve(|line| {
        let (pool, workspaces) = (pool.clone(), Arc::clone(&workspaces));
        async move {
            match acl::decide(&pool, &mut *workspaces.lock().await, &line).await {
                Ok(decision) => decision.as_str(),
                Err(e) => {
                    error!("failed to process '{line}': {e}");
                    "BH"
                }
            }
        }
    })
    .await
}
