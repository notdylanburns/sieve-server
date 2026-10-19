use std::process::ExitCode;

use log::error;
use sieve_squid_helpers::{auth, protocol};
use sieve_common::{config, database, logger};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let log_config = logger::LogConfig {
        id: "sieve-proxy-auth",
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

    let pool = match database::connect(&url, 1).await {
        Ok(pool) => pool,
        Err(e) => {
            error!("failed to connect to database: {e}");
            return ExitCode::FAILURE;
        }
    };

    protocol::serve(|line| {
        let pool = pool.clone();
        async move { auth::check(&pool, &line).await }
    })
    .await
}
