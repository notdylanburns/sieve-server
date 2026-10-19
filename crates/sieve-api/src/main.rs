use std::process::ExitCode;

use sieve_common::logger;

mod applications;
mod audit;
mod auth;
mod client;
pub(crate) mod common;
mod config;
mod devices;
pub(crate) mod error;
mod events;
mod frontend;
mod icons;
mod invites;
mod proxy_ca;
mod server;
mod sites;
pub(crate) mod state;
mod videos;
pub(crate) mod workspace;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> ExitCode {
    let log_config = logger::LogConfig {
        id: "sieve-api",
        level: logger::LogLevel::Debug,
    };

    if let Err(e) = logger::init(log_config) {
        eprintln!("error: failed to configure logger: {e}");
        return ExitCode::FAILURE;
    };

    server::run().await
}
