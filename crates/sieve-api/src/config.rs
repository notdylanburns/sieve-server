use std::net::SocketAddr;
use std::path::PathBuf;

use ipnetwork::IpNetwork;
use sieve_common::config::{self, Error};

pub(crate) struct Config {
    pub bind_address: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub icon_dir: PathBuf,
    pub frontend_dir: PathBuf,
    pub audit_retention_days: Option<u32>,
    pub trusted_proxies: Box<[IpNetwork]>,
    pub proxy_ca: Option<PathBuf>,
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self {
            bind_address: config::parse_var_or("BIND_ADDRESS", "0.0.0.0:8080")?,
            database_url: config::database_url()?,
            database_max_connections: config::parse_var_or("DATABASE_MAX_CONNECTIONS", "10")?,
            icon_dir: config::icon_dir()?,
            frontend_dir: config::var("FRONTEND_DIR")?.into(),
            audit_retention_days: match config::parse_var("AUDIT_RETENTION_DAYS") {
                Ok(days) => Some(days),
                Err(Error::Missing(_)) => None,
                Err(e) => return Err(e),
            },
            trusted_proxies: config::var_or("TRUSTED_PROXIES", "")?
                .split(',')
                .map(str::trim)
                .filter(|proxy| !proxy.is_empty())
                .map(|proxy| {
                    proxy
                        .parse()
                        .map_err(|e: ipnetwork::IpNetworkError| {
                            Error::Invalid("TRUSTED_PROXIES", e.to_string())
                        })
                })
                .collect::<Result<_, _>>()?,
            proxy_ca: match config::var("PROXY_CA_CERT") {
                Ok(path) => Some(path.into()),
                Err(Error::Missing(_)) => None,
                Err(e) => return Err(e),
            },
        })
    }
}
