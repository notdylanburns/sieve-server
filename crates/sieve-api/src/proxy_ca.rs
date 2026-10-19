use std::path::PathBuf;

use axum::http::header;
use axum::response::{IntoResponse, Response};
use log::warn;

use crate::error::ApiError;

/// The Squid CA certificate clients install so they trust bumped connections. It's public:
/// only the private key, which never leaves the Squid container, is sensitive.
pub(crate) async fn get(path: Option<PathBuf>) -> Result<Response, ApiError> {
    let path = path.ok_or(ApiError::NotFound)?;

    let certificate = tokio::fs::read(&path).await.map_err(|e| {
        warn!("failed to read proxy CA certificate {}: {e}", path.display());
        ApiError::NotFound
    })?;

    Ok((
        [
            (header::CONTENT_TYPE, "application/x-x509-ca-cert"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"sieve-proxy-ca.crt\""),
        ],
        certificate,
    )
        .into_response())
}
