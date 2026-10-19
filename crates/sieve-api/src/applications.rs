use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use sieve_common::LogError;
use sieve_common::database::{sites, videos};

use crate::error::{ApiError, IntoApiError};
use crate::state::AppState;
use crate::workspace::ClientWorkspace;

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Web,
    Video,
}

#[derive(Debug, serde::Serialize)]
struct Application {
    id: Box<str>,
    kind: Kind,
    name: Box<str>,
    url: Box<str>,
    icon: Option<Box<str>>,
}

fn icon_url(name: &str) -> Box<str> {
    format!("/static/icons/{name}").into()
}

fn etag(body: &[u8]) -> HeaderValue {
    let hash = Sha256::digest(body)
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    HeaderValue::from_str(&format!("\"{hash}\"")).expect("hex is a valid header value")
}

fn matches_etag(headers: &HeaderMap, etag: &HeaderValue) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|tag| tag.trim().trim_start_matches("W/"))
        .any(|tag| tag == "*" || tag.as_bytes() == etag.as_bytes())
}

/// The workspace's desktop applications: approved sites, then videos.
pub(crate) async fn get(
    State(state): State<AppState>,
    ClientWorkspace(workspace): ClientWorkspace,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let mut conn = state.conn().await?;
    let web = sites::get_web_applications(&mut conn, workspace)
        .await
        .log_error("failed to list web applications")
        .as_internal_server_error()?;
    let video = videos::get_video_applications(&mut conn, workspace)
        .await
        .log_error("failed to list video applications")
        .as_internal_server_error()?;
    drop(conn);

    let web = web.into_iter().map(|app| Application {
        id: match app.path_id {
            None => format!("chromium-domain-{}", app.domain_id),
            Some(path_id) => format!("chromium-path-{path_id}"),
        }
        .into(),
        kind: Kind::Web,
        name: app.title.unwrap_or_else(|| app.url.clone()),
        url: app.url,
        icon: app.icon.as_deref().map(icon_url),
    });

    let video = video.into_iter().map(|app| Application {
        id: format!("video-{}", app.id).into(),
        kind: Kind::Video,
        name: app.title.unwrap_or_else(|| app.url.clone()),
        url: app.url,
        icon: app.thumbnail.as_deref().map(icon_url),
    });

    let body = serde_json::to_vec(&web.chain(video).collect::<Vec<_>>())
        .log_error("failed to serialise applications")
        .as_internal_server_error()?;
    let etag = etag(&body);

    let mut response = if matches_etag(&headers, &etag) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (
            [(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))],
            body,
        )
            .into_response()
    };

    let headers = response.headers_mut();
    headers.insert(header::ETAG, etag);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_matching() {
        let tag = etag(b"[]");
        let mut headers = HeaderMap::new();
        assert!(!matches_etag(&headers, &tag));

        headers.insert(header::IF_NONE_MATCH, tag.clone());
        assert!(matches_etag(&headers, &tag));

        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("\"other\", W/\"x\""));
        assert!(!matches_etag(&headers, &tag));

        let weak = format!("\"a\", W/{}", tag.to_str().unwrap());
        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_str(&weak).unwrap());
        assert!(matches_etag(&headers, &tag));

        headers.insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert!(matches_etag(&headers, &tag));
    }
}
