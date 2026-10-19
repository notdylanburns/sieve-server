use std::process::Stdio;
use std::time::Duration;

use reqwest::Client;
use url::Url;

use crate::fetch::{self, Error};
use crate::icon;

const YT_DLP_TIMEOUT: Duration = Duration::from_secs(90);
const THUMBNAIL_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug, Default, serde::Deserialize)]
pub struct Info {
    pub title: Option<String>,
    uploader: Option<String>,
    channel: Option<String>,
    duration: Option<f64>,
    pub thumbnail: Option<String>,
}

impl Info {
    pub fn uploader(&self) -> Option<&str> {
        self.uploader.as_deref().or(self.channel.as_deref())
    }

    pub fn duration(&self) -> Option<u32> {
        self.duration
            .filter(|duration| duration.is_finite() && *duration >= 0.0)
            .map(|duration| duration.round() as u32)
    }
}

pub async fn info(yt_dlp_bin: &str, url: &str) -> Result<Info, Error> {
    let child = tokio::process::Command::new(yt_dlp_bin)
        .args([
            "--dump-single-json",
            "--skip-download",
            "--flat-playlist",
            "--no-cache-dir",
            "--no-warnings",
            "--ignore-config",
            "--",
            url,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let output = tokio::time::timeout(YT_DLP_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| format!("yt-dlp timed out after {}s", YT_DLP_TIMEOUT.as_secs()))??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = stderr
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("no output");
        return Err(format!("yt-dlp failed ({}): {message}", output.status).into());
    }

    Ok(serde_json::from_slice(&output.stdout)?)
}

pub async fn thumbnail(client: &Client, url: &str) -> Result<Vec<u8>, Error> {
    let download = fetch::download(client, &Url::parse(url)?, THUMBNAIL_LIMIT).await?;
    icon::thumbnail(&download)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yt_dlp_output() {
        let info: Info = serde_json::from_str(
            r#"{
                "id": "abc",
                "title": "A Video",
                "channel": "A Channel",
                "duration": 61.4,
                "thumbnail": "https://i.ytimg.com/vi/abc/maxresdefault.jpg",
                "formats": []
            }"#,
        )
        .unwrap();

        assert_eq!(info.title.as_deref(), Some("A Video"));
        assert_eq!(info.uploader(), Some("A Channel"));
        assert_eq!(info.duration(), Some(61));
        assert_eq!(
            info.thumbnail.as_deref(),
            Some("https://i.ytimg.com/vi/abc/maxresdefault.jpg")
        );
    }

    #[test]
    fn prefers_uploader_and_tolerates_missing_fields() {
        let info: Info =
            serde_json::from_str(r#"{"uploader": "Up", "channel": "Ch", "duration": null}"#)
                .unwrap();

        assert_eq!(info.uploader(), Some("Up"));
        assert_eq!(info.duration(), None);
        assert_eq!(info.title, None);
    }
}
