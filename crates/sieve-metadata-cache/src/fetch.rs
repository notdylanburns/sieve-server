use std::collections::HashSet;
use std::time::Duration;

use log::warn;
use reqwest::Client;
use scraper::{Html, Selector};
use url::Url;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

const PAGE_LIMIT: usize = 4 * 1024 * 1024;
pub const ICON_LIMIT: usize = 1024 * 1024;
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 sieve-metadata-cache";

pub fn client() -> reqwest::Result<Client> {
    Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(20))
        .no_proxy()
        .build()
}

#[derive(Debug)]
pub struct Download {
    pub url: Url,
    pub content_type: Option<String>,
    pub bytes: Vec<u8>,
}

pub async fn download(client: &Client, url: &Url, limit: usize) -> Result<Download, Error> {
    let mut response = client.get(url.clone()).send().await?.error_for_status()?;

    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(format!("{url} is larger than {limit} bytes").into());
    }

    let final_url = response.url().clone();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > limit {
            return Err(format!("{url} is larger than {limit} bytes").into());
        }
        bytes.extend_from_slice(&chunk);
    }

    Ok(Download {
        url: final_url,
        content_type,
        bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconCandidate {
    pub url: Url,
    pub size: Option<u32>,
    pub svg: bool,
}

#[derive(Debug)]
pub struct Page {
    pub url: Url,
    pub title: Option<String>,
    pub icons: Vec<IconCandidate>,
}

pub async fn page(client: &Client, url: &str) -> Result<Page, Error> {
    let download = download(client, &Url::parse(url)?, PAGE_LIMIT).await?;
    let parsed = parse_html(&download.url, &String::from_utf8_lossy(&download.bytes));
    let mut icons = parsed.icons;

    if let Some(manifest) = parsed.manifest {
        match manifest_icons(client, &manifest).await {
            Ok(manifest_icons) => icons.extend(manifest_icons),
            Err(e) => warn!("failed to load manifest {manifest}: {e}"),
        }
    }

    if let Ok(favicon) = download.url.join("/favicon.ico") {
        icons.push(IconCandidate {
            url: favicon,
            size: None,
            svg: false,
        });
    }

    Ok(Page {
        url: download.url,
        title: parsed.title,
        icons: rank(icons),
    })
}

#[derive(Debug, Default)]
struct ParsedHtml {
    title: Option<String>,
    icons: Vec<IconCandidate>,
    manifest: Option<Url>,
}

fn selector(selector: &str) -> Selector {
    Selector::parse(selector).expect("invalid selector")
}

fn parse_html(url: &Url, html: &str) -> ParsedHtml {
    let document = Html::parse_document(html);
    let mut parsed = ParsedHtml::default();

    let base = document
        .select(&selector("base[href]"))
        .next()
        .and_then(|base| url.join(base.value().attr("href")?).ok())
        .unwrap_or_else(|| url.clone());

    parsed.title = document
        .select(&selector("title"))
        .next()
        .map(|title| {
            title
                .text()
                .flat_map(str::split_whitespace)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|title| !title.is_empty());

    for link in document.select(&selector("link[rel][href]")) {
        let element = link.value();
        let rel = element.attr("rel").unwrap_or_default().to_ascii_lowercase();
        let Some(Ok(href)) = element.attr("href").map(|href| base.join(href.trim())) else {
            continue;
        };

        for rel in rel.split_ascii_whitespace() {
            match rel {
                "manifest" => {
                    parsed.manifest.get_or_insert(href.clone());
                }
                "icon" | "apple-touch-icon" | "apple-touch-icon-precomposed" => {
                    parsed
                        .icons
                        .push(candidate(href.clone(), element.attr("sizes"), element.attr("type")));
                }
                _ => continue,
            }
            break;
        }
    }

    parsed
}

fn candidate(url: Url, sizes: Option<&str>, mime: Option<&str>) -> IconCandidate {
    let svg = mime.is_some_and(|mime| mime.contains("svg")) || url.path().ends_with(".svg");

    let size = sizes.and_then(|sizes| {
        sizes
            .split_ascii_whitespace()
            .filter_map(|size| {
                let (width, height) = size.to_ascii_lowercase().split_once('x').map(|(w, h)| {
                    (w.parse::<u32>().ok(), h.parse::<u32>().ok())
                })?;
                Some(width?.min(height?))
            })
            .max()
    });

    IconCandidate { url, size, svg }
}

#[derive(Debug, serde::Deserialize)]
struct Manifest {
    #[serde(default)]
    icons: Vec<ManifestIcon>,
}

#[derive(Debug, serde::Deserialize)]
struct ManifestIcon {
    src: String,
    sizes: Option<String>,
    #[serde(rename = "type")]
    mime: Option<String>,
    purpose: Option<String>,
}

async fn manifest_icons(client: &Client, url: &Url) -> Result<Vec<IconCandidate>, Error> {
    let download = download(client, url, PAGE_LIMIT).await?;
    let manifest: Manifest = serde_json::from_slice(&download.bytes)?;

    Ok(manifest
        .icons
        .into_iter()
        .filter(|icon| {
            icon.purpose
                .as_deref()
                .is_none_or(|purpose| purpose.split_ascii_whitespace().any(|p| p == "any"))
        })
        .filter_map(|icon| {
            Some(candidate(
                download.url.join(&icon.src).ok()?,
                icon.sizes.as_deref(),
                icon.mime.as_deref(),
            ))
        })
        .collect())
}

fn rank(mut icons: Vec<IconCandidate>) -> Vec<IconCandidate> {
    let mut seen = HashSet::new();
    icons.retain(|icon| {
        matches!(icon.url.scheme(), "http" | "https") && seen.insert(icon.url.clone())
    });
    icons.sort_by_key(|icon| std::cmp::Reverse((icon.svg, icon.size.unwrap_or(0))));
    icons
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(url: &str) -> Url {
        Url::parse(url).unwrap()
    }

    #[test]
    fn parses_title_icons_and_manifest() {
        let parsed = parse_html(
            &url("https://example.com/docs/page"),
            r#"
            <html><head>
                <title>
                    Example
                    Page
                </title>
                <link rel="stylesheet" href="/style.css">
                <link rel="shortcut icon" href="/favicon-32.png" sizes="16x16 32x32">
                <link rel="apple-touch-icon" href="touch.png" sizes="180x180">
                <link rel="icon" href="/logo.svg" type="image/svg+xml" sizes="any">
                <link rel="mask-icon" href="/mask.svg">
                <link rel="manifest" href="/site.webmanifest">
                <link rel="icon" href="data:image/png;base64,AAAA">
            </head></html>
            "#,
        );

        assert_eq!(parsed.title.as_deref(), Some("Example Page"));
        assert_eq!(parsed.manifest, Some(url("https://example.com/site.webmanifest")));
        assert_eq!(
            parsed.icons,
            vec![
                IconCandidate {
                    url: url("https://example.com/favicon-32.png"),
                    size: Some(32),
                    svg: false
                },
                IconCandidate {
                    url: url("https://example.com/docs/touch.png"),
                    size: Some(180),
                    svg: false
                },
                IconCandidate {
                    url: url("https://example.com/logo.svg"),
                    size: None,
                    svg: true
                },
                IconCandidate {
                    url: url("data:image/png;base64,AAAA"),
                    size: None,
                    svg: false
                },
            ]
        );
    }

    #[test]
    fn respects_base_href_and_missing_title() {
        let parsed = parse_html(
            &url("https://example.com/a/b"),
            r#"<head><base href="https://cdn.example.net/assets/"><link rel="icon" href="icon.png"></head>"#,
        );

        assert_eq!(parsed.title, None);
        assert_eq!(parsed.icons[0].url, url("https://cdn.example.net/assets/icon.png"));
    }

    #[test]
    fn ranks_svg_then_largest_and_drops_duplicates_and_data_urls() {
        let icon = |u: &str, size, svg| IconCandidate {
            url: url(u),
            size,
            svg,
        };

        let ranked = rank(vec![
            icon("https://a.com/32.png", Some(32), false),
            icon("data:image/png;base64,AAAA", Some(512), false),
            icon("https://a.com/unsized.png", None, false),
            icon("https://a.com/180.png", Some(180), false),
            icon("https://a.com/logo.svg", None, true),
            icon("https://a.com/32.png", Some(32), false),
            icon("https://a.com/favicon.ico", None, false),
        ]);

        let urls: Vec<&str> = ranked.iter().map(|icon| icon.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://a.com/logo.svg",
                "https://a.com/180.png",
                "https://a.com/32.png",
                "https://a.com/unsized.png",
                "https://a.com/favicon.ico",
            ]
        );
    }
}
