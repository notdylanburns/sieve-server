use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use image::RgbaImage;
use image::imageops::{self, FilterType};
use log::{debug, info};
use reqwest::Client;
use resvg::{tiny_skia, usvg};
use sha2::{Digest, Sha256};
use url::Url;

use crate::fetch::{self, Download, Error, Page};

pub const ICON_SIZE: u32 = 128;
const THUMBNAIL_WIDTH: u32 = 320;
const MIN_SOURCE_SIZE: u32 = 16;
const MAX_ATTEMPTS: usize = 6;

pub struct Icon {
    pub source: Url,
    pub png: Vec<u8>,
}

enum Decoded {
    Vector(RgbaImage),
    Raster(RgbaImage),
}

pub async fn best(client: &Client, page: &Page) -> Result<Icon, Error> {
    let mut best: Option<(u32, Url, RgbaImage)> = None;
    let mut errors = Vec::new();

    for candidate in page.icons.iter().take(MAX_ATTEMPTS) {
        let decoded = match fetch::download(client, &candidate.url, fetch::ICON_LIMIT).await {
            Ok(download) => decode(&download),
            Err(e) => Err(e),
        };

        match decoded {
            Ok(Decoded::Vector(image)) => {
                return Ok(Icon {
                    source: candidate.url.clone(),
                    png: encode(&image)?,
                });
            }
            Ok(Decoded::Raster(image)) => {
                let size = image.width().min(image.height());
                debug!("{} is {}x{}", candidate.url, image.width(), image.height());

                if size >= MIN_SOURCE_SIZE && best.as_ref().is_none_or(|(best, ..)| size > *best) {
                    best = Some((size, candidate.url.clone(), image));
                }

                if size >= ICON_SIZE {
                    break;
                }
            }
            Err(e) => {
                debug!("skipping {}: {e}", candidate.url);
                errors.push(format!("{}: {e}", candidate.url));
            }
        }
    }

    let Some((_, source, image)) = best else {
        return Err(if errors.is_empty() {
            "no icon candidates found".into()
        } else {
            format!("no usable icon ({})", errors.join("; ")).into()
        });
    };

    Ok(Icon {
        source,
        png: encode(&fit(&image))?,
    })
}

fn decode(download: &Download) -> Result<Decoded, Error> {
    let svg = download
        .content_type
        .as_deref()
        .is_some_and(|content_type| content_type.contains("svg"))
        || looks_like_svg(&download.bytes);

    if svg {
        Ok(Decoded::Vector(render_svg(&download.bytes)?))
    } else {
        Ok(Decoded::Raster(
            image::load_from_memory(&download.bytes)?.to_rgba8(),
        ))
    }
}

fn looks_like_svg(bytes: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(1024)]);
    let head = head.trim_start();
    head.starts_with("<svg") || (head.starts_with("<?xml") && head.contains("<svg"))
}

fn render_svg(bytes: &[u8]) -> Result<RgbaImage, Error> {
    let options = usvg::Options {
        image_href_resolver: usvg::ImageHrefResolver {
            resolve_data: usvg::ImageHrefResolver::default_data_resolver(),
            resolve_string: Box::new(|_, _| None),
        },
        ..Default::default()
    };

    let tree = usvg::Tree::from_data(bytes, &options)?;
    let size = tree.size();
    let scale = ICON_SIZE as f32 / size.width().max(size.height());

    let mut pixmap =
        tiny_skia::Pixmap::new(ICON_SIZE, ICON_SIZE).ok_or("failed to allocate pixmap")?;
    let transform = tiny_skia::Transform::from_translate(
        (ICON_SIZE as f32 - size.width() * scale) / 2.0,
        (ICON_SIZE as f32 - size.height() * scale) / 2.0,
    )
    .pre_scale(scale, scale);

    resvg::render(&tree, transform, &mut pixmap.as_mut());

    let rgba = pixmap
        .pixels()
        .iter()
        .flat_map(|pixel| {
            let color = pixel.demultiply();
            [color.red(), color.green(), color.blue(), color.alpha()]
        })
        .collect();

    Ok(RgbaImage::from_raw(ICON_SIZE, ICON_SIZE, rgba).ok_or("invalid pixmap size")?)
}

fn fit(image: &RgbaImage) -> RgbaImage {
    let (width, height) = image.dimensions();
    let scale = ICON_SIZE as f32 / width.max(height) as f32;
    let scaled = |length: u32| ((length as f32 * scale).round() as u32).clamp(1, ICON_SIZE);
    let (width, height) = (scaled(width), scaled(height));

    let resized = imageops::resize(image, width, height, FilterType::Lanczos3);
    let mut canvas = RgbaImage::new(ICON_SIZE, ICON_SIZE);
    imageops::overlay(
        &mut canvas,
        &resized,
        ((ICON_SIZE - width) / 2) as i64,
        ((ICON_SIZE - height) / 2) as i64,
    );
    canvas
}

pub fn thumbnail(download: &Download) -> Result<Vec<u8>, Error> {
    let image = image::load_from_memory(&download.bytes)?.to_rgba8();
    let (width, height) = image.dimensions();
    let scale = (THUMBNAIL_WIDTH as f32 / width as f32).min(1.0);
    let scaled = |length: u32| ((length as f32 * scale).round() as u32).max(1);

    encode(&imageops::resize(
        &image,
        scaled(width),
        scaled(height),
        FilterType::Lanczos3,
    ))
}

fn encode(image: &RgbaImage) -> Result<Vec<u8>, Error> {
    let mut png = Vec::new();
    image.write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)?;
    Ok(png)
}

pub fn store(dir: &Path, png: &[u8]) -> std::io::Result<String> {
    let name: String = Sha256::digest(png)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .chain([".png".to_owned()])
        .collect();
    let path = dir.join(&name);

    if !path.exists() {
        std::fs::create_dir_all(dir)?;
        let tmp = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, png)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
        std::fs::rename(tmp, &path)?;
    }

    Ok(name)
}

pub fn remove_unreferenced(dir: &Path, referenced: &HashSet<Box<str>>) -> std::io::Result<()> {
    let entries = match dir.read_dir() {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };

        if name.starts_with('.') || !name.ends_with(".png") || referenced.contains(name) {
            continue;
        }

        info!("removing unreferenced icon {name}");
        std::fs::remove_file(entry.path())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn download(content_type: Option<&str>, bytes: &[u8]) -> Download {
        Download {
            url: Url::parse("https://example.com/icon").unwrap(),
            content_type: content_type.map(str::to_owned),
            bytes: bytes.to_vec(),
        }
    }

    fn png(width: u32, height: u32) -> Vec<u8> {
        encode(&RgbaImage::from_pixel(
            width,
            height,
            image::Rgba([255, 0, 0, 255]),
        ))
        .unwrap()
    }

    #[test]
    fn renders_svg_centred_at_icon_size() {
        let svg = br##"<?xml version="1.0"?>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="10">
                <rect width="20" height="10" fill="#00ff00"/>
                <image href="/etc/passwd" width="20" height="10"/>
            </svg>"##;

        let Decoded::Vector(image) = decode(&download(None, svg)).unwrap() else {
            panic!("expected svg");
        };

        assert_eq!(image.dimensions(), (ICON_SIZE, ICON_SIZE));
        assert_eq!(image.get_pixel(64, 64).0, [0, 255, 0, 255]);
        assert_eq!(image.get_pixel(64, 10).0[3], 0);
    }

    #[test]
    fn fits_raster_onto_square_canvas() {
        let Decoded::Raster(image) = decode(&download(Some("image/png"), &png(32, 16))).unwrap()
        else {
            panic!("expected raster");
        };

        let fitted = fit(&image);
        assert_eq!(fitted.dimensions(), (ICON_SIZE, ICON_SIZE));
        assert_eq!(fitted.get_pixel(64, 64).0, [255, 0, 0, 255]);
        assert_eq!(fitted.get_pixel(64, 10).0[3], 0);
    }

    #[test]
    fn thumbnails_keep_aspect_ratio_and_never_upscale() {
        let decode_png = |png: Vec<u8>| image::load_from_memory(&png).unwrap().to_rgba8();

        let large = thumbnail(&download(Some("image/png"), &png(1280, 720))).unwrap();
        assert_eq!(decode_png(large).dimensions(), (THUMBNAIL_WIDTH, 180));

        let small = thumbnail(&download(Some("image/png"), &png(160, 90))).unwrap();
        assert_eq!(decode_png(small).dimensions(), (160, 90));
    }

    #[test]
    fn rejects_non_images() {
        assert!(decode(&download(Some("text/html"), b"<html></html>")).is_err());
    }

    #[test]
    fn stores_by_content_hash_and_removes_unreferenced() {
        let dir = std::env::temp_dir().join(format!("sieve-icon-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let keep = store(&dir, &png(1, 1)).unwrap();
        let drop = store(&dir, &png(2, 2)).unwrap();
        assert_eq!(store(&dir, &png(1, 1)).unwrap(), keep);
        assert_eq!(keep.len(), 64 + ".png".len());
        assert_eq!(
            std::fs::metadata(dir.join(&keep))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );

        remove_unreferenced(&dir, &[keep.clone().into()].into_iter().collect()).unwrap();
        assert!(dir.join(&keep).exists());
        assert!(!dir.join(&drop).exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
