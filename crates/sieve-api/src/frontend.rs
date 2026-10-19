use std::path::Path;

use tower_http::services::{ServeDir, ServeFile};

pub fn service(dir: &Path) -> ServeDir<ServeFile> {
    ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")))
}
