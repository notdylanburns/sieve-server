use std::path::Path;

use tower_http::services::ServeDir;

pub fn service(dir: &Path) -> ServeDir {
    ServeDir::new(dir)
}
