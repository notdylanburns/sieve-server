use axum::routing::{Router, delete, get, patch, post};

use crate::state::AppState;

mod videos;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(videos::get))
        .route("/", post(videos::post))
        .route("/{video_id}", patch(videos::patch))
        .route("/{video_id}", delete(videos::delete))
}
