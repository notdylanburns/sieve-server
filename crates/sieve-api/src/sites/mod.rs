use axum::routing::{Router, delete, get, patch, post};

use crate::state::AppState;

mod domains;
mod lookup;
mod meta;
mod paths;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/lookup", get(lookup::get))
        .route("/domains", get(domains::get))
        .route("/domains", post(domains::post))
        .route("/domains/{domain_id}", patch(domains::patch))
        .route("/domains/{domain_id}", delete(domains::delete))
        .route("/domains/{domain_id}/paths", get(paths::get))
        .route("/domains/{domain_id}/paths", post(paths::post))
        .route("/domains/{domain_id}/paths/{path_id}", patch(paths::patch))
        .route(
            "/domains/{domain_id}/paths/{path_id}",
            delete(paths::delete),
        )
}
