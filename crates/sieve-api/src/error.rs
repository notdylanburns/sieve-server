use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use log::{error, warn};

pub(crate) async fn log_error_responses(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let response = next.run(request).await;
    let status = response.status();

    if !status.is_client_error() && !status.is_server_error() {
        return response;
    }

    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    let message = String::from_utf8_lossy(&bytes);

    if status.is_server_error() {
        error!("{method} {uri} -> {status}: {message}");
    } else {
        warn!("{method} {uri} -> {status}: {message}");
    }

    Response::from_parts(parts, Body::from(bytes))
}

#[derive(Debug)]
pub(crate) enum ApiError {
    BadRequest(&'static str),
    Unauthorized,
    Forbidden,
    NotFound,
    InternalServerError,
}

impl ApiError {
    fn code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn headers(&self) -> impl Iterator<Item = (&'static str, &'static str)> {
        [].into_iter()
    }

    fn body(&self) -> Body {
        match self {
            Self::BadRequest(message) => Body::from(*message),
            Self::Unauthorized => Body::from("Unauthorized"),
            Self::Forbidden => Body::from("Forbidden"),
            Self::NotFound => Body::from("Not Found"),
            Self::InternalServerError => Body::from("Internal Server Error"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        self.headers()
            .fold(Response::builder().status(self.code()), |r, (k, v)| {
                r.header(k, v)
            })
            .body(self.body())
            .expect("invalid arguments passed to response builder")
    }
}

pub(crate) trait IntoApiError<T> {
    fn as_internal_server_error(self) -> Result<T, ApiError>;
}

impl<T, E: std::fmt::Display> IntoApiError<T> for Result<T, E> {
    fn as_internal_server_error(self) -> Result<T, ApiError> {
        self.map_err(|_| ApiError::InternalServerError)
    }
}

impl<T> IntoApiError<T> for Option<T> {
    fn as_internal_server_error(self) -> Result<T, ApiError> {
        self.ok_or(ApiError::InternalServerError)
    }
}
