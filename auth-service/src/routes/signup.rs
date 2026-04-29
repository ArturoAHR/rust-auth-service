use axum::{http::StatusCode, response::IntoResponse};

pub async fn sign_up() -> impl IntoResponse {
    StatusCode::OK.into_response()
}
