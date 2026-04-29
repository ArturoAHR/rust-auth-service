use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct SignUpRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

pub async fn sign_up(Json(request): Json<SignUpRequest>) -> impl IntoResponse {
    StatusCode::OK.into_response()
}
