use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{domain::AuthApiError, utils::auth::validate_token};

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    token: String,
}

pub async fn verify_token(
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    validate_token(&request.token)
        .await
        .map_err(|_| AuthApiError::InvalidToken)?;

    Ok(StatusCode::OK.into_response())
}
