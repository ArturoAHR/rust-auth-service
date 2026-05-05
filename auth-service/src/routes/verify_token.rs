use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{domain::AuthApiError, utils::auth::validate_token, AppState};

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    token: String,
}

pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    let banned_token_store = state.banned_token_store.read().await;

    validate_token(&request.token, &*banned_token_store)
        .await
        .map_err(|_| AuthApiError::InvalidToken)?;

    Ok(StatusCode::OK.into_response())
}
