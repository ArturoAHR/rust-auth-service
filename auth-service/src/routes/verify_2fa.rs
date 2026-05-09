use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use crate::{
    domain::{
        parse::{Email, LoginAttemptId, TwoFactorAuthCode},
        AuthApiError,
    },
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct VerifyTwoFactorAuthRequest {
    email: String,
    #[serde(rename = "loginAttemptId")]
    login_attempt_id: String,
    #[serde(rename = "2FACode")]
    two_factor_auth_code: String,
}

pub async fn verify_2fa(
    State(state): State<AppState>,
    Json(request): Json<VerifyTwoFactorAuthRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    let email = Email::parse(request.email).map_err(|_| AuthApiError::InvalidCredentials)?;
    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
        .map_err(|_| AuthApiError::InvalidCredentials)?;
    let two_factor_auth_code = TwoFactorAuthCode::parse(request.two_factor_auth_code)
        .map_err(|_| AuthApiError::InvalidCredentials)?;

    let two_factor_auth_code_store = state.two_factor_auth_code_store.write().await;

    let two_factor_auth_code_record = two_factor_auth_code_store
        .get_code(&email)
        .await
        .map_err(|_| AuthApiError::IncorrectCredentials)?;

    if two_factor_auth_code_record != (login_attempt_id, two_factor_auth_code) {
        return Err(AuthApiError::IncorrectCredentials);
    }

    Ok(StatusCode::OK.into_response())
}
