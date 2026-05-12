use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use tracing::instrument;

use crate::{
    domain::{
        parse::{Email, LoginAttemptId, TwoFactorAuthCode},
        AuthApiError,
    },
    utils::auth::generate_auth_cookie,
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

#[instrument(name = "Verify two factor authentication code", skip_all)]
pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<VerifyTwoFactorAuthRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthApiError> {
    let email = Email::parse(request.email).map_err(|_| AuthApiError::InvalidCredentials)?;
    let login_attempt_id = LoginAttemptId::parse(request.login_attempt_id)
        .map_err(|_| AuthApiError::InvalidCredentials)?;
    let two_factor_auth_code = TwoFactorAuthCode::parse(request.two_factor_auth_code)
        .map_err(|_| AuthApiError::InvalidCredentials)?;

    let mut two_factor_auth_code_store = state.two_factor_auth_code_store.write().await;

    let two_factor_auth_code_record = two_factor_auth_code_store
        .get_code(&email)
        .await
        .map_err(|_| AuthApiError::IncorrectCredentials)?;

    if two_factor_auth_code_record != (login_attempt_id, two_factor_auth_code) {
        return Err(AuthApiError::IncorrectCredentials);
    }

    two_factor_auth_code_store
        .remove_code(&email)
        .await
        .map_err(AuthApiError::UnexpectedError)?;

    let auth_cookie = generate_auth_cookie(&email).map_err(AuthApiError::UnexpectedError)?;

    let updated_jar = jar.add(auth_cookie);

    Ok((updated_jar, StatusCode::OK.into_response()))
}
