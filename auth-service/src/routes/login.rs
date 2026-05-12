use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use color_eyre::eyre::{eyre, Context};
use serde::{Deserialize, Serialize};

use crate::{
    domain::{
        parse::{Email, LoginAttemptId, TwoFactorAuthCode},
        AuthApiError,
    },
    utils::auth::generate_auth_cookie,
    AppState,
};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    RegularAuth,
    TwoFactorAuth(TwoFactorAuthResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorAuthResponse {
    pub message: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthApiError> {
    let email = Email::parse(request.email).map_err(|_| AuthApiError::InvalidCredentials)?;
    let user_store = &state.user_store.read().await;

    user_store
        .validate_user(&email, &request.password)
        .await
        .map_err(|_| AuthApiError::IncorrectCredentials)?;

    let user = user_store
        .get_user(&email)
        .await
        .map_err(|_| AuthApiError::IncorrectCredentials)?;

    let response = if user.requires_2fa {
        handle_2fa(&state, jar, &email).await
    } else {
        handle_no_2fa(jar, &email).await
    }?;

    Ok(response)
}

async fn handle_no_2fa(
    jar: CookieJar,
    email: &Email,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthApiError> {
    let auth_cookie = generate_auth_cookie(&email)
        .wrap_err("Failed to generate auth cookie.")
        .map_err(AuthApiError::UnexpectedError)?;

    let updated_jar = jar.add(auth_cookie);

    Ok((
        updated_jar,
        (StatusCode::OK, Json::from(LoginResponse::RegularAuth)),
    ))
}

async fn handle_2fa(
    state: &AppState,
    jar: CookieJar,
    email: &Email,
) -> Result<(CookieJar, (StatusCode, Json<LoginResponse>)), AuthApiError> {
    let login_attempt_id = LoginAttemptId::default();
    let two_factor_auth_code = TwoFactorAuthCode::default();

    let mut two_factor_auth_code_store = state.two_factor_auth_code_store.write().await;

    two_factor_auth_code_store
        .add_code(
            email.clone(),
            login_attempt_id.clone(),
            two_factor_auth_code.clone(),
        )
        .await
        .map_err(AuthApiError::UnexpectedError)?;

    let email_client = state.email_client.read().await;

    email_client
        .send_email(
            &email,
            "Two Factor Authentication Code",
            two_factor_auth_code.as_ref().into(),
        )
        .await
        .wrap_err("Failed to send two factor auth code email")
        .map_err(AuthApiError::UnexpectedError)?;

    let response = LoginResponse::TwoFactorAuth(TwoFactorAuthResponse {
        message: "2FA required".to_owned(),
        login_attempt_id: login_attempt_id.as_ref().into(),
    });

    Ok((jar, (StatusCode::PARTIAL_CONTENT, Json::from(response))))
}
