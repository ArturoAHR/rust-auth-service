use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    domain::{
        parse::{Email, Password},
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

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(CookieJar, impl IntoResponse), AuthApiError> {
    let email = Email::parse(request.email).map_err(|_| AuthApiError::InvalidCredentials)?;
    let password =
        Password::parse(request.password).map_err(|_| AuthApiError::InvalidCredentials)?;

    let user_store = &state.user_store.read().await;

    user_store
        .validate_user(&email, &password)
        .await
        .map_err(|_| AuthApiError::IncorrectCredentials)?;

    user_store
        .get_user(&email)
        .await
        .map_err(|_| AuthApiError::IncorrectCredentials)?;

    let auth_cookie = generate_auth_cookie(&email).map_err(|_| AuthApiError::UnexpectedError)?;

    let updated_jar = jar.add(auth_cookie);

    Ok((updated_jar, StatusCode::OK.into_response()))
}
