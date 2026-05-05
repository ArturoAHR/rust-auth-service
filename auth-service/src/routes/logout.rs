use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{cookie::Cookie, CookieJar};

use crate::{
    domain::AuthApiError,
    utils::{auth::validate_token, constants::JWT_COOKIE_NAME},
    AppState,
};

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, impl IntoResponse), AuthApiError> {
    let cookie = jar
        .get(&JWT_COOKIE_NAME)
        .ok_or(AuthApiError::MissingToken)?;

    let token = cookie.value().to_owned();
    let banned_token_store = state.banned_token_store.read().await;

    validate_token(&token, &*banned_token_store)
        .await
        .map_err(|_| AuthApiError::InvalidToken)?;

    let jar = jar.remove(Cookie::from(JWT_COOKIE_NAME.to_owned()));

    drop(banned_token_store);
    let mut banned_token_store = state.banned_token_store.write().await;

    banned_token_store
        .ban_token(&token)
        .await
        .map_err(|_| AuthApiError::UnexpectedError)?;

    Ok((jar, StatusCode::OK.into_response()))
}
