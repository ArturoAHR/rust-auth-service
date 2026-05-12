use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::{
    domain::{
        parse::{Email, HashedPassword},
        AuthApiError, User,
    },
    AppState,
};

#[derive(Deserialize)]
pub struct SignUpRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

#[instrument(name = "Signup", skip_all, err(Debug))]
pub async fn sign_up(
    State(state): State<AppState>,
    Json(request): Json<SignUpRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    let email = Email::parse(request.email).map_err(|_| AuthApiError::InvalidCredentials)?;
    let password = HashedPassword::parse(request.password)
        .await
        .map_err(|_| AuthApiError::InvalidCredentials)?;

    let mut user_store = state.user_store.write().await;

    if let Ok(_) = user_store.get_user(&email).await {
        return Err(AuthApiError::UserAlreadyExists);
    }

    let user = User::new(email, password, request.requires_2fa);

    user_store
        .add_user(user)
        .await
        .map_err(|_| AuthApiError::UnexpectedError)?;

    let response = Json(SignUpResponse {
        message: "User created successfully".to_owned(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct SignUpResponse {
    pub message: String,
}
