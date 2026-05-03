use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{
    domain::{AuthApiError, User},
    AppState,
};

#[derive(Deserialize)]
pub struct SignUpRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}

pub async fn sign_up(
    State(state): State<AppState>,
    Json(request): Json<SignUpRequest>,
) -> Result<impl IntoResponse, AuthApiError> {
    let email = request.email;
    let password = request.password;

    if email.len() == 0usize || !email.contains("@") {
        return Err(AuthApiError::InvalidCredentials);
    }

    if password.len() < 8 {
        return Err(AuthApiError::InvalidCredentials);
    }

    let mut user_store = state.user_store.write().await;

    if let Ok(_) = user_store.get_user(&email) {
        return Err(AuthApiError::UserAlreadyExists);
    }

    let user = User::new(email, password, request.requires_2fa);

    user_store
        .add_user(user)
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
