use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::{domain::User, AppState};

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
) -> impl IntoResponse {
    let user = User::new(request.email, request.password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    user_store.add_user(user).unwrap();

    let response = Json(SignUpResponse {
        message: "User created successfully".to_owned(),
    });

    (StatusCode::CREATED, response)
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct SignUpResponse {
    pub message: String,
}
