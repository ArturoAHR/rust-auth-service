use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let payload = json!({});

    let response = app.post_verify_token(&payload).await;

    assert_eq!(
        response.status().as_u16(),
        422,
        "Should return correct status when body is malformed"
    );
}

#[tokio::test]
async fn should_return_200_if_token_is_valid() {
    let app = TestApp::new().await;

    let user_email = get_random_email();
    let user_password = "password12345".to_owned();

    let sign_up_payload = json!({
        "email": user_email.clone(),
        "password": user_password.clone(),
        "requires2FA": false
    });

    let _ = app.post_sign_up(&sign_up_payload).await;

    let login_payload = json!({
        "email": user_email.clone(),
        "password": user_password.clone()
    });

    let login_response = app.post_login(&login_payload).await;

    let token = login_response
        .cookies()
        .find_map(|cookie| {
            if cookie.name() == JWT_COOKIE_NAME {
                Some(cookie.value().to_owned())
            } else {
                None
            }
        })
        .expect(&format!(
            "No \"{}\" token found in cookie jar after login",
            JWT_COOKIE_NAME
        ));

    let payload = json!({
        "token": &token,
    });

    let response = app.post_verify_token(&payload).await;

    assert_eq!(
        response.status().as_u16(),
        200,
        "Should have validated the token {}",
        token
    );
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    let payload = json!({
        "token": "invalid-token",
    });

    let response = app.post_verify_token(&payload).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Token validation should have failed",
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to Error Response")
            .error,
        "Invalid token",
    )
}

#[tokio::test]
async fn should_return_401_if_token_is_banned() {
    let app = TestApp::new().await;

    let user_email = get_random_email();
    let user_password = "password12345".to_owned();

    let sign_up_payload = json!({
        "email": user_email.clone(),
        "password": user_password.clone(),
        "requires2FA": false
    });

    let _ = app.post_sign_up(&sign_up_payload).await;

    let login_payload = json!({
        "email": user_email.clone(),
        "password": user_password.clone()
    });

    let login_response = app.post_login(&login_payload).await;

    let token = login_response
        .cookies()
        .find_map(|cookie| {
            if cookie.name() == JWT_COOKIE_NAME {
                Some(cookie.value().to_owned())
            } else {
                None
            }
        })
        .expect(&format!(
            "No \"{}\" token found in cookie jar after login",
            JWT_COOKIE_NAME
        ));

    let _ = app.post_logout().await;

    let payload = json!({
        "token": &token,
    });

    let response = app.post_verify_token(&payload).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Token validation should have failed",
    );
}
