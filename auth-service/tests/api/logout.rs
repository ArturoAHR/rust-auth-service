use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use reqwest::Url;
use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_400_if_jwt_cookie_is_missing() {
    let mut app = TestApp::new().await;

    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        400,
        "Should return correct status when JWT is missing"
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to Error Response")
            .error,
        "Missing token",
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Should return correct status when JWT is invalid"
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to Error Response")
            .error,
        "Invalid token",
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let mut app = TestApp::new().await;

    let user_email = get_random_email();
    let user_password = "password12345".to_owned();

    let sign_up_payload = json!({
        "email": user_email,
        "password": user_password,
        "requires2FA": false
    });

    let _ = app.post_sign_up(&sign_up_payload).await;

    let login_payload = json!({
        "email": user_email,
        "password": user_password
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

    let response = app.post_logout().await;

    let banned_token_store = app.banned_token_store.read().await;

    let is_token_banned = banned_token_store
        .contains_token(&token)
        .await
        .expect("Could not check if token is banned.");

    drop(banned_token_store);

    assert_eq!(
        response.status().as_u16(),
        200,
        "Logout should have succeeded"
    );

    assert!(is_token_banned);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let mut app = TestApp::new().await;

    let user_email = get_random_email();
    let user_password = "password12345".to_owned();

    let sign_up_payload = json!({
        "email": user_email,
        "password": user_password,
        "requires2FA": false
    });

    let _ = app.post_sign_up(&sign_up_payload).await;

    let login_payload = json!({
        "email": user_email,
        "password": user_password
    });

    let _ = app.post_login(&login_payload).await;

    let _ = app.post_logout().await;

    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        400,
        "Should have removed JWT from cookie jar"
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to Error Response")
            .error,
        "Missing token",
    );

    app.clean_up().await;
}
