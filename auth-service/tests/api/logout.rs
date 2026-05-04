use auth_service::{utils::constants::JWT_COOKIE_NAME, ErrorResponse};
use reqwest::Url;
use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_400_if_jwt_cookie_is_missing() {
    let app = TestApp::new().await;

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
    )
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

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
    )
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
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

    let _ = app.post_login(&login_payload).await;

    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        200,
        "Logout should have succeeded"
    );
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
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
    )
}
