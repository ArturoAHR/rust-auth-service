use auth_service::utils::constants::JWT_COOKIE_NAME;
use reqwest::Url;

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_is_missing() {
    let app = TestApp::new().await;

    let response = app.post_logout().await;

    assert_eq!(
        response.status().as_u16(),
        400,
        "Should return correct status when JWT is missing"
    );
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
}
