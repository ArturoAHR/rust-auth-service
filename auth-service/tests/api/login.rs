use auth_service::{
    domain::parse::Email, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};
use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        json!({
            "password": "password123",
        }),
        json!({
            "email": random_email,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let test_cases = [
        json!({
            "email": "",
            "password": "password123",
        }),
        json!({
            "email": "invalid-email",
            "password": "password123",
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to Error Response")
                .error,
            "Invalid credentials".to_owned()
        )
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
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
        "password": "wrong-password"
    });

    let response = app.post_login(&login_payload).await;

    assert_eq!(
        response.status().as_u16(),
        401,
        "Authentication should have failed"
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to Error Response")
            .error,
        "Incorrect credentials".to_owned()
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
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

    let response = app.post_login(&login_payload).await;

    assert_eq!(
        response.status().as_u16(),
        200,
        "Authentication should have succeeded"
    );

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;

    let user_email = get_random_email();
    let user_password = "password12345".to_owned();

    let sign_up_payload = json!({
        "email": user_email,
        "password": user_password,
        "requires2FA": true
    });

    let _ = app.post_sign_up(&sign_up_payload).await;

    let login_payload = json!({
        "email": user_email,
        "password": user_password
    });

    let response = app.post_login(&login_payload).await;

    assert_eq!(
        response.status().as_u16(),
        206,
        "Should have emitted 2FA attempt"
    );

    let two_factor_auth_response = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(two_factor_auth_response.message, "2FA required".to_owned());

    let login_attempt_id = two_factor_auth_response.login_attempt_id;

    let added_code_record = app
        .two_factor_auth_code_store
        .read()
        .await
        .get_code(&Email::parse(user_email).unwrap())
        .await
        .unwrap();

    assert_eq!(login_attempt_id, added_code_record.0.as_ref());

    app.clean_up().await;
}
