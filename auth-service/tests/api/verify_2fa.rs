use auth_service::{
    domain::parse::Email, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use uuid::Uuid;
use wiremock::{
    matchers::{method, path},
    Mock, ResponseTemplate,
};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    let login_attempt_id = Uuid::new_v4();

    let test_cases = vec![
        json!({"email": random_email, "loginAttemptId":  login_attempt_id }),
        json!({"email": random_email, "2FACode": "123456"}),
        json!({"loginAttemptId": login_attempt_id, "2FACode": "123456"}),
    ];

    for test_case in test_cases {
        let response = app.post_verify_2fa(&test_case).await;

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

    let random_email = get_random_email();
    let login_attempt_id = Uuid::new_v4();

    let test_cases = vec![
        json!({"email": "",  "loginAttemptId":  login_attempt_id, "2FACode": "123456"}),
        json!({"email": "invalid-email",  "loginAttemptId":  login_attempt_id, "2FACode": "123456"}),
        json!({"email": random_email,  "loginAttemptId":  "invalid-uuid", "2FACode": "123456"}),
        json!({"email": random_email,  "loginAttemptId":  login_attempt_id, "2FACode": "123"}),
    ];

    for test_case in test_cases {
        let response = app.post_verify_2fa(&test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input {:?}",
            test_case
        );
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
        "requires2FA": true
    });

    let _ = app.post_sign_up(&sign_up_payload).await;

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_payload = json!({
        "email": user_email,
        "password": user_password
    });

    let login_response = app.post_login(&login_payload).await;

    let login_attempt_id = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize login response into TwoFactorAuthResponse")
        .login_attempt_id;

    let verify_2fa_payload =
        json!({"email": user_email, "loginAttemptId": login_attempt_id, "2FACode": "123456"});

    let response = app.post_verify_2fa(&verify_2fa_payload).await;

    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_an_old_code_is_used() {
    let mut app = TestApp::new().await;

    let user_email = get_random_email();
    let user_password = "password12345".to_owned();

    let sign_up_payload = json!({
        "email": user_email,
        "password": user_password,
        "requires2FA": true
    });

    let _ = app.post_sign_up(&sign_up_payload).await;

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&app.email_server)
        .await;

    let login_payload = json!({
        "email": user_email,
        "password": user_password
    });

    let login_response = app.post_login(&login_payload).await;

    let two_factor_code_store = app.two_factor_auth_code_store.read().await;

    let login_attempt_id = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize login response into TwoFactorAuthResponse")
        .login_attempt_id;

    let two_factor_code = two_factor_code_store
        .get_code(&Email::parse(SecretString::new(user_email.clone().into_boxed_str())).unwrap())
        .await
        .unwrap()
        .1;

    drop(two_factor_code_store);

    let _ = app.post_login(&login_payload).await;

    let verify_2fa_payload = json!({"email": user_email, "loginAttemptId": login_attempt_id, "2FACode": two_factor_code.as_ref().expose_secret()});

    let response = app.post_verify_2fa(&verify_2fa_payload).await;

    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
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

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_response = app.post_login(&login_payload).await;

    let two_factor_code_store = app.two_factor_auth_code_store.read().await;

    let login_attempt_id = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize login response into TwoFactorAuthResponse")
        .login_attempt_id;

    let two_factor_code = two_factor_code_store
        .get_code(&Email::parse(SecretString::new(user_email.clone().into_boxed_str())).unwrap())
        .await
        .unwrap()
        .1;

    drop(two_factor_code_store);

    let verify_2fa_payload = json!({"email": user_email, "loginAttemptId": login_attempt_id, "2FACode": two_factor_code.as_ref().expose_secret()});

    let response = app.post_verify_2fa(&verify_2fa_payload).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_is_used_twice() {
    let mut app = TestApp::new().await;

    let user_email = get_random_email();
    let user_password = "password12345".to_owned();

    let sign_up_payload = json!({
        "email": user_email,
        "password": user_password,
        "requires2FA": true
    });

    let _ = app.post_sign_up(&sign_up_payload).await;

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_payload = json!({
        "email": user_email,
        "password": user_password
    });

    let login_response = app.post_login(&login_payload).await;

    let two_factor_code_store = app.two_factor_auth_code_store.read().await;

    let login_attempt_id = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize login response into TwoFactorAuthResponse")
        .login_attempt_id;

    let two_factor_code = two_factor_code_store
        .get_code(&Email::parse(SecretString::new(user_email.clone().into_boxed_str())).unwrap())
        .await
        .unwrap()
        .1;

    drop(two_factor_code_store);

    let verify_2fa_payload = json!({"email": user_email, "loginAttemptId": login_attempt_id, "2FACode": two_factor_code.as_ref().expose_secret()});

    let _ = app.post_verify_2fa(&verify_2fa_payload).await;

    let response = app.post_verify_2fa(&verify_2fa_payload).await;

    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}
