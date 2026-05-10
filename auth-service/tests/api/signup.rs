use auth_service::{routes::SignUpResponse, ErrorResponse};
use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        json!({
            "password": "password123",
            "requires2FA": true
        }),
        json!({
            "email": random_email,
            "requires2FA": true
        }),
        json!({
            "email": random_email,
            "password": "password123",
        }),
        json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": "true"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_sign_up(test_case).await;

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
async fn should_return_201_if_valid_input() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let request_body = json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_sign_up(&request_body).await;

    assert_eq!(
        response.status().as_u16(),
        201,
        "Didn't successfully signup user {:?}",
        request_body
    );

    let expected_response = SignUpResponse {
        message: "User created successfully".to_owned(),
    };

    assert_eq!(
        response
            .json::<SignUpResponse>()
            .await
            .expect("Could not deserialize response body."),
        expected_response
    );

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        json!({
            "email": "",
            "password": "password123",
            "requires2FA": false
        }),
        json!({
            "email": "invalid-email",
            "password": "password123",
            "requires2FA": false
        }),
        json!({
            "email": random_email,
            "password": "1234567",
            "requires2FA": false
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_sign_up(test_case).await;

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
async fn should_return_409_if_email_already_exists() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let request_body = json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let _ = app.post_sign_up(&request_body).await;

    let response = app.post_sign_up(&request_body).await;

    assert_eq!(
        response.status().as_u16(),
        409,
        "Should have returned conflict error code for payload: {:?}",
        request_body
    );

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to Error Response")
            .error,
        "User already exists".to_owned()
    );

    app.clean_up().await;
}
